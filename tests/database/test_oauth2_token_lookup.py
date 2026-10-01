"""Database tests for token lookup and deletion used by introspection and
revocation, and the per-client tenant-introspection flag."""

from datetime import UTC, datetime, timedelta

import database
import pytest


def _tokens(test_tenant, oauth_client, user):
    """A refresh token and an access token minted from it."""
    refresh, refresh_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=oauth_client["id"],
        user_id=user["id"],
        scope="openid email",
    )
    access = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=oauth_client["id"],
        user_id=user["id"],
        parent_token_id=refresh_id,
        scope="openid email",
    )
    return refresh, refresh_id, access


class TestFindToken:
    def test_finds_access_token_with_client_public_id(
        self, test_tenant, normal_oauth2_client, test_user
    ):
        _, _, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        found = database.oauth2.find_token(test_tenant["id"], access)

        assert found is not None
        assert found["token_type"] == "access"
        assert str(found["client_id"]) == str(normal_oauth2_client["id"])
        assert found["client_public_id"] == normal_oauth2_client["client_id"]
        assert str(found["user_id"]) == str(test_user["id"])
        assert found["scope"] == "openid email"
        assert found["created_at"] is not None
        assert found["expires_at"] > datetime.now(UTC)
        assert "token_hash" not in found

    def test_finds_refresh_token(self, test_tenant, normal_oauth2_client, test_user):
        refresh, refresh_id, _ = _tokens(test_tenant, normal_oauth2_client, test_user)

        found = database.oauth2.find_token(test_tenant["id"], refresh)

        assert found is not None
        assert found["token_type"] == "refresh"
        assert str(found["id"]) == str(refresh_id)

    def test_unknown_token(self, test_tenant, normal_oauth2_client, test_user):
        _tokens(test_tenant, normal_oauth2_client, test_user)
        assert database.oauth2.find_token(test_tenant["id"], "not-a-token") is None

    def test_expired_token(self, test_tenant, normal_oauth2_client, test_user):
        _, _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        database.execute(
            test_tenant["id"],
            "update oauth2_tokens set expires_at = :past where token_type = 'access'",
            {"past": datetime.now(UTC) - timedelta(seconds=1)},
        )

        assert database.oauth2.find_token(test_tenant["id"], access) is None

    def test_other_tenant_cannot_find(self, test_tenant, normal_oauth2_client, test_user):
        _, _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        other = database.fetchone(
            database.UNSCOPED,
            "insert into tenants (subdomain, name) values (:s, :n) returning id",
            {"s": f"tok-other-{datetime.now(UTC).timestamp():.0f}", "n": "Other"},
        )
        try:
            assert database.oauth2.find_token(str(other["id"]), access) is None
        finally:
            database.execute(
                database.UNSCOPED, "delete from tenants where id = :id", {"id": other["id"]}
            )


class TestDeleteToken:
    def test_deleting_refresh_token_cascades_to_access_tokens(
        self, test_tenant, normal_oauth2_client, test_user
    ):
        refresh, refresh_id, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        assert database.oauth2.delete_token(test_tenant["id"], str(refresh_id)) == 1

        assert database.oauth2.find_token(test_tenant["id"], refresh) is None
        assert database.oauth2.find_token(test_tenant["id"], access) is None

    def test_deleting_access_token_keeps_refresh_token(
        self, test_tenant, normal_oauth2_client, test_user
    ):
        refresh, _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        access_row = database.oauth2.find_token(test_tenant["id"], access)

        assert database.oauth2.delete_token(test_tenant["id"], str(access_row["id"])) == 1

        assert database.oauth2.find_token(test_tenant["id"], access) is None
        assert database.oauth2.find_token(test_tenant["id"], refresh) is not None

    def test_deleting_missing_token(self, test_tenant, normal_oauth2_client, test_user):
        _, refresh_id, _ = _tokens(test_tenant, normal_oauth2_client, test_user)
        database.oauth2.delete_token(test_tenant["id"], str(refresh_id))

        assert database.oauth2.delete_token(test_tenant["id"], str(refresh_id)) == 0


class TestTenantIntrospectionFlag:
    def test_defaults_off(self, test_tenant, normal_oauth2_client, b2b_oauth2_client):
        for created in (normal_oauth2_client, b2b_oauth2_client):
            row = database.oauth2.get_client_by_client_id(test_tenant["id"], created["client_id"])
            assert row["can_introspect_tenant_tokens"] is False

    @pytest.mark.parametrize("enabled", [True, False])
    def test_set(self, test_tenant, b2b_oauth2_client, enabled):
        updated = database.oauth2.set_client_tenant_introspection(
            test_tenant["id"], b2b_oauth2_client["client_id"], enabled
        )

        assert updated["can_introspect_tenant_tokens"] is enabled
        row = database.oauth2.get_client_by_id(test_tenant["id"], str(b2b_oauth2_client["id"]))
        assert row["can_introspect_tenant_tokens"] is enabled

    def test_set_unknown_client(self, test_tenant):
        assert (
            database.oauth2.set_client_tenant_introspection(test_tenant["id"], "nope", True) is None
        )

    def test_listed_with_oidc_flags(self, test_tenant, normal_oauth2_client):
        """The list query carries the same flags as the single-client lookups."""
        database.oauth2.set_client_tenant_introspection(
            test_tenant["id"], normal_oauth2_client["client_id"], True
        )
        database.oauth2.update_client_oidc_settings(
            test_tenant["id"], normal_oauth2_client["client_id"], oidc_enabled=True
        )

        for client_type in (None, "normal"):
            rows = database.oauth2.get_all_clients(test_tenant["id"], client_type=client_type)
            row = next(r for r in rows if r["client_id"] == normal_oauth2_client["client_id"])
            assert row["can_introspect_tenant_tokens"] is True
            assert row["oidc_enabled"] is True
            assert row["available_to_all"] is False
