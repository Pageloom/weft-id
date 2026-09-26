"""Integration tests for database.oauth2.consent (remembered consent grants).

Runs against the real Postgres schema: upsert semantics (create, widen, no
shrink), the user- and client-side listings with their joins, the three delete
shapes, FK cascades from client and user deletion, and RLS tenant isolation.
"""

from uuid import uuid4

import database
import pytest


def _client(test_tenant, test_admin_user, name="Consent App"):
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=name,
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(test_admin_user["id"]),
    )


def _grant(test_tenant, client, user, scopes):
    return database.oauth2.upsert_consent_grant(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        client_id=str(client["id"]),
        user_id=str(user["id"]),
        scopes=scopes,
    )


class TestUpsert:
    def test_create_returns_sorted_deduplicated_scopes(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _client(test_tenant, test_admin_user)
        row = _grant(test_tenant, client, test_user, ["profile", "openid", "profile"])
        assert row["scopes"] == ["openid", "profile"]
        assert str(row["client_id"]) == str(client["id"])
        assert str(row["user_id"]) == str(test_user["id"])
        assert row["granted_at"] == row["updated_at"]

    def test_second_upsert_widens_and_keeps_one_row(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        first = _grant(test_tenant, client, test_user, ["openid"])
        second = _grant(test_tenant, client, test_user, ["email", "openid"])
        assert second["id"] == first["id"]
        assert second["scopes"] == ["email", "openid"]
        assert second["updated_at"] >= first["updated_at"]
        assert second["granted_at"] == first["granted_at"]
        rows = database.oauth2.list_consent_grants_for_user(test_tenant["id"], str(test_user["id"]))
        assert len(rows) == 1

    def test_upsert_never_shrinks(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        _grant(test_tenant, client, test_user, ["openid", "email"])
        row = _grant(test_tenant, client, test_user, ["openid"])
        assert row["scopes"] == ["email", "openid"]

    def test_empty_scope_set_is_a_bare_grant(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        row = _grant(test_tenant, client, test_user, [])
        assert row["scopes"] == []
        assert database.oauth2.get_consent_grant(
            test_tenant["id"], str(client["id"]), str(test_user["id"])
        )

    def test_one_row_per_client_and_user(self, test_tenant, test_admin_user, test_user):
        a = _client(test_tenant, test_admin_user, "A")
        b = _client(test_tenant, test_admin_user, "B")
        _grant(test_tenant, a, test_user, ["openid"])
        _grant(test_tenant, b, test_user, ["openid"])
        _grant(test_tenant, a, test_admin_user, ["openid"])
        tid = test_tenant["id"]
        assert len(database.oauth2.list_consent_grants_for_user(tid, str(test_user["id"]))) == 2
        assert len(database.oauth2.list_consent_grants_for_client(tid, str(a["id"]))) == 2

    def test_scope_count_is_bounded(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        with pytest.raises(Exception, match="chk_oauth2_consent_grants_scopes_count"):
            _grant(test_tenant, client, test_user, [f"s{i}" for i in range(51)])


class TestLookups:
    def test_get_missing_is_none(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        assert (
            database.oauth2.get_consent_grant(
                test_tenant["id"], str(client["id"]), str(test_user["id"])
            )
            is None
        )
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(uuid4())) is None

    def test_get_by_id(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        row = _grant(test_tenant, client, test_user, ["openid"])
        found = database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(row["id"]))
        assert found is not None
        assert found["scopes"] == ["openid"]

    def test_user_listing_joins_client_and_orders_by_name(
        self, test_tenant, test_admin_user, test_user
    ):
        zed = _client(test_tenant, test_admin_user, "zed app")
        alpha = _client(test_tenant, test_admin_user, "Alpha app")
        database.oauth2.deactivate_client(test_tenant["id"], zed["client_id"])
        _grant(test_tenant, zed, test_user, ["openid"])
        _grant(test_tenant, alpha, test_user, ["openid", "email"])
        rows = database.oauth2.list_consent_grants_for_user(test_tenant["id"], str(test_user["id"]))
        assert [r["client_name"] for r in rows] == ["Alpha app", "zed app"]
        assert rows[0]["client_public_id"] == alpha["client_id"]
        assert rows[0]["client_is_active"] is True
        assert rows[1]["client_is_active"] is False
        assert rows[0]["client_description"] is None

    def test_client_listing_joins_user_and_primary_email(
        self, test_tenant, test_admin_user, test_user
    ):
        client = _client(test_tenant, test_admin_user)
        _grant(test_tenant, client, test_user, ["openid"])
        rows = database.oauth2.list_consent_grants_for_client(test_tenant["id"], str(client["id"]))
        assert len(rows) == 1
        assert rows[0]["user_email"] == test_user["email"]
        assert rows[0]["user_first_name"] == test_user["first_name"]
        assert rows[0]["user_last_name"] == test_user["last_name"]

    def test_client_listing_tolerates_user_without_primary_email(
        self, test_tenant, test_admin_user
    ):
        client = _client(test_tenant, test_admin_user)
        user = database.fetchone(
            test_tenant["id"],
            """
            insert into users (tenant_id, password_hash, first_name, last_name, role)
            values (:tid, :ph, 'No', 'Email', 'member') returning id
            """,
            {"tid": test_tenant["id"], "ph": "x" * 60},
        )
        _grant(test_tenant, client, user, ["openid"])
        rows = database.oauth2.list_consent_grants_for_client(test_tenant["id"], str(client["id"]))
        assert rows[0]["user_email"] is None


class TestDeletes:
    def test_delete_one(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        row = _grant(test_tenant, client, test_user, ["openid"])
        assert database.oauth2.delete_consent_grant(test_tenant["id"], str(row["id"])) == 1
        assert database.oauth2.delete_consent_grant(test_tenant["id"], str(row["id"])) == 0

    def test_delete_for_user_leaves_other_users(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        _grant(test_tenant, client, test_user, ["openid"])
        _grant(test_tenant, client, test_admin_user, ["openid"])
        assert (
            database.oauth2.delete_consent_grants_for_user(test_tenant["id"], str(test_user["id"]))
            == 1
        )
        remaining = database.oauth2.list_consent_grants_for_client(
            test_tenant["id"], str(client["id"])
        )
        assert [str(r["user_id"]) for r in remaining] == [str(test_admin_user["id"])]

    def test_delete_for_client_leaves_other_clients(self, test_tenant, test_admin_user, test_user):
        a = _client(test_tenant, test_admin_user, "A")
        b = _client(test_tenant, test_admin_user, "B")
        _grant(test_tenant, a, test_user, ["openid"])
        _grant(test_tenant, b, test_user, ["openid"])
        tid = test_tenant["id"]
        assert database.oauth2.delete_consent_grants_for_client(tid, str(a["id"])) == 1
        remaining = database.oauth2.list_consent_grants_for_user(
            test_tenant["id"], str(test_user["id"])
        )
        assert [str(r["client_id"]) for r in remaining] == [str(b["id"])]

    def test_client_deletion_cascades(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        row = _grant(test_tenant, client, test_user, ["openid"])
        database.oauth2.delete_client(test_tenant["id"], client["client_id"])
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(row["id"])) is None

    def test_user_deletion_cascades(self, test_tenant, test_admin_user):
        client = _client(test_tenant, test_admin_user)
        user = database.fetchone(
            test_tenant["id"],
            """
            insert into users (tenant_id, password_hash, first_name, last_name, role)
            values (:tid, :ph, 'Gone', 'Soon', 'member') returning id
            """,
            {"tid": test_tenant["id"], "ph": "x" * 60},
        )
        row = _grant(test_tenant, client, user, ["openid"])
        database.execute(test_tenant["id"], "delete from users where id = :id", {"id": user["id"]})
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(row["id"])) is None


class TestTenantIsolation:
    def test_grant_not_visible_under_other_tenant(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        row = _grant(test_tenant, client, test_user, ["openid"])
        other = database.fetchone(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
            {"s": f"other-{uuid4().hex[:8]}", "n": "Other Tenant"},
        )
        try:
            assert database.oauth2.get_consent_grant_by_id(other["id"], str(row["id"])) is None
            assert (
                database.oauth2.get_consent_grant(
                    other["id"], str(client["id"]), str(test_user["id"])
                )
                is None
            )
            assert (
                database.oauth2.list_consent_grants_for_client(other["id"], str(client["id"])) == []
            )
            assert database.oauth2.delete_consent_grant(other["id"], str(row["id"])) == 0
        finally:
            database.execute(
                database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": other["id"]}
            )
        assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(row["id"]))

    def test_unscoped_read_fails_closed(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        row = _grant(test_tenant, client, test_user, ["openid"])
        # Join-free lookups: the joined listings would trip the older
        # oauth2_clients policy (no NULLIF) before this table's policy applies.
        assert database.oauth2.get_consent_grant_by_id(database.UNSCOPED, str(row["id"])) is None
        assert (
            database.oauth2.get_consent_grant(
                database.UNSCOPED, str(client["id"]), str(test_user["id"])
            )
            is None
        )

    def test_unscoped_write_fails_closed(self, test_tenant, test_admin_user, test_user):
        client = _client(test_tenant, test_admin_user)
        with pytest.raises(Exception, match="row-level security|violates"):
            database.oauth2.upsert_consent_grant(
                tenant_id=database.UNSCOPED,
                tenant_id_value=str(test_tenant["id"]),
                client_id=str(client["id"]),
                user_id=str(test_user["id"]),
                scopes=["openid"],
            )
