"""Integration tests for the social sign-in columns (migration 0079).

Covers the widened provider_type CHECK, the connection settings columns
(show_on_login, GitHub allowed orgs, Apple signing key) and the link
last_used_at column against the real Postgres schema.
"""

from uuid import uuid4

import database
import psycopg.errors
import pytest


def _create_connection(tenant, user, provider_type="generic"):
    return database.oidc_upstream.create_connection(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=f"Social {uuid4().hex[:8]}",
        provider_type=provider_type,
        issuer="https://idp.example.com",
        created_by=str(user["id"]),
    )


class TestProviderTypes:
    @pytest.mark.parametrize(
        "provider_type",
        ["microsoft", "linkedin", "gitlab", "github", "discord", "facebook", "apple"],
    )
    def test_social_provider_types_accepted(self, test_tenant, test_user, provider_type):
        row = _create_connection(test_tenant, test_user, provider_type)
        assert row["provider_type"] == provider_type

    def test_unknown_provider_type_rejected(self, test_tenant, test_user):
        with pytest.raises(psycopg.errors.CheckViolation):
            _create_connection(test_tenant, test_user, "myspace")


class TestConnectionSettingsColumns:
    def test_defaults(self, test_tenant, test_user):
        row = _create_connection(test_tenant, test_user)
        assert row["show_on_login"] is False
        assert row["github_allowed_orgs"] is None
        assert row["apple_team_id"] is None
        assert row["apple_key_id"] is None
        assert row["apple_private_key_enc"] is None

    def test_update_sets_settings(self, test_tenant, test_user):
        conn = _create_connection(test_tenant, test_user, "github")
        row = database.oidc_upstream.update_connection(
            test_tenant["id"],
            str(conn["id"]),
            show_on_login=True,
            github_allowed_orgs=["acme", "acme-labs"],
            apple_team_id="TEAM123456",
            apple_key_id="KEY1234567",
            apple_private_key_enc="encrypted-key",
        )
        assert row["show_on_login"] is True
        assert row["github_allowed_orgs"] == ["acme", "acme-labs"]
        assert row["apple_team_id"] == "TEAM123456"
        assert row["apple_key_id"] == "KEY1234567"
        assert row["apple_private_key_enc"] == "encrypted-key"

    def test_update_clears_nullable_settings(self, test_tenant, test_user):
        conn = _create_connection(test_tenant, test_user, "github")
        database.oidc_upstream.update_connection(
            test_tenant["id"], str(conn["id"]), github_allowed_orgs=["acme"], apple_key_id="K"
        )
        row = database.oidc_upstream.update_connection(
            test_tenant["id"], str(conn["id"]), github_allowed_orgs=None, apple_key_id=None
        )
        assert row["github_allowed_orgs"] is None
        assert row["apple_key_id"] is None

    def test_show_on_login_cannot_be_nulled(self, test_tenant, test_user):
        conn = _create_connection(test_tenant, test_user)
        row = database.oidc_upstream.update_connection(
            test_tenant["id"], str(conn["id"]), show_on_login=None
        )
        assert row["show_on_login"] is False

    def test_allowed_orgs_count_capped(self, test_tenant, test_user):
        conn = _create_connection(test_tenant, test_user, "github")
        with pytest.raises(psycopg.errors.CheckViolation):
            database.oidc_upstream.update_connection(
                test_tenant["id"],
                str(conn["id"]),
                github_allowed_orgs=[f"org-{i}" for i in range(101)],
            )

    @pytest.mark.parametrize(
        ("field", "limit"),
        [("apple_team_id", 50), ("apple_key_id", 50), ("apple_private_key_enc", 8192)],
    )
    def test_apple_lengths_capped(self, test_tenant, test_user, field, limit):
        conn = _create_connection(test_tenant, test_user, "apple")
        with pytest.raises(psycopg.errors.CheckViolation):
            database.oidc_upstream.update_connection(
                test_tenant["id"], str(conn["id"]), **{field: "x" * (limit + 1)}
            )


class TestCreateWithAllowedOrgs:
    def test_create_stores_allowed_orgs(self, test_tenant, test_user):
        row = database.oidc_upstream.create_connection(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name=f"GitHub {uuid4().hex[:8]}",
            provider_type="github",
            issuer="https://github.com",
            created_by=str(test_user["id"]),
            github_allowed_orgs=["acme", "globex"],
        )
        assert row["github_allowed_orgs"] == ["acme", "globex"]
        fetched = database.oidc_upstream.get_connection(test_tenant["id"], str(row["id"]))
        assert fetched["github_allowed_orgs"] == ["acme", "globex"]


class TestLinkLastUsed:
    def test_last_used_at_null_on_create(self, test_tenant, test_user):
        conn = _create_connection(test_tenant, test_user)
        link = database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        assert "last_used_at" in link
        assert link["last_used_at"] is None
