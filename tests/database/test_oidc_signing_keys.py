"""Integration tests for database.oidc.signing_keys.

Covers CRUD, rotation, previous-key cleanup, RLS tenant isolation, and the
UNIQUE-per-tenant constraint against the real Postgres schema.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database
import psycopg
import pytest


def _create(tenant, kid="kid-a", created_by=None):
    return database.oidc.create_signing_key(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        kid=kid,
        public_key_pem="-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
        private_key_pem_enc="enc-private-material",
        created_by=created_by,
    )


class TestCreateAndGet:
    def test_create_returns_row(self, test_tenant):
        row = _create(test_tenant)
        assert row is not None
        assert row["kid"] == "kid-a"
        assert row["algorithm"] == "RS256"
        assert row["is_active"] is True
        assert str(row["tenant_id"]) == str(test_tenant["id"])
        assert row["created_by"] is None
        assert row["previous_kid"] is None
        assert row["rotation_grace_period_ends_at"] is None

    def test_create_with_actor(self, test_tenant, test_user):
        row = _create(test_tenant, created_by=str(test_user["id"]))
        assert str(row["created_by"]) == str(test_user["id"])

    def test_get_returns_none_when_absent(self, test_tenant):
        assert database.oidc.get_signing_key(test_tenant["id"]) is None

    def test_get_returns_row(self, test_tenant):
        _create(test_tenant)
        row = database.oidc.get_signing_key(test_tenant["id"])
        assert row is not None
        assert row["kid"] == "kid-a"
        assert row["private_key_pem_enc"] == "enc-private-material"

    def test_one_row_per_tenant(self, test_tenant):
        _create(test_tenant, kid="kid-a")
        with pytest.raises(psycopg.errors.UniqueViolation):
            _create(test_tenant, kid="kid-b")


class TestRotation:
    def test_rotate_moves_current_to_previous(self, test_tenant):
        _create(test_tenant, kid="kid-old")
        grace = datetime.now(UTC) + timedelta(hours=24)
        result = database.oidc.rotate_signing_key(
            tenant_id=test_tenant["id"],
            new_kid="kid-new",
            new_public_key_pem="new-pub",
            new_private_key_pem_enc="new-enc",
            previous_kid="kid-old",
            previous_public_key_pem="-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
            previous_private_key_pem_enc="enc-private-material",
            previous_created_at=datetime.now(UTC),
            rotation_grace_period_ends_at=grace,
        )
        assert result["kid"] == "kid-new"
        assert result["public_key_pem"] == "new-pub"
        assert result["private_key_pem_enc"] == "new-enc"
        assert result["previous_kid"] == "kid-old"
        assert result["rotation_grace_period_ends_at"] is not None

    def test_clear_previous_only_when_grace_expired(self, test_tenant):
        _create(test_tenant, kid="kid-old")
        # Rotate with an already-expired grace period.
        past = datetime.now(UTC) - timedelta(hours=1)
        database.oidc.rotate_signing_key(
            tenant_id=test_tenant["id"],
            new_kid="kid-new",
            new_public_key_pem="new-pub",
            new_private_key_pem_enc="new-enc",
            previous_kid="kid-old",
            previous_public_key_pem="old-pub",
            previous_private_key_pem_enc="old-enc",
            previous_created_at=datetime.now(UTC),
            rotation_grace_period_ends_at=past,
        )
        cleared = database.oidc.clear_previous_signing_key(test_tenant["id"])
        assert cleared is not None
        assert cleared["previous_kid"] is None
        assert cleared["rotation_grace_period_ends_at"] is None

    def test_clear_previous_noop_when_grace_active(self, test_tenant):
        _create(test_tenant, kid="kid-old")
        future = datetime.now(UTC) + timedelta(hours=24)
        database.oidc.rotate_signing_key(
            tenant_id=test_tenant["id"],
            new_kid="kid-new",
            new_public_key_pem="new-pub",
            new_private_key_pem_enc="new-enc",
            previous_kid="kid-old",
            previous_public_key_pem="old-pub",
            previous_private_key_pem_enc="old-enc",
            previous_created_at=datetime.now(UTC),
            rotation_grace_period_ends_at=future,
        )
        assert database.oidc.clear_previous_signing_key(test_tenant["id"]) is None
        # Previous key still present.
        row = database.oidc.get_signing_key(test_tenant["id"])
        assert row["previous_kid"] == "kid-old"


class TestTenantIsolation:
    def test_key_not_visible_under_other_tenant(self, test_tenant):
        """A tenant's key row must never resolve when scoped to another tenant."""
        _create(test_tenant, kid="kid-a")

        other_subdomain = f"other-{uuid4().hex[:8]}"
        other = database.fetchone(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
            {"s": other_subdomain, "n": "Other Tenant"},
        )
        try:
            assert database.oidc.get_signing_key(other["id"]) is None
            # And the owning tenant still sees its own key.
            assert database.oidc.get_signing_key(test_tenant["id"])["kid"] == "kid-a"
        finally:
            database.execute(
                database.UNSCOPED,
                "DELETE FROM tenants WHERE id = :id",
                {"id": other["id"]},
            )

    def test_unscoped_read_fails_closed(self, test_tenant):
        """Strict RLS: with app.tenant_id unset (UNSCOPED), no key resolves.

        Unlike scim_inbound_tokens (which has a permissive escape hatch so the
        bearer-auth path can look a token up before the tenant is known), the
        oidc_signing_keys policy is strict. An UNSCOPED read -- where
        app.tenant_id is never SET -- must return nothing, so private key
        material can never leak through an unset request scope.
        """
        _create(test_tenant, kid="kid-a")
        # The owning, scoped tenant sees its key...
        assert database.oidc.get_signing_key(test_tenant["id"]) is not None
        # ...but an UNSCOPED read fails closed (returns None) rather than
        # surfacing the row.
        assert database.oidc.get_signing_key(database.UNSCOPED) is None
