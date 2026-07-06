"""Service-layer tests for OIDC signing-key management (services.oidc.keys).

Covers lazy provisioning, encryption at rest, JWKS shape / public-only
exposure, verify-readiness (real RS256 round-trip against the published
JWKS), rotation-with-overlap, the in-progress guard, grace-period cleanup,
authorization, and multi-tenant isolation. Runs against the real schema so
RLS scoping is exercised.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import cast

import database
import jwt
import pytest
from jwt.algorithms import RSAAlgorithm
from services import oidc as oidc_service
from services.exceptions import ForbiddenError, ValidationError
from services.types import RequestingUser
from utils.saml import decrypt_private_key


def _super_admin(tenant, user) -> RequestingUser:
    return cast(
        RequestingUser,
        {
            "id": str(user["id"]),
            "tenant_id": str(tenant["id"]),
            "role": "super_admin",
            "email": user.get("email", "admin@example.com"),
        },
    )


class TestLazyProvisioning:
    def test_get_jwks_provisions_on_first_use(self, test_tenant):
        assert database.oidc.get_signing_key(test_tenant["id"]) is None
        jwks = oidc_service.get_jwks(str(test_tenant["id"]))
        assert len(jwks.keys) == 1
        assert database.oidc.get_signing_key(test_tenant["id"]) is not None

    def test_get_jwks_idempotent(self, test_tenant):
        first = oidc_service.get_jwks(str(test_tenant["id"]))
        second = oidc_service.get_jwks(str(test_tenant["id"]))
        assert first.keys[0].kid == second.keys[0].kid

    def test_get_active_signing_key_provisions(self, test_tenant):
        active = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        assert active.algorithm == "RS256"
        assert "BEGIN PRIVATE KEY" in active.private_key_pem
        assert "BEGIN PUBLIC KEY" in active.public_key_pem


class TestEncryptionAtRest:
    def test_private_key_stored_encrypted_not_plaintext(self, test_tenant):
        active = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        row = database.oidc.get_signing_key(test_tenant["id"])
        stored = row["private_key_pem_enc"]
        # The stored value is not the plaintext PEM...
        assert "BEGIN PRIVATE KEY" not in stored
        assert stored != active.private_key_pem
        # ...but decrypts back to the active private key.
        assert decrypt_private_key(stored) == active.private_key_pem


class TestJWKSShape:
    def test_jwks_public_only_and_spec_fields(self, test_tenant):
        jwks = oidc_service.get_jwks(str(test_tenant["id"]))
        jwk = jwks.keys[0]
        assert jwk.kty == "RSA"
        assert jwk.use == "sig"
        assert jwk.alg == "RS256"
        assert jwk.kid
        assert jwk.n and jwk.e
        # No private components leak into the serialized JWK.
        serialized = json.dumps(jwks.model_dump())
        for private_member in ('"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"', "PRIVATE"):
            assert private_member not in serialized

    def test_kid_matches_active_key(self, test_tenant):
        active = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        jwks = oidc_service.get_jwks(str(test_tenant["id"]))
        assert jwks.keys[0].kid == active.kid

    def test_jwks_is_verify_ready(self, test_tenant):
        """A token signed with the active key verifies against the JWKS entry."""
        active = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        token = jwt.encode(
            {"sub": "user-123"},
            active.private_key_pem,
            algorithm="RS256",
            headers={"kid": active.kid},
        )
        jwks = oidc_service.get_jwks(str(test_tenant["id"]))
        entry = next(k for k in jwks.keys if k.kid == active.kid)
        public_key = RSAAlgorithm.from_jwk(json.dumps(entry.model_dump()))
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        assert decoded["sub"] == "user-123"


class TestRotation:
    def test_rotate_serves_both_keys_during_grace(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        original = oidc_service.get_active_signing_key(str(test_tenant["id"]))

        result = oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        assert result.kid != original.kid
        assert result.previous_kid == original.kid
        assert result.grace_period_ends_at > datetime.now(UTC)

        jwks = oidc_service.get_jwks(str(test_tenant["id"]))
        kids = {k.kid for k in jwks.keys}
        # Both the new active and the retired-but-in-grace key are published.
        assert result.kid in kids
        assert original.kid in kids
        assert len(jwks.keys) == 2

    def test_rotate_changes_active_signing_key(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        original = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        new_active = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        assert new_active.kid != original.kid
        assert new_active.private_key_pem != original.private_key_pem

    def test_expired_previous_key_dropped_from_jwks(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        oidc_service.get_active_signing_key(str(test_tenant["id"]))
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)

        # Force the grace period into the past, then only the active key remains.
        database.execute(
            test_tenant["id"],
            "UPDATE oidc_signing_keys SET rotation_grace_period_ends_at = :past",
            {"past": datetime.now(UTC) - timedelta(hours=1)},
        )
        jwks = oidc_service.get_jwks(str(test_tenant["id"]))
        assert len(jwks.keys) == 1

    def test_rotation_in_progress_guard(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        with pytest.raises(ValidationError) as exc:
            oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        assert exc.value.code == "oidc_signing_key_rotation_in_progress"

    def test_rotation_rejects_out_of_bounds_grace(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        with pytest.raises(ValidationError) as exc:
            oidc_service.rotate_signing_key(ru, grace_period_hours=0)
        assert exc.value.code == "oidc_invalid_grace_period"

    def test_rotation_requires_super_admin(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        ru["role"] = "admin"
        with pytest.raises(ForbiddenError):
            oidc_service.rotate_signing_key(ru)

    def test_rotation_emits_event(self, test_tenant, test_user, mocker):
        spy = mocker.patch("services.oidc.keys.log_event")
        ru = _super_admin(test_tenant, test_user)
        oidc_service.rotate_signing_key(ru, grace_period_hours=12)
        spy.assert_called_once()
        kwargs = spy.call_args.kwargs
        assert kwargs["event_type"] == "oidc_signing_key_rotated"
        assert kwargs["artifact_type"] == "oidc_signing_key"
        assert kwargs["tenant_id"] == str(test_tenant["id"])


class TestCleanup:
    def test_cleanup_returns_true_when_cleared(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        database.execute(
            test_tenant["id"],
            "UPDATE oidc_signing_keys SET rotation_grace_period_ends_at = :past",
            {"past": datetime.now(UTC) - timedelta(hours=1)},
        )
        assert oidc_service.cleanup_previous_signing_key(str(test_tenant["id"])) is True

    def test_cleanup_returns_false_when_nothing_to_clear(self, test_tenant):
        oidc_service.get_active_signing_key(str(test_tenant["id"]))
        assert oidc_service.cleanup_previous_signing_key(str(test_tenant["id"])) is False

    def test_cleanup_is_idempotent(self, test_tenant, test_user):
        """A second cleanup after the previous key is gone is a safe no-op."""
        ru = _super_admin(test_tenant, test_user)
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        database.execute(
            test_tenant["id"],
            "UPDATE oidc_signing_keys SET rotation_grace_period_ends_at = :past",
            {"past": datetime.now(UTC) - timedelta(hours=1)},
        )
        assert oidc_service.cleanup_previous_signing_key(str(test_tenant["id"])) is True
        # Repeat call: nothing left to clear, and no error.
        assert oidc_service.cleanup_previous_signing_key(str(test_tenant["id"])) is False
        # The active key survives the double cleanup.
        assert len(oidc_service.get_jwks(str(test_tenant["id"])).keys) == 1

    def test_lazy_provision_via_jwks_has_null_created_by(self, test_tenant):
        """Unauthenticated JWKS provisioning stores no actor (created_by NULL)."""
        oidc_service.get_jwks(str(test_tenant["id"]))
        row = database.oidc.get_signing_key(test_tenant["id"])
        assert row is not None
        assert row["created_by"] is None


class TestTenantIsolation:
    def test_each_tenant_gets_distinct_keys(self, test_tenant, second_test_tenant):
        jwks_a = oidc_service.get_jwks(str(test_tenant["id"]))
        jwks_b = oidc_service.get_jwks(str(second_test_tenant["id"]))
        assert jwks_a.keys[0].kid != jwks_b.keys[0].kid
        # A tenant's active private key never appears under the other tenant.
        active_a = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        active_b = oidc_service.get_active_signing_key(str(second_test_tenant["id"]))
        assert active_a.private_key_pem != active_b.private_key_pem


@pytest.fixture
def second_test_tenant():
    """A second tenant for cross-tenant isolation checks."""
    from uuid import uuid4

    subdomain = f"second-{uuid4().hex[:8]}"
    tenant = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id, subdomain, name",
        {"s": subdomain, "n": "Second Tenant"},
    )
    yield tenant
    database.execute(
        database.UNSCOPED,
        "DELETE FROM tenants WHERE id = :id",
        {"id": tenant["id"]},
    )
