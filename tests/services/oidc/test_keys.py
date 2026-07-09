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
from uuid import uuid4

import database
import jwt
import pytest
from jwt.algorithms import RSAAlgorithm
from services import oidc as oidc_service
from services.exceptions import ForbiddenError, ValidationError
from services.oidc import tokens as tokens_service
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

    def test_provision_reselects_the_winner_on_conflict_race(self, test_tenant, monkeypatch):
        # Two concurrent first-fetches: the winner inserts the key; the loser's
        # `on conflict do nothing` insert returns None. Simulate the loser by
        # forcing create_signing_key to return None, and assert _provision
        # re-selects the existing key rather than raising.
        from services.oidc import keys as keys_mod

        winner = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        monkeypatch.setattr(database.oidc, "create_signing_key", lambda **kwargs: None)

        row = keys_mod._provision(str(test_tenant["id"]), None)

        assert row["kid"] == winner.kid


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

    def test_inflight_id_token_still_verifies_after_rotation(self, test_tenant, test_user):
        """SEAM: an ID token minted just before a rotation must still verify
        against the post-rotation JWKS via the retained previous key.

        Guards the interaction between Iteration 1 (key rotation with overlap)
        and Iteration 2 (ID-token minting): rotation must not strand tokens that
        relying parties are still holding. This exercises the real crypto path
        (sign with the active key, rotate, re-fetch JWKS, verify) so a bug that
        mis-stored the retired public key would surface as a verification
        failure rather than being masked by a kid-presence assertion.
        """
        tid = str(test_tenant["id"])
        issuer = "https://rp.example.com"

        # Mint a token with the currently-active key (the in-flight token).
        token = tokens_service.issue_id_token(
            tenant_id=tid,
            issuer=issuer,
            client_uuid=str(uuid4()),
            client_id="rp-client",
            user_id=str(test_user["id"]),
            scopes={"openid"},
        )
        signed_kid = jwt.get_unverified_header(token)["kid"]

        # Rotate: the active signing key changes, previous key stays in JWKS.
        ru = _super_admin(test_tenant, test_user)
        result = oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        assert result.previous_kid == signed_kid
        assert result.kid != signed_kid

        # The RP re-fetches the JWKS after rotation and still resolves the kid.
        jwks = oidc_service.get_jwks(tid)
        entry = next(k for k in jwks.keys if k.kid == signed_kid)
        public_key = RSAAlgorithm.from_jwk(json.dumps(entry.model_dump()))
        decoded = jwt.decode(
            token, public_key, algorithms=["RS256"], audience="rp-client", issuer=issuer
        )
        assert decoded["sub"] == str(test_user["id"])

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


class TestSigningKeyStatus:
    def test_status_provisions_and_reports_active_key(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        ru["role"] = "admin"  # admin is sufficient for the read
        status = oidc_service.get_signing_key_status(ru)
        assert status.algorithm == "RS256"
        assert status.kid
        assert status.previous_kid is None
        assert status.rotation_grace_period_ends_at is None
        assert status.rotation_in_progress is False
        # The read provisioned the key lazily with the requesting actor.
        row = database.oidc.get_signing_key(test_tenant["id"])
        assert str(row["created_by"]) == str(test_user["id"])

    def test_status_reflects_rotation_in_progress(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        original = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        result = oidc_service.rotate_signing_key(ru, grace_period_hours=24)

        status = oidc_service.get_signing_key_status(ru)
        assert status.kid == result.kid
        assert status.previous_kid == original.kid
        assert status.previous_created_at is not None
        assert status.rotation_grace_period_ends_at is not None
        assert status.rotation_in_progress is True

    def test_status_shows_lapsed_grace_as_not_in_progress(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        database.execute(
            test_tenant["id"],
            "UPDATE oidc_signing_keys SET rotation_grace_period_ends_at = :past",
            {"past": datetime.now(UTC) - timedelta(hours=1)},
        )
        status = oidc_service.get_signing_key_status(ru)
        assert status.previous_kid is not None  # not yet swept
        assert status.rotation_in_progress is False

    def test_status_requires_admin(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        ru["role"] = "user"
        with pytest.raises(ForbiddenError):
            oidc_service.get_signing_key_status(ru)

    def test_status_tracks_activity(self, test_tenant, test_user, mocker):
        spy = mocker.patch("services.oidc.keys.track_activity")
        ru = _super_admin(test_tenant, test_user)
        oidc_service.get_signing_key_status(ru)
        spy.assert_called_once_with(str(test_tenant["id"]), str(test_user["id"]))

    def test_status_never_exposes_key_material(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        serialized = oidc_service.get_signing_key_status(ru).model_dump_json()
        assert "PRIVATE" not in serialized
        assert "BEGIN PUBLIC KEY" not in serialized


class TestForceCleanup:
    def _expire_grace(self, test_tenant):
        database.execute(
            test_tenant["id"],
            "UPDATE oidc_signing_keys SET rotation_grace_period_ends_at = :past",
            {"past": datetime.now(UTC) - timedelta(hours=1)},
        )

    def test_force_cleanup_requires_super_admin(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        ru["role"] = "admin"
        with pytest.raises(ForbiddenError):
            oidc_service.force_cleanup_previous_signing_key(ru)

    def test_force_cleanup_clears_expired_retired_key(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        self._expire_grace(test_tenant)

        assert oidc_service.force_cleanup_previous_signing_key(ru) is True
        row = database.oidc.get_signing_key(test_tenant["id"])
        assert row["previous_kid"] is None

    def test_force_cleanup_respects_grace_window(self, test_tenant, test_user):
        """A retired key still within grace is never force-cleared."""
        ru = _super_admin(test_tenant, test_user)
        original = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)

        assert oidc_service.force_cleanup_previous_signing_key(ru) is False
        row = database.oidc.get_signing_key(test_tenant["id"])
        assert row["previous_kid"] == original.kid

    def test_force_cleanup_returns_false_when_never_rotated(self, test_tenant, test_user):
        ru = _super_admin(test_tenant, test_user)
        oidc_service.get_active_signing_key(str(test_tenant["id"]))
        assert oidc_service.force_cleanup_previous_signing_key(ru) is False

    def test_force_cleanup_emits_event_with_actor(self, test_tenant, test_user, mocker):
        ru = _super_admin(test_tenant, test_user)
        original = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        self._expire_grace(test_tenant)

        spy = mocker.patch("services.oidc.keys.log_event")
        oidc_service.force_cleanup_previous_signing_key(ru)
        spy.assert_called_once()
        kwargs = spy.call_args.kwargs
        assert kwargs["event_type"] == "oidc_signing_key_cleanup_completed"
        assert kwargs["artifact_type"] == "oidc_signing_key"
        assert kwargs["actor_user_id"] == str(test_user["id"])
        assert kwargs["metadata"]["previous_kid"] == original.kid

    def test_sweep_cleanup_emits_event_with_system_actor(self, test_tenant, test_user, mocker):
        from services.event_log import SYSTEM_ACTOR_ID

        ru = _super_admin(test_tenant, test_user)
        oidc_service.rotate_signing_key(ru, grace_period_hours=24)
        self._expire_grace(test_tenant)

        spy = mocker.patch("services.oidc.keys.log_event")
        oidc_service.cleanup_previous_signing_key(str(test_tenant["id"]))
        spy.assert_called_once()
        assert spy.call_args.kwargs["actor_user_id"] == SYSTEM_ACTOR_ID

    def test_cleanup_noop_emits_no_event(self, test_tenant, mocker):
        oidc_service.get_active_signing_key(str(test_tenant["id"]))
        spy = mocker.patch("services.oidc.keys.log_event")
        assert oidc_service.cleanup_previous_signing_key(str(test_tenant["id"])) is False
        spy.assert_not_called()


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
