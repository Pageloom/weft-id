"""Per-tenant OIDC signing-key management.

WeftID is a downstream OIDC provider: it signs RS256 ID tokens with a
per-tenant RSA key and publishes the corresponding public key(s) as a JWKS
so relying parties can verify those tokens. This module owns the key
lifecycle:

- **Lazy provisioning**: the first time a tenant needs a key (e.g. a public
  JWKS fetch) one is generated and stored. There is no separate "enable"
  step.
- **Active key**: exactly one current key per tenant, used for signing.
- **Rotation with overlap**: :func:`rotate_signing_key` generates a new key,
  demotes the current one to the ``previous_*`` columns, and sets a grace
  period. Both public keys remain in the JWKS until the grace period ends,
  so RPs can still verify tokens that were signed by the old key before it
  is cleared by :func:`cleanup_previous_signing_key`.

Rotation procedure (documented per acceptance criteria):
    1. Generate a fresh RSA-2048 keypair and a new stable ``kid``.
    2. Move the current (kid, public, encrypted-private) into ``previous_*``
       and record ``rotation_grace_period_ends_at = now + grace``.
    3. Emit ``oidc_signing_key_rotated``.
    4. New tokens are signed with the new key; the previous public key stays
       published in JWKS for the grace window; after it lapses,
       :func:`cleanup_previous_signing_key` removes the stale public key.

Private-key material never leaves the service layer: it is stored encrypted
at rest (reusing the SAML Fernet helper) and only decrypted here for signing.
The JWKS assembler and the public router surface expose public components
(RSA ``n``/``e``) only.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

import database
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm
from schemas.oidc import JWK, JWKS, OIDCSigningKeyRotationResult
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ValidationError
from services.types import RequestingUser
from utils.saml import decrypt_private_key, encrypt_private_key

# RS256 signing. RSA-2048 is the OIDC baseline and matches the SAML precedent.
_ALGORITHM = "RS256"
_KEY_SIZE = 2048
_PUBLIC_EXPONENT = 65537

# Default rotation overlap. ID tokens are short-lived, so a day of overlap is
# ample for in-flight verification; bounded to guard against pathological input.
_DEFAULT_GRACE_PERIOD_HOURS = 24
_MIN_GRACE_PERIOD_HOURS = 1
_MAX_GRACE_PERIOD_HOURS = 24 * 30  # 30 days


@dataclass(frozen=True)
class ActiveSigningKey:
    """The active signing key, for internal service use only.

    Carries the decrypted private key PEM so a later iteration's token minter
    (also in the service layer) can sign. This object must never be handed to
    a router or serialized to a response.
    """

    kid: str
    algorithm: str
    private_key_pem: str
    public_key_pem: str


def _generate_kid() -> str:
    """Return a stable, URL-safe, collision-resistant key id."""
    return secrets.token_urlsafe(24)


def _generate_keypair() -> tuple[str, str]:
    """Generate an RSA keypair.

    Returns:
        (public_key_pem, private_key_pem) where the public key is a
        SubjectPublicKeyInfo PEM and the private key is an unencrypted PKCS8
        PEM (encrypted before storage by the caller).
    """
    private_key = rsa.generate_private_key(
        public_exponent=_PUBLIC_EXPONENT,
        key_size=_KEY_SIZE,
    )
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return public_pem, private_pem


def _public_jwk(public_key_pem: str, kid: str) -> JWK:
    """Build a public JWK (RSA n/e only) from a public-key PEM.

    Uses PyJWT's JWK serializer to derive the base64url ``n``/``e`` values,
    then keeps only public members and stamps kid/alg/use. No private
    components are ever produced from a public key.
    """
    public_key = cast(RSAPublicKey, serialization.load_pem_public_key(public_key_pem.encode()))
    raw = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    return JWK(
        kty=raw["kty"],
        use="sig",
        alg=_ALGORITHM,
        kid=kid,
        n=raw["n"],
        e=raw["e"],
    )


def _provision(tenant_id: str, actor_user_id: str | None) -> dict:
    """Generate and persist the tenant's initial signing key, returning its row."""
    public_pem, private_pem = _generate_keypair()
    row = database.oidc.create_signing_key(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        kid=_generate_kid(),
        public_key_pem=public_pem,
        private_key_pem_enc=encrypt_private_key(private_pem),
        created_by=actor_user_id,
        algorithm=_ALGORITHM,
    )
    if row is None:  # pragma: no cover - insert failure is not expected
        raise ValidationError(
            message="Failed to provision OIDC signing key",
            code="oidc_signing_key_provision_failed",
        )
    return row


def _get_or_provision(tenant_id: str, actor_user_id: str | None = None) -> dict:
    """Return the tenant's signing-key row, provisioning it lazily if absent."""
    row = database.oidc.get_signing_key(tenant_id)
    if row is None:
        row = _provision(tenant_id, actor_user_id)
    return row


def get_active_signing_key(tenant_id: str, actor_user_id: str | None = None) -> ActiveSigningKey:
    """Return the tenant's active signing key, provisioning one on first use.

    Intended for internal service-layer callers (e.g. the ID-token minter in a
    later iteration). Includes the decrypted private key, so the result must
    never leave the service layer.
    """
    row = _get_or_provision(tenant_id, actor_user_id)
    return ActiveSigningKey(
        kid=row["kid"],
        algorithm=row["algorithm"],
        private_key_pem=decrypt_private_key(row["private_key_pem_enc"]),
        public_key_pem=row["public_key_pem"],
    )


def get_jwks(tenant_id: str) -> JWKS:
    """Return the tenant's JWKS: the active key plus any within-grace retired key.

    Public endpoint data: only public RSA components (n/e) with a stable kid,
    ``alg`` RS256 and ``use`` sig. Provisions the key lazily on first fetch.
    Private material is never included.
    """
    row = _get_or_provision(tenant_id)

    keys = [_public_jwk(row["public_key_pem"], row["kid"])]

    grace_end = row.get("rotation_grace_period_ends_at")
    if (
        row.get("previous_public_key_pem")
        and row.get("previous_kid")
        and grace_end is not None
        and grace_end > datetime.now(UTC)
    ):
        keys.append(_public_jwk(row["previous_public_key_pem"], row["previous_kid"]))

    return JWKS(keys=keys)


def rotate_signing_key(
    requesting_user: RequestingUser,
    grace_period_hours: int = _DEFAULT_GRACE_PERIOD_HOURS,
) -> OIDCSigningKeyRotationResult:
    """Rotate the tenant's OIDC signing key with an overlap grace period.

    Authorization: Requires super_admin role.
    Logs: ``oidc_signing_key_rotated``.

    The current key is demoted to the previous slot and kept in the JWKS until
    ``grace_period_hours`` elapse, so relying parties can still verify tokens
    signed just before the rotation. See the module docstring for the full
    procedure.
    """
    require_super_admin(requesting_user)

    if not (_MIN_GRACE_PERIOD_HOURS <= grace_period_hours <= _MAX_GRACE_PERIOD_HOURS):
        raise ValidationError(
            message=(
                f"grace_period_hours must be between {_MIN_GRACE_PERIOD_HOURS} "
                f"and {_MAX_GRACE_PERIOD_HOURS}"
            ),
            code="oidc_invalid_grace_period",
        )

    tenant_id = requesting_user["tenant_id"]

    # Ensure a key exists to rotate (lazily provisions if the tenant never
    # fetched its JWKS before rotating).
    current = _get_or_provision(tenant_id, requesting_user["id"])

    # Guard: refuse to rotate while a prior rotation is still within its grace
    # period, which would drop the not-yet-expired previous key.
    grace_end = current.get("rotation_grace_period_ends_at")
    if grace_end is not None and grace_end > datetime.now(UTC):
        raise ValidationError(
            message="Signing-key rotation already in progress",
            code="oidc_signing_key_rotation_in_progress",
        )

    public_pem, private_pem = _generate_keypair()
    new_kid = _generate_kid()
    now = datetime.now(UTC)
    grace_period_ends = now + timedelta(hours=grace_period_hours)

    result = database.oidc.rotate_signing_key(
        tenant_id=tenant_id,
        new_kid=new_kid,
        new_public_key_pem=public_pem,
        new_private_key_pem_enc=encrypt_private_key(private_pem),
        previous_kid=current["kid"],
        previous_public_key_pem=current["public_key_pem"],
        previous_private_key_pem_enc=current["private_key_pem_enc"],
        previous_created_at=current["created_at"],
        rotation_grace_period_ends_at=grace_period_ends,
    )
    if result is None:  # pragma: no cover - update failure is not expected
        raise ValidationError(
            message="Failed to rotate OIDC signing key",
            code="oidc_signing_key_rotation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oidc_signing_key",
        artifact_id=str(result["id"]),
        event_type="oidc_signing_key_rotated",
        metadata={
            "kid": new_kid,
            "previous_kid": current["kid"],
            "grace_period_hours": grace_period_hours,
            "grace_period_ends_at": str(grace_period_ends),
        },
    )

    return OIDCSigningKeyRotationResult(
        kid=new_kid,
        previous_kid=current["kid"],
        rotated_at=now,
        grace_period_ends_at=grace_period_ends,
    )


def cleanup_previous_signing_key(tenant_id: str) -> bool:
    """Drop the previous key once its rotation grace period has ended.

    Returns True if a stale previous key was cleared, False otherwise. Safe to
    call repeatedly (idempotent). Intended for a future background sweep.
    """
    return database.oidc.clear_previous_signing_key(tenant_id) is not None
