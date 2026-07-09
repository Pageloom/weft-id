"""Per-tenant OIDC signing-key database operations.

One row per tenant (UNIQUE tenant_id), mirroring the current + previous
column shape of sp_signing_certificates. Every query is RLS-scoped via the
``tenant_id`` argument to the database helpers, so only the calling tenant's
single row is ever visible; the SELECT/UPDATE statements therefore need no
explicit tenant predicate. Private-key material is stored encrypted
(private_key_pem_enc) and is never decrypted in this layer.
"""

from typing import Any

from database._core import UNSCOPED, TenantArg, fetchall, fetchone

_COLUMNS = """
    id, tenant_id, kid, algorithm, is_active,
    public_key_pem, private_key_pem_enc, created_by, created_at,
    previous_kid, previous_public_key_pem, previous_private_key_pem_enc,
    previous_created_at, rotation_grace_period_ends_at
"""


def get_signing_key(tenant_id: TenantArg) -> dict | None:
    """Return the tenant's OIDC signing key row, or None if not provisioned."""
    return fetchone(
        tenant_id,
        f"select {_COLUMNS} from oidc_signing_keys",
    )


def create_signing_key(
    tenant_id: TenantArg,
    tenant_id_value: str,
    kid: str,
    public_key_pem: str,
    private_key_pem_enc: str,
    created_by: str | None,
    algorithm: str = "RS256",
) -> dict | None:
    """Insert the tenant's initial OIDC signing key.

    ``created_by`` is optional because the key may be lazily provisioned by
    an unauthenticated public JWKS fetch (no actor user).

    Uses ``on conflict (tenant_id) do nothing`` so two concurrent first-fetches
    can't both raise on the ``unique(tenant_id)`` constraint: the winner inserts
    and returns its row, the loser gets ``None`` (and the caller re-selects the
    winner's key).
    """
    return fetchone(
        tenant_id,
        f"""
        insert into oidc_signing_keys (
            tenant_id, kid, algorithm, public_key_pem, private_key_pem_enc, created_by
        )
        values (
            :tenant_id_value, :kid, :algorithm, :public_key_pem,
            :private_key_pem_enc, :created_by
        )
        on conflict (tenant_id) do nothing
        returning {_COLUMNS}
        """,
        {
            "tenant_id_value": tenant_id_value,
            "kid": kid,
            "algorithm": algorithm,
            "public_key_pem": public_key_pem,
            "private_key_pem_enc": private_key_pem_enc,
            "created_by": created_by,
        },
    )


def rotate_signing_key(
    tenant_id: TenantArg,
    new_kid: str,
    new_public_key_pem: str,
    new_private_key_pem_enc: str,
    previous_kid: str,
    previous_public_key_pem: str,
    previous_private_key_pem_enc: str,
    previous_created_at: Any,
    rotation_grace_period_ends_at: Any,
) -> dict | None:
    """Rotate the tenant's signing key, retaining the old one through a grace period.

    Moves the current key into the previous_* columns and installs the new
    key as current. Both public keys stay published in JWKS until the grace
    period ends and the previous key is cleared.
    """
    return fetchone(
        tenant_id,
        f"""
        update oidc_signing_keys
        set kid = :new_kid,
            public_key_pem = :new_public_key_pem,
            private_key_pem_enc = :new_private_key_pem_enc,
            created_at = now(),
            previous_kid = :previous_kid,
            previous_public_key_pem = :previous_public_key_pem,
            previous_private_key_pem_enc = :previous_private_key_pem_enc,
            previous_created_at = :previous_created_at,
            rotation_grace_period_ends_at = :rotation_grace_period_ends_at
        returning {_COLUMNS}
        """,
        {
            "new_kid": new_kid,
            "new_public_key_pem": new_public_key_pem,
            "new_private_key_pem_enc": new_private_key_pem_enc,
            "previous_kid": previous_kid,
            "previous_public_key_pem": previous_public_key_pem,
            "previous_private_key_pem_enc": previous_private_key_pem_enc,
            "previous_created_at": previous_created_at,
            "rotation_grace_period_ends_at": rotation_grace_period_ends_at,
        },
    )


def get_signing_keys_needing_cleanup() -> list[dict]:
    """Get all OIDC signing keys whose rotation grace period has expired.

    This is a cross-tenant query used by the worker's periodic cleanup sweep.

    Routes through the `list_oidc_signing_keys_needing_cleanup_unscoped()`
    SECURITY DEFINER function (migration 0054). The function is owned by
    `appowner` (the table owner, which is exempt from RLS) and exposes only
    non-sensitive columns -- never key material. The `oidc_signing_keys`
    table's RLS policy is strict and rejects unscoped reads, so this is the
    only sanctioned cross-tenant accessor (same pattern as the SCIM cleanup
    accessor from migration 0040).

    Returns:
        List of dicts with id, tenant_id, previous_kid, and
        rotation_grace_period_ends_at.
    """
    return fetchall(
        UNSCOPED,
        """
        select id, tenant_id, previous_kid, rotation_grace_period_ends_at
        from list_oidc_signing_keys_needing_cleanup_unscoped()
        """,
    )


def clear_previous_signing_key(tenant_id: TenantArg) -> dict | None:
    """Clear the previous key once its rotation grace period has ended.

    No-op (returns None) if there is no expired previous key.
    """
    return fetchone(
        tenant_id,
        f"""
        update oidc_signing_keys
        set previous_kid = null,
            previous_public_key_pem = null,
            previous_private_key_pem_enc = null,
            previous_created_at = null,
            rotation_grace_period_ends_at = null
        where rotation_grace_period_ends_at is not null
          and rotation_grace_period_ends_at < now()
        returning {_COLUMNS}
        """,
    )
