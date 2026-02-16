"""Per-SP signing certificate database operations."""

from typing import Any

from database._core import TenantArg, fetchone

# ---------------------------------------------------------------------------
# Cross-tenant queries (used by background worker)
# ---------------------------------------------------------------------------


def get_certificates_needing_rotation_or_cleanup() -> list[dict]:
    """Get all SP signing certificates that need rotation or cleanup.

    This is a cross-tenant query used by the worker for auto-rotation.
    Does not use RLS (called without tenant context).

    Returns two categories:
    - Needs rotation: expires within 90 days, no active rotation in progress
    - Needs cleanup: grace period has expired

    Returns:
        List of dicts with id, sp_id, tenant_id, expires_at,
        rotation_grace_period_ends_at, and action ('rotate' or 'cleanup').
    """
    from psycopg.rows import dict_row

    from ._core import get_pool

    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select id, sp_id, tenant_id, expires_at,
                       rotation_grace_period_ends_at,
                       'rotate' as action
                from sp_signing_certificates
                where expires_at < now() + interval '90 days'
                  and rotation_grace_period_ends_at is null
                union all
                select id, sp_id, tenant_id, expires_at,
                       rotation_grace_period_ends_at,
                       'cleanup' as action
                from sp_signing_certificates
                where rotation_grace_period_ends_at is not null
                  and rotation_grace_period_ends_at < now()
                """
            )
            return list(cur.fetchall())


def get_signing_certificate(tenant_id: TenantArg, sp_id: str) -> dict | None:
    """Get the signing certificate for a specific service provider.

    Returns:
        Dict with id, sp_id, tenant_id, certificate_pem, private_key_pem_enc,
        expires_at, created_by, created_at, plus rotation fields.
        Returns None if not found.
    """
    return fetchone(
        tenant_id,
        """
        select id, sp_id, tenant_id, certificate_pem, private_key_pem_enc,
               expires_at, created_by, created_at,
               previous_certificate_pem, previous_private_key_pem_enc,
               previous_expires_at, rotation_grace_period_ends_at
        from sp_signing_certificates
        where sp_id = :sp_id
        """,
        {"sp_id": sp_id},
    )


def create_signing_certificate(
    tenant_id: TenantArg,
    sp_id: str,
    tenant_id_value: str,
    certificate_pem: str,
    private_key_pem_enc: str,
    expires_at: Any,
    created_by: str,
) -> dict | None:
    """Create a signing certificate for a service provider.

    Returns:
        Dict with created certificate details
    """
    return fetchone(
        tenant_id,
        """
        insert into sp_signing_certificates (
            sp_id, tenant_id, certificate_pem, private_key_pem_enc,
            expires_at, created_by
        )
        values (
            :sp_id, :tenant_id, :certificate_pem, :private_key_pem_enc,
            :expires_at, :created_by
        )
        returning id, sp_id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at
        """,
        {
            "sp_id": sp_id,
            "tenant_id": tenant_id_value,
            "certificate_pem": certificate_pem,
            "private_key_pem_enc": private_key_pem_enc,
            "expires_at": expires_at,
            "created_by": created_by,
        },
    )


def rotate_signing_certificate(
    tenant_id: TenantArg,
    sp_id: str,
    new_certificate_pem: str,
    new_private_key_pem_enc: str,
    new_expires_at: Any,
    previous_certificate_pem: str,
    previous_private_key_pem_enc: str,
    previous_expires_at: Any,
    rotation_grace_period_ends_at: Any,
) -> dict | None:
    """Rotate the signing certificate for a service provider.

    Moves current cert to previous_* columns and sets the new certificate.
    Both remain valid during the grace period.

    Returns:
        Dict with updated certificate details including all rotation fields
    """
    return fetchone(
        tenant_id,
        """
        update sp_signing_certificates
        set certificate_pem = :new_certificate_pem,
            private_key_pem_enc = :new_private_key_pem_enc,
            expires_at = :new_expires_at,
            previous_certificate_pem = :previous_certificate_pem,
            previous_private_key_pem_enc = :previous_private_key_pem_enc,
            previous_expires_at = :previous_expires_at,
            rotation_grace_period_ends_at = :rotation_grace_period_ends_at
        where sp_id = :sp_id
        returning id, sp_id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {
            "sp_id": sp_id,
            "new_certificate_pem": new_certificate_pem,
            "new_private_key_pem_enc": new_private_key_pem_enc,
            "new_expires_at": new_expires_at,
            "previous_certificate_pem": previous_certificate_pem,
            "previous_private_key_pem_enc": previous_private_key_pem_enc,
            "previous_expires_at": previous_expires_at,
            "rotation_grace_period_ends_at": rotation_grace_period_ends_at,
        },
    )


def clear_previous_signing_certificate(tenant_id: TenantArg, sp_id: str) -> dict | None:
    """Clear the previous certificate after grace period has ended.

    Returns:
        Dict with updated certificate details
    """
    return fetchone(
        tenant_id,
        """
        update sp_signing_certificates
        set previous_certificate_pem = null,
            previous_private_key_pem_enc = null,
            previous_expires_at = null,
            rotation_grace_period_ends_at = null
        where sp_id = :sp_id
        returning id, sp_id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {"sp_id": sp_id},
    )
