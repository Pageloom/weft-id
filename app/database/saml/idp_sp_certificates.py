"""Per-IdP SP certificate database operations."""

from typing import Any

from database._core import UNSCOPED, TenantArg, fetchall, fetchone

# ---------------------------------------------------------------------------
# Cross-tenant queries (used by background worker)
# ---------------------------------------------------------------------------


def get_idp_sp_certificates_needing_rotation_or_cleanup() -> list[dict]:
    """Get all per-IdP SP certificates that need rotation or cleanup.

    This is a cross-tenant query used by the worker for auto-rotation.
    Uses UNSCOPED to bypass RLS (system task).

    Returns two categories:
    - Needs rotation: expires within the tenant's configured window, no active rotation in progress
    - Needs cleanup: grace period has expired

    Returns:
        List of dicts with id, idp_id, tenant_id, expires_at,
        rotation_grace_period_ends_at, and action ('rotate' or 'cleanup').
    """
    return fetchall(
        UNSCOPED,
        """
        select sc.id, sc.idp_id, sc.tenant_id, sc.expires_at,
               sc.rotation_grace_period_ends_at,
               'rotate' as action
        from saml_idp_sp_certificates sc
        left join tenant_security_settings tss
            on tss.tenant_id = sc.tenant_id
        where sc.expires_at < now() + make_interval(
            days => coalesce(tss.certificate_rotation_window_days, 90)
        )
          and sc.rotation_grace_period_ends_at is null
        union all
        select sc.id, sc.idp_id, sc.tenant_id, sc.expires_at,
               sc.rotation_grace_period_ends_at,
               'cleanup' as action
        from saml_idp_sp_certificates sc
        where sc.rotation_grace_period_ends_at is not null
          and sc.rotation_grace_period_ends_at < now()
        """,
    )


def get_idp_sp_certificate(tenant_id: TenantArg, idp_id: str) -> dict | None:
    """Get the SP certificate for a specific identity provider.

    Returns:
        Dict with id, idp_id, tenant_id, certificate_pem, private_key_pem_enc,
        expires_at, created_by, created_at, plus rotation fields.
        Returns None if not found.
    """
    return fetchone(
        tenant_id,
        """
        select id, idp_id, tenant_id, certificate_pem, private_key_pem_enc,
               expires_at, created_by, created_at,
               previous_certificate_pem, previous_private_key_pem_enc,
               previous_expires_at, rotation_grace_period_ends_at
        from saml_idp_sp_certificates
        where idp_id = :idp_id
        """,
        {"idp_id": idp_id},
    )


def create_idp_sp_certificate(
    tenant_id: TenantArg,
    idp_id: str,
    tenant_id_value: str,
    certificate_pem: str,
    private_key_pem_enc: str,
    expires_at: Any,
    created_by: str,
) -> dict | None:
    """Create an SP certificate for an identity provider.

    Returns:
        Dict with created certificate details
    """
    return fetchone(
        tenant_id,
        """
        insert into saml_idp_sp_certificates (
            idp_id, tenant_id, certificate_pem, private_key_pem_enc,
            expires_at, created_by
        )
        values (
            :idp_id, :tenant_id, :certificate_pem, :private_key_pem_enc,
            :expires_at, :created_by
        )
        returning id, idp_id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at
        """,
        {
            "idp_id": idp_id,
            "tenant_id": tenant_id_value,
            "certificate_pem": certificate_pem,
            "private_key_pem_enc": private_key_pem_enc,
            "expires_at": expires_at,
            "created_by": created_by,
        },
    )


def rotate_idp_sp_certificate(
    tenant_id: TenantArg,
    idp_id: str,
    new_certificate_pem: str,
    new_private_key_pem_enc: str,
    new_expires_at: Any,
    previous_certificate_pem: str,
    previous_private_key_pem_enc: str,
    previous_expires_at: Any,
    rotation_grace_period_ends_at: Any,
) -> dict | None:
    """Rotate the SP certificate for an identity provider.

    Moves current cert to previous_* columns and sets the new certificate.
    Both remain valid during the grace period.

    Returns:
        Dict with updated certificate details including all rotation fields
    """
    return fetchone(
        tenant_id,
        """
        update saml_idp_sp_certificates
        set certificate_pem = :new_certificate_pem,
            private_key_pem_enc = :new_private_key_pem_enc,
            expires_at = :new_expires_at,
            previous_certificate_pem = :previous_certificate_pem,
            previous_private_key_pem_enc = :previous_private_key_pem_enc,
            previous_expires_at = :previous_expires_at,
            rotation_grace_period_ends_at = :rotation_grace_period_ends_at
        where idp_id = :idp_id
        returning id, idp_id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {
            "idp_id": idp_id,
            "new_certificate_pem": new_certificate_pem,
            "new_private_key_pem_enc": new_private_key_pem_enc,
            "new_expires_at": new_expires_at,
            "previous_certificate_pem": previous_certificate_pem,
            "previous_private_key_pem_enc": previous_private_key_pem_enc,
            "previous_expires_at": previous_expires_at,
            "rotation_grace_period_ends_at": rotation_grace_period_ends_at,
        },
    )


def clear_previous_idp_sp_certificate(tenant_id: TenantArg, idp_id: str) -> dict | None:
    """Clear the previous certificate after grace period has ended.

    Returns:
        Dict with updated certificate details
    """
    return fetchone(
        tenant_id,
        """
        update saml_idp_sp_certificates
        set previous_certificate_pem = null,
            previous_private_key_pem_enc = null,
            previous_expires_at = null,
            rotation_grace_period_ends_at = null
        where idp_id = :idp_id
          and rotation_grace_period_ends_at is not null
          and rotation_grace_period_ends_at < now()
        returning id, idp_id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {"idp_id": idp_id},
    )
