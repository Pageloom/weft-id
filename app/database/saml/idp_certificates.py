"""IdP certificate database operations for multi-cert support."""

from database._core import TenantArg, execute, fetchall, fetchone


def list_idp_certificates(tenant_id: TenantArg, idp_id: str) -> list[dict]:
    """List all certificates for an IdP, ordered by creation date descending.

    Returns:
        List of dicts with certificate details.
    """
    return fetchall(
        tenant_id,
        """
        select id, idp_id, tenant_id, certificate_pem, fingerprint,
               expires_at, created_at
        from idp_certificates
        where idp_id = :idp_id
        order by created_at desc
        """,
        {"idp_id": idp_id},
    )


def get_idp_certificate(tenant_id: TenantArg, cert_id: str) -> dict | None:
    """Get a specific IdP certificate by ID.

    Returns:
        Dict with certificate details, or None if not found.
    """
    return fetchone(
        tenant_id,
        """
        select id, idp_id, tenant_id, certificate_pem, fingerprint,
               expires_at, created_at
        from idp_certificates
        where id = :cert_id
        """,
        {"cert_id": cert_id},
    )


def get_idp_certificate_by_fingerprint(
    tenant_id: TenantArg, idp_id: str, fingerprint: str
) -> dict | None:
    """Get a certificate by its fingerprint for duplicate detection.

    Returns:
        Dict with certificate details, or None if not found.
    """
    return fetchone(
        tenant_id,
        """
        select id, idp_id, tenant_id, certificate_pem, fingerprint,
               expires_at, created_at
        from idp_certificates
        where idp_id = :idp_id and fingerprint = :fingerprint
        """,
        {"idp_id": idp_id, "fingerprint": fingerprint},
    )


def create_idp_certificate(
    tenant_id: TenantArg,
    idp_id: str,
    tenant_id_value: str,
    certificate_pem: str,
    fingerprint: str,
    expires_at: object,
) -> dict | None:
    """Create a new IdP certificate.

    Returns:
        Dict with created certificate details.
    """
    return fetchone(
        tenant_id,
        """
        insert into idp_certificates (
            idp_id, tenant_id, certificate_pem, fingerprint, expires_at
        )
        values (
            :idp_id, :tenant_id, :certificate_pem, :fingerprint, :expires_at
        )
        returning id, idp_id, tenant_id, certificate_pem, fingerprint,
                  expires_at, created_at
        """,
        {
            "idp_id": idp_id,
            "tenant_id": tenant_id_value,
            "certificate_pem": certificate_pem,
            "fingerprint": fingerprint,
            "expires_at": expires_at,
        },
    )


def delete_idp_certificate(tenant_id: TenantArg, cert_id: str) -> bool:
    """Delete an IdP certificate.

    Returns:
        True if deleted, False if not found.
    """
    result = execute(
        tenant_id,
        """
        delete from idp_certificates
        where id = :cert_id
        """,
        {"cert_id": cert_id},
    )
    return result > 0


def update_idp_certificate_fingerprint(
    tenant_id: TenantArg, cert_id: str, fingerprint: str, expires_at: object
) -> dict | None:
    """Backfill fingerprint and expiry for migrated certificates.

    Returns:
        Dict with updated certificate details, or None if not found.
    """
    return fetchone(
        tenant_id,
        """
        update idp_certificates
        set fingerprint = :fingerprint, expires_at = :expires_at
        where id = :cert_id
        returning id, idp_id, tenant_id, certificate_pem, fingerprint,
                  expires_at, created_at
        """,
        {"cert_id": cert_id, "fingerprint": fingerprint, "expires_at": expires_at},
    )
