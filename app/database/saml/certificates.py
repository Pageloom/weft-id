"""SAML SP certificate database operations."""

from typing import Any

from database._core import TenantArg, fetchone


def get_sp_certificate(tenant_id: TenantArg) -> dict | None:
    """
    Get the SP certificate for a tenant.

    Returns:
        Dict with id, tenant_id, certificate_pem, private_key_pem_enc,
        expires_at, created_by, created_at, plus rotation fields:
        previous_certificate_pem, previous_private_key_pem_enc,
        previous_expires_at, rotation_grace_period_ends_at.
        Returns None if not found.
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, certificate_pem, private_key_pem_enc,
               expires_at, created_by, created_at,
               previous_certificate_pem, previous_private_key_pem_enc,
               previous_expires_at, rotation_grace_period_ends_at
        from saml_sp_certificates
        """,
        {},
    )


def create_sp_certificate(
    tenant_id: TenantArg,
    tenant_id_value: str,
    certificate_pem: str,
    private_key_pem_enc: str,
    expires_at: Any,
    created_by: str,
) -> dict | None:
    """
    Create an SP certificate for a tenant.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        certificate_pem: PEM-encoded X.509 certificate
        private_key_pem_enc: Fernet-encrypted PEM-encoded private key
        expires_at: Certificate expiry timestamp
        created_by: User ID who created the certificate

    Returns:
        Dict with created certificate details
    """
    return fetchone(
        tenant_id,
        """
        insert into saml_sp_certificates (
            tenant_id, certificate_pem, private_key_pem_enc,
            expires_at, created_by
        )
        values (
            :tenant_id, :certificate_pem, :private_key_pem_enc,
            :expires_at, :created_by
        )
        returning id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "certificate_pem": certificate_pem,
            "private_key_pem_enc": private_key_pem_enc,
            "expires_at": expires_at,
            "created_by": created_by,
        },
    )


def update_sp_certificate(
    tenant_id: TenantArg,
    certificate_pem: str,
    private_key_pem_enc: str,
    expires_at: Any,
) -> dict | None:
    """
    Update the SP certificate for a tenant.

    Returns:
        Dict with updated certificate details
    """
    return fetchone(
        tenant_id,
        """
        update saml_sp_certificates
        set certificate_pem = :certificate_pem,
            private_key_pem_enc = :private_key_pem_enc,
            expires_at = :expires_at
        returning id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {
            "certificate_pem": certificate_pem,
            "private_key_pem_enc": private_key_pem_enc,
            "expires_at": expires_at,
        },
    )


def rotate_sp_certificate(
    tenant_id: TenantArg,
    new_certificate_pem: str,
    new_private_key_pem_enc: str,
    new_expires_at: Any,
    previous_certificate_pem: str,
    previous_private_key_pem_enc: str,
    previous_expires_at: Any,
    rotation_grace_period_ends_at: Any,
) -> dict | None:
    """
    Rotate the SP certificate with grace period support.

    Moves the current certificate to previous_* columns and sets the new certificate.
    Both certificates remain valid during the grace period.

    Args:
        tenant_id: Tenant ID for scoping
        new_certificate_pem: The new certificate (becomes current)
        new_private_key_pem_enc: Encrypted private key for new cert
        new_expires_at: Expiry of new certificate
        previous_certificate_pem: Current certificate (becomes previous)
        previous_private_key_pem_enc: Encrypted private key of current cert
        previous_expires_at: Expiry of current/previous certificate
        rotation_grace_period_ends_at: When grace period ends

    Returns:
        Dict with updated certificate details including all rotation fields
    """
    return fetchone(
        tenant_id,
        """
        update saml_sp_certificates
        set certificate_pem = :new_certificate_pem,
            private_key_pem_enc = :new_private_key_pem_enc,
            expires_at = :new_expires_at,
            previous_certificate_pem = :previous_certificate_pem,
            previous_private_key_pem_enc = :previous_private_key_pem_enc,
            previous_expires_at = :previous_expires_at,
            rotation_grace_period_ends_at = :rotation_grace_period_ends_at
        returning id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {
            "new_certificate_pem": new_certificate_pem,
            "new_private_key_pem_enc": new_private_key_pem_enc,
            "new_expires_at": new_expires_at,
            "previous_certificate_pem": previous_certificate_pem,
            "previous_private_key_pem_enc": previous_private_key_pem_enc,
            "previous_expires_at": previous_expires_at,
            "rotation_grace_period_ends_at": rotation_grace_period_ends_at,
        },
    )


def clear_previous_certificate(tenant_id: TenantArg) -> dict | None:
    """
    Clear the previous certificate after grace period has ended.

    Returns:
        Dict with updated certificate details
    """
    return fetchone(
        tenant_id,
        """
        update saml_sp_certificates
        set previous_certificate_pem = null,
            previous_private_key_pem_enc = null,
            previous_expires_at = null,
            rotation_grace_period_ends_at = null
        returning id, tenant_id, certificate_pem, private_key_pem_enc,
                  expires_at, created_by, created_at,
                  previous_certificate_pem, previous_private_key_pem_enc,
                  previous_expires_at, rotation_grace_period_ends_at
        """,
        {},
    )
