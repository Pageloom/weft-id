"""SP certificate management for SAML SSO.

This module handles Service Provider (SP) certificate operations:
- Get or create SP certificate
- Get SP metadata
- Rotate SP certificate with grace period
- Generate SP metadata XML
"""

import database
from schemas.saml import CertificateRotationResult, SPCertificate, SPMetadata
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser
from utils.saml import (
    encrypt_private_key,
    generate_sp_certificate,
    generate_sp_metadata_xml,
    get_certificate_expiry,
)


def get_or_create_sp_certificate(
    requesting_user: RequestingUser,
) -> SPCertificate:
    """
    Get existing SP certificate or generate a new one.

    Authorization: Requires super_admin role.

    If no certificate exists for the tenant, generates a self-signed
    certificate valid for 10 years.

    Returns:
        SPCertificate with certificate_pem (no private key exposed)
    """
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Try to get existing certificate
    cert = database.saml.get_sp_certificate(tenant_id)

    if cert:
        return SPCertificate(
            id=str(cert["id"]),
            certificate_pem=cert["certificate_pem"],
            expires_at=cert["expires_at"],
            created_at=cert["created_at"],
        )

    # Generate new certificate
    cert_pem, key_pem = generate_sp_certificate(tenant_id)
    encrypted_key = encrypt_private_key(key_pem)
    expires_at = get_certificate_expiry(cert_pem)

    cert = database.saml.create_sp_certificate(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        certificate_pem=cert_pem,
        private_key_pem_enc=encrypted_key,
        expires_at=expires_at,
        created_by=requesting_user["id"],
    )

    if cert is None:
        raise ValidationError(
            message="Failed to create SP certificate",
            code="sp_certificate_creation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_sp_certificate",
        artifact_id=str(cert["id"]),
        event_type="saml_sp_certificate_created",
        metadata={"expires_at": str(expires_at)},
    )

    return SPCertificate(
        id=str(cert["id"]),
        certificate_pem=cert["certificate_pem"],
        expires_at=cert["expires_at"],
        created_at=cert["created_at"],
    )


def get_sp_metadata(
    requesting_user: RequestingUser,
    base_url: str,
) -> SPMetadata:
    """
    Get SP metadata info for display in admin UI.

    Authorization: Requires super_admin role.

    Args:
        requesting_user: The authenticated user
        base_url: Base URL for generating metadata URL

    Returns:
        SPMetadata with entity_id, acs_url, metadata_url, certificate info
    """
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    # Get or create certificate
    cert = get_or_create_sp_certificate(requesting_user)

    # Generate metadata URL
    metadata_url = f"{base_url}/saml/metadata"
    acs_url = f"{base_url}/saml/acs"  # Generic ACS URL

    return SPMetadata(
        entity_id=metadata_url,
        acs_url=acs_url,
        metadata_url=metadata_url,
        certificate_pem=cert.certificate_pem,
        certificate_expires_at=cert.expires_at,
    )


def rotate_sp_certificate(
    requesting_user: RequestingUser,
    grace_period_days: int = 7,
) -> CertificateRotationResult:
    """
    Rotate SP certificate with grace period.

    Authorization: Requires super_admin role.

    The old certificate remains valid during the grace period, allowing
    IdP administrators time to update their SP metadata configuration.
    Both certificates are included in the SP metadata during the grace period.

    Args:
        requesting_user: The authenticated user
        grace_period_days: Number of days the old certificate remains valid (default 7)

    Returns:
        CertificateRotationResult with new cert info and grace period details
    """
    from datetime import UTC, datetime, timedelta

    require_super_admin(requesting_user, log_failure=True, service_name="saml")
    tenant_id = requesting_user["tenant_id"]

    # Get current certificate
    current = database.saml.get_sp_certificate(tenant_id)
    if not current:
        raise NotFoundError(
            message="No SP certificate exists to rotate",
            code="sp_certificate_not_found",
        )

    # Generate new certificate
    new_cert_pem, new_key_pem = generate_sp_certificate(tenant_id)
    new_encrypted_key = encrypt_private_key(new_key_pem)
    new_expires_at = get_certificate_expiry(new_cert_pem)

    # Calculate grace period end
    grace_period_ends = datetime.now(UTC) + timedelta(days=grace_period_days)

    # Rotate: current becomes previous, new becomes current
    result = database.saml.rotate_sp_certificate(
        tenant_id=tenant_id,
        new_certificate_pem=new_cert_pem,
        new_private_key_pem_enc=new_encrypted_key,
        new_expires_at=new_expires_at,
        previous_certificate_pem=current["certificate_pem"],
        previous_private_key_pem_enc=current["private_key_pem_enc"],
        previous_expires_at=current["expires_at"],
        rotation_grace_period_ends_at=grace_period_ends,
    )

    if result is None:
        raise ValidationError(
            message="Failed to rotate SP certificate",
            code="sp_certificate_rotation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_sp_certificate",
        artifact_id=str(result["id"]),
        event_type="saml_sp_certificate_rotated",
        metadata={
            "grace_period_days": grace_period_days,
            "grace_period_ends_at": str(grace_period_ends),
            "new_expires_at": str(new_expires_at),
        },
    )

    return CertificateRotationResult(
        new_certificate_pem=new_cert_pem,
        new_expires_at=new_expires_at,
        grace_period_ends_at=grace_period_ends,
    )


def get_tenant_sp_metadata_xml(tenant_id: str, base_url: str) -> str:
    """
    Generate SP metadata XML for IdPs to consume.

    No authorization required (public endpoint).

    Args:
        tenant_id: Tenant ID
        base_url: Base URL for the tenant

    Returns:
        XML metadata string
    """
    cert = database.saml.get_sp_certificate(tenant_id)

    if cert is None:
        raise NotFoundError(
            message="SP certificate not configured",
            code="sp_certificate_not_found",
        )

    entity_id = f"{base_url}/saml/metadata"
    acs_url = f"{base_url}/saml/acs"

    return generate_sp_metadata_xml(
        entity_id=entity_id,
        acs_url=acs_url,
        certificate_pem=cert["certificate_pem"],
    )
