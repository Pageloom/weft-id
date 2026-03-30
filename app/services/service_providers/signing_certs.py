"""Per-SP signing certificate management.

View, rotate, and get metadata URL info for SP signing certificates.
"""

import logging

import database
from schemas.service_providers import (
    SPMetadataURLInfo,
    SPSigningCertificate,
    SPSigningCertificateRotationResult,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser
from utils.saml_idp import make_idp_entity_id

logger = logging.getLogger(__name__)


def get_sp_signing_certificate(
    requesting_user: RequestingUser,
    sp_id: str,
) -> SPSigningCertificate:
    """Get signing certificate info for an SP.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert is None:
        raise NotFoundError(
            message="Signing certificate not found for this service provider",
            code="sp_signing_certificate_not_found",
        )

    return SPSigningCertificate(
        id=str(cert["id"]),
        sp_id=str(cert["sp_id"]),
        certificate_pem=cert["certificate_pem"],
        expires_at=cert["expires_at"],
        created_at=cert["created_at"],
        has_previous_certificate=cert["previous_certificate_pem"] is not None,
        rotation_grace_period_ends_at=cert.get("rotation_grace_period_ends_at"),
    )


def rotate_sp_signing_certificate(
    requesting_user: RequestingUser,
    sp_id: str,
    grace_period_days: int = 7,
) -> SPSigningCertificateRotationResult:
    """Rotate the signing certificate for an SP.

    Authorization: Requires super_admin role.
    Logs: sp_signing_certificate_rotated event.
    """
    from datetime import UTC, datetime, timedelta

    from utils.saml import encrypt_private_key, generate_sp_certificate, get_certificate_expiry

    require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    # Get current certificate
    current = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if current is None:
        raise NotFoundError(
            message="No signing certificate exists to rotate",
            code="sp_signing_certificate_not_found",
        )

    # Guard: reject rotation if one is already in progress
    grace_end = current.get("rotation_grace_period_ends_at")
    if grace_end is not None and grace_end > datetime.now(UTC):
        raise ValidationError(
            message="Certificate rotation already in progress",
            code="sp_signing_certificate_rotation_in_progress",
        )

    # Generate new certificate
    from services.settings import get_certificate_lifetime

    validity_years = get_certificate_lifetime(tenant_id)
    new_cert_pem, new_key_pem = generate_sp_certificate(tenant_id, validity_years=validity_years)
    new_encrypted_key = encrypt_private_key(new_key_pem)
    new_expires_at = get_certificate_expiry(new_cert_pem)

    # Calculate grace period end
    grace_period_ends = datetime.now(UTC) + timedelta(days=grace_period_days)

    # Rotate
    result = database.sp_signing_certificates.rotate_signing_certificate(
        tenant_id=tenant_id,
        sp_id=sp_id,
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
            message="Failed to rotate SP signing certificate",
            code="sp_signing_certificate_rotation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="sp_signing_certificate",
        artifact_id=str(result["id"]),
        event_type="sp_signing_certificate_rotated",
        metadata={
            "sp_id": sp_id,
            "grace_period_days": grace_period_days,
            "grace_period_ends_at": str(grace_period_ends),
            "new_expires_at": str(new_expires_at),
        },
    )

    return SPSigningCertificateRotationResult(
        new_certificate_pem=new_cert_pem,
        new_expires_at=new_expires_at,
        grace_period_ends_at=grace_period_ends,
    )


def get_sp_metadata_url_info(
    requesting_user: RequestingUser,
    sp_id: str,
    base_url: str,
) -> SPMetadataURLInfo:
    """Get per-SP metadata URL info.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    return SPMetadataURLInfo(
        metadata_url=f"{base_url}/saml/idp/metadata/{sp_id}",
        entity_id=make_idp_entity_id(tenant_id, sp_id),
        sso_url=f"{base_url}/saml/idp/sso",
        sp_id=sp_id,
        sp_name=sp_row["name"],
    )
