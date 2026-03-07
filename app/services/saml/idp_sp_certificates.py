"""Per-IdP SP certificate management.

Each identity provider gets its own SP signing certificate for SAML
AuthnRequest signing and metadata. This isolates certificate rotation
to individual IdPs rather than affecting the entire tenant.
"""

import logging
from datetime import UTC, datetime

import database
from schemas.saml import CertificateRotationResult, IdPSPCertificate
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
    make_sp_entity_id,
)

logger = logging.getLogger(__name__)


def get_or_create_idp_sp_certificate(
    tenant_id: str,
    idp_id: str,
    created_by: str,
) -> dict:
    """Get existing per-IdP SP certificate or generate a new one.

    Internal function, no auth required. Called during IdP creation
    and SSO flows.

    Returns:
        Dict with certificate details including private_key_pem_enc
    """
    cert = database.saml.get_idp_sp_certificate(tenant_id, idp_id)
    if cert:
        return cert

    # Generate new certificate
    from services.settings import get_certificate_lifetime

    validity_years = get_certificate_lifetime(tenant_id)
    cert_pem, key_pem = generate_sp_certificate(tenant_id, validity_years=validity_years)
    encrypted_key = encrypt_private_key(key_pem)
    expires_at = get_certificate_expiry(cert_pem)

    cert = database.saml.create_idp_sp_certificate(
        tenant_id=tenant_id,
        idp_id=idp_id,
        tenant_id_value=tenant_id,
        certificate_pem=cert_pem,
        private_key_pem_enc=encrypted_key,
        expires_at=expires_at,
        created_by=created_by,
    )

    if cert is None:
        raise ValidationError(
            message="Failed to create per-IdP SP certificate",
            code="idp_sp_certificate_creation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=created_by,
        artifact_type="saml_idp_sp_certificate",
        artifact_id=str(cert["id"]),
        event_type="saml_idp_sp_certificate_created",
        metadata={"idp_id": idp_id, "expires_at": str(expires_at)},
    )

    return cert


def get_idp_sp_certificate_for_display(
    requesting_user: RequestingUser,
    idp_id: str,
) -> IdPSPCertificate | None:
    """Get per-IdP SP certificate info for admin display.

    Authorization: Requires super_admin role.
    """
    require_super_admin(requesting_user, log_failure=True, service_name="saml")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    cert = database.saml.get_idp_sp_certificate(tenant_id, idp_id)
    if not cert:
        return None

    return IdPSPCertificate(
        id=str(cert["id"]),
        idp_id=str(cert["idp_id"]),
        certificate_pem=cert["certificate_pem"],
        expires_at=cert["expires_at"],
        created_at=cert["created_at"],
        has_previous_certificate=cert.get("previous_certificate_pem") is not None,
        rotation_grace_period_ends_at=cert.get("rotation_grace_period_ends_at"),
    )


def rotate_idp_sp_certificate(
    requesting_user: RequestingUser,
    idp_id: str,
    grace_period_days: int = 7,
) -> CertificateRotationResult:
    """Rotate per-IdP SP certificate with grace period.

    Authorization: Requires super_admin role.
    """
    from datetime import timedelta

    require_super_admin(requesting_user, log_failure=True, service_name="saml")
    tenant_id = requesting_user["tenant_id"]

    # Verify IdP exists
    idp = database.saml.get_identity_provider(tenant_id, idp_id)
    if not idp:
        raise NotFoundError(message="Identity provider not found", code="idp_not_found")

    # Get current certificate
    current = database.saml.get_idp_sp_certificate(tenant_id, idp_id)
    if not current:
        raise NotFoundError(
            message="No per-IdP SP certificate exists to rotate",
            code="idp_sp_certificate_not_found",
        )

    # Guard: reject rotation if one is already in progress
    grace_end = current.get("rotation_grace_period_ends_at")
    if grace_end is not None and grace_end > datetime.now(UTC):
        raise ValidationError(
            message="Certificate rotation already in progress",
            code="idp_sp_certificate_rotation_in_progress",
        )

    # Generate new certificate
    from services.settings import get_certificate_lifetime

    validity_years = get_certificate_lifetime(tenant_id)
    new_cert_pem, new_key_pem = generate_sp_certificate(tenant_id, validity_years=validity_years)
    new_encrypted_key = encrypt_private_key(new_key_pem)
    new_expires_at = get_certificate_expiry(new_cert_pem)

    grace_period_ends = datetime.now(UTC) + timedelta(days=grace_period_days)

    result = database.saml.rotate_idp_sp_certificate(
        tenant_id=tenant_id,
        idp_id=idp_id,
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
            message="Failed to rotate per-IdP SP certificate",
            code="idp_sp_certificate_rotation_failed",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="saml_idp_sp_certificate",
        artifact_id=str(result["id"]),
        event_type="saml_idp_sp_certificate_rotated",
        metadata={
            "idp_id": idp_id,
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


def get_idp_sp_metadata_xml(
    tenant_id: str,
    idp_id: str,
    base_url: str,
) -> str:
    """Generate per-IdP SP metadata XML.

    Public function, no auth required (served at /saml/metadata/{idp_id}).
    """
    cert = database.saml.get_idp_sp_certificate(tenant_id, idp_id)
    if cert is None:
        raise NotFoundError(
            message="Per-IdP SP certificate not found",
            code="idp_sp_certificate_not_found",
        )

    entity_id = make_sp_entity_id(tenant_id, idp_id)
    acs_url = f"{base_url}/saml/acs/{idp_id}"

    previous_cert = cert.get("previous_certificate_pem")

    # Fetch IdP's attribute mapping so metadata reflects actual attributes
    idp_row = database.saml.get_identity_provider(tenant_id, idp_id)
    idp_attribute_mapping = idp_row.get("attribute_mapping") if idp_row else None

    return generate_sp_metadata_xml(
        entity_id=entity_id,
        acs_url=acs_url,
        certificate_pem=cert["certificate_pem"],
        previous_certificate_pem=previous_cert,
        attribute_mapping=idp_attribute_mapping,
    )
