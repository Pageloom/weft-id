"""SP certificate management for SAML SSO.

This module handles Service Provider (SP) certificate operations:
- Get or create SP certificate (used as IdP-side fallback for downstream SPs)

Per-IdP SP certificates are managed in idp_sp_certificates.py.
"""

import database
from schemas.saml import SPCertificate
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ValidationError
from services.types import RequestingUser
from utils.saml import (
    encrypt_private_key,
    generate_sp_certificate,
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
    from services.settings import get_certificate_lifetime

    validity_years = get_certificate_lifetime(tenant_id)
    cert_pem, key_pem = generate_sp_certificate(tenant_id, validity_years=validity_years)
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
