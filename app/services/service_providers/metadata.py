"""IdP metadata generation for downstream SPs.

Generates SAML IdP metadata XML for tenant-level and per-SP endpoints.
"""

import logging

import database
from services.exceptions import NotFoundError
from utils.saml_idp import generate_idp_metadata_xml

logger = logging.getLogger(__name__)


def _resolve_idp_certificate(tenant_id: str, sp_id: str | None = None) -> dict:
    """Resolve the IdP signing certificate for metadata generation.

    Tries per-SP certificate first (if sp_id given), then falls back
    to the tenant-level certificate.

    Returns:
        Certificate database row dict.

    Raises:
        NotFoundError: If no certificate is available.
    """
    cert = None
    if sp_id is not None:
        cert = database.sp_signing_certificates.get_signing_certificate(tenant_id, sp_id)
    if cert is None:
        cert = database.saml.get_sp_certificate(tenant_id)
    if cert is None:
        raise NotFoundError(
            message="IdP certificate not configured",
            code="idp_certificate_not_found",
        )
    return cert


def get_tenant_idp_metadata_xml(tenant_id: str, base_url: str) -> str:
    """Generate IdP metadata XML for downstream SPs to consume.

    No authorization required (public endpoint).

    Args:
        tenant_id: Tenant ID
        base_url: Base URL for the tenant

    Returns:
        XML metadata string

    Raises:
        NotFoundError: If no SP certificate is configured for the tenant
    """
    cert = _resolve_idp_certificate(tenant_id)

    entity_id = f"{base_url}/saml/idp/metadata"
    sso_url = f"{base_url}/saml/idp/sso"

    return generate_idp_metadata_xml(
        entity_id=entity_id,
        sso_url=sso_url,
        certificate_pem=cert["certificate_pem"],
    )


def get_sp_idp_metadata_xml(tenant_id: str, sp_id: str, base_url: str) -> str:
    """Generate IdP metadata XML with per-SP signing certificate.

    No authorization required (public endpoint).
    Falls back to tenant cert if no per-SP cert exists.

    Args:
        tenant_id: Tenant ID
        sp_id: Service Provider ID
        base_url: Base URL for the tenant

    Returns:
        XML metadata string

    Raises:
        NotFoundError: If SP not found or no certificate available
    """
    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(
            message="Service provider not found",
            code="sp_not_found",
        )

    cert = _resolve_idp_certificate(tenant_id, sp_id=sp_id)

    entity_id = f"{base_url}/saml/idp/metadata/{sp_id}"
    sso_url = f"{base_url}/saml/idp/sso"

    return generate_idp_metadata_xml(
        entity_id=entity_id,
        sso_url=sso_url,
        certificate_pem=cert["certificate_pem"],
    )
