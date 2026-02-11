"""REST API endpoints for downstream SAML Service Provider management."""

from typing import Annotated

from api_dependencies import require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request, status
from schemas.service_providers import (
    IdPMetadataInfo,
    SPConfig,
    SPCreate,
    SPListResponse,
    SPMetadataImportURL,
    SPMetadataImportXML,
    SPMetadataURLInfo,
    SPSigningCertificate,
    SPSigningCertificateRotationResult,
)
from services import service_providers as sp_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/service-providers", tags=["Service Providers"])


# =============================================================================
# SP CRUD Endpoints
# =============================================================================


@router.get("/", response_model=SPListResponse)
def list_service_providers(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """List all registered downstream SAML Service Providers.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.list_service_providers(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/", response_model=SPConfig, status_code=status.HTTP_201_CREATED)
def create_service_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_data: SPCreate,
):
    """Create a new Service Provider from manual entry.

    Requires super_admin role.

    Request body:
    - name: Display name for the SP
    - entity_id: SP's SAML Entity ID
    - acs_url: Assertion Consumer Service URL
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.create_service_provider(requesting_user, sp_data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/import-xml", response_model=SPConfig, status_code=status.HTTP_201_CREATED)
def import_service_provider_from_xml(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    import_data: SPMetadataImportXML,
):
    """Import a Service Provider from metadata XML.

    Requires super_admin role.

    Parses the provided XML metadata and creates a new SP with the
    extracted configuration (entity_id, acs_url, certificate).

    Request body:
    - name: Display name for the SP
    - metadata_xml: Raw SAML metadata XML content
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.import_sp_from_metadata_xml(
            requesting_user,
            name=import_data.name,
            metadata_xml=import_data.metadata_xml,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/import-url", response_model=SPConfig, status_code=status.HTTP_201_CREATED)
def import_service_provider_from_url(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    import_data: SPMetadataImportURL,
):
    """Import a Service Provider from metadata URL.

    Requires super_admin role.

    Fetches SP metadata from the provided URL and creates a new SP
    with the extracted configuration.

    Request body:
    - name: Display name for the SP
    - metadata_url: URL to fetch SAML metadata from
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.import_sp_from_metadata_url(
            requesting_user,
            name=import_data.name,
            metadata_url=import_data.metadata_url,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


def _get_base_url(request: Request) -> str:
    """Get base URL from request for building SAML URLs (always HTTPS)."""
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"https://{host}"


@router.get("/idp-metadata-url", response_model=IdPMetadataInfo)
def get_idp_metadata_url(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """Get the IdP metadata URL and related endpoints.

    Requires super_admin role.

    Returns the metadata URL, entity ID, and SSO URL that downstream
    SPs need for SAML integration.
    """
    base_url = _get_base_url(request)
    return IdPMetadataInfo(
        metadata_url=f"{base_url}/saml/idp/metadata",
        entity_id=f"{base_url}/saml/idp/metadata",
        sso_url=f"{base_url}/saml/idp/sso",
    )


@router.get("/{sp_id}", response_model=SPConfig)
def get_service_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Get details of a specific Service Provider.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.get_service_provider(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{sp_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_service_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Delete a Service Provider.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        sp_service.delete_service_provider(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Per-SP Signing Certificate Endpoints
# =============================================================================


@router.get("/{sp_id}/signing-certificate", response_model=SPSigningCertificate)
def get_sp_signing_certificate(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Get signing certificate info for a Service Provider.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.get_sp_signing_certificate(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/{sp_id}/signing-certificate/rotate",
    response_model=SPSigningCertificateRotationResult,
)
def rotate_sp_signing_certificate(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Rotate the signing certificate for a Service Provider.

    Requires super_admin role.
    The previous certificate remains valid during a 7-day grace period.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.rotate_sp_signing_certificate(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{sp_id}/metadata-url", response_model=SPMetadataURLInfo)
def get_sp_metadata_url(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Get per-SP metadata URL info.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return sp_service.get_sp_metadata_url_info(requesting_user, sp_id, base_url)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
