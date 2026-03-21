"""REST API endpoints for downstream SAML Service Provider management."""

from typing import Annotated

from api_dependencies import get_current_user_api, require_admin_api, require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request, UploadFile, status
from schemas.service_providers import (
    SPConfig,
    SPCreate,
    SPEstablishTrustManual,
    SPEstablishTrustURL,
    SPEstablishTrustXML,
    SPGroupAssignAdd,
    SPGroupAssignmentList,
    SPGroupBulkAssign,
    SPListResponse,
    SPMetadataChangePreview,
    SPMetadataImportURL,
    SPMetadataImportXML,
    SPMetadataReimport,
    SPMetadataURLInfo,
    SPSigningCertificate,
    SPSigningCertificateRotationResult,
    SPUpdate,
    UserAppList,
)
from services import branding as branding_service
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
    - description: Optional description
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


@router.patch("/{sp_id}", response_model=SPConfig)
def update_service_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    sp_data: SPUpdate,
):
    """Update a Service Provider's configuration.

    Requires super_admin role.

    Request body (all fields optional, at least one required):
    - name: Display name
    - description: Description
    - acs_url: Assertion Consumer Service URL
    - slo_url: Single Logout URL
    - nameid_format: NameID format (emailAddress, persistent, transient, unspecified)
    - include_group_claims: Whether to include group claims in assertions
    - group_assertion_scope: Per-SP group scope override (null to inherit)
    - available_to_all: Whether the SP is accessible to all users
    - attribute_mapping: Custom SAML attribute name mappings (dict)
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.update_service_provider(requesting_user, sp_id, sp_data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{sp_id}/enable", response_model=SPConfig)
def enable_service_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Enable a disabled Service Provider.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.enable_service_provider(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{sp_id}/disable", response_model=SPConfig)
def disable_service_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Disable a Service Provider. Disabled SPs reject SSO requests.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.disable_service_provider(requesting_user, sp_id)
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
# Trust Establishment Endpoints
# =============================================================================


@router.post("/{sp_id}/establish-trust/url", response_model=SPConfig)
def establish_trust_from_url(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    data: SPEstablishTrustURL,
):
    """Establish trust with an SP by fetching its metadata URL.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.establish_trust_from_metadata_url(
            requesting_user, sp_id, data.metadata_url
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{sp_id}/establish-trust/xml", response_model=SPConfig)
def establish_trust_from_xml(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    data: SPEstablishTrustXML,
):
    """Establish trust with an SP by providing metadata XML.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.establish_trust_from_metadata_xml(
            requesting_user, sp_id, data.metadata_xml
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{sp_id}/establish-trust/manual", response_model=SPConfig)
def establish_trust_manually(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    data: SPEstablishTrustManual,
):
    """Establish trust with an SP by manually providing entity_id and acs_url.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.establish_trust_manually(
            requesting_user,
            sp_id,
            entity_id=data.entity_id,
            acs_url=data.acs_url,
            slo_url=data.slo_url,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# SP Metadata Lifecycle Endpoints
# =============================================================================


@router.post("/{sp_id}/metadata/preview-refresh", response_model=SPMetadataChangePreview)
def preview_metadata_refresh(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Preview changes from refreshing metadata from the stored URL.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.preview_sp_metadata_refresh(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{sp_id}/metadata/apply-refresh", response_model=SPConfig)
def apply_metadata_refresh(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Re-fetch metadata from URL and apply changes.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.apply_sp_metadata_refresh(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{sp_id}/metadata/preview-reimport", response_model=SPMetadataChangePreview)
def preview_metadata_reimport(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    data: SPMetadataReimport,
):
    """Preview changes from re-importing metadata from provided XML.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.preview_sp_metadata_reimport(requesting_user, sp_id, data.metadata_xml)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{sp_id}/metadata/apply-reimport", response_model=SPConfig)
def apply_metadata_reimport(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    data: SPMetadataReimport,
):
    """Parse provided XML and apply metadata changes.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.apply_sp_metadata_reimport(requesting_user, sp_id, data.metadata_xml)
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


# =============================================================================
# SP Group Assignments
# =============================================================================


@router.get("/{sp_id}/groups", response_model=SPGroupAssignmentList)
def list_sp_groups(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    sp_id: str,
):
    """List groups assigned to a Service Provider.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.list_sp_group_assignments(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{sp_id}/groups", status_code=status.HTTP_201_CREATED)
def assign_group_to_sp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    sp_id: str,
    data: SPGroupAssignAdd,
):
    """Assign a group to a Service Provider.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.assign_sp_to_group(requesting_user, sp_id, data.group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{sp_id}/groups/bulk", status_code=status.HTTP_201_CREATED)
def bulk_assign_groups_to_sp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    sp_id: str,
    data: SPGroupBulkAssign,
):
    """Bulk-assign groups to a Service Provider.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        count = sp_service.bulk_assign_sp_to_groups(requesting_user, sp_id, data.group_ids)
        return {"status": "ok", "assigned": count}
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{sp_id}/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_group_from_sp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    sp_id: str,
    group_id: str,
):
    """Remove a group assignment from a Service Provider.

    Requires admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        sp_service.remove_sp_group_assignment(requesting_user, sp_id, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# SP Logo Endpoints
# =============================================================================


@router.post("/{sp_id}/logo", status_code=status.HTTP_201_CREATED)
async def upload_sp_logo(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    file: UploadFile,
):
    """Upload a custom logo for a service provider.

    Requires super_admin role.
    Accepts PNG (square, min 48x48) or SVG (square viewBox) up to 256KB.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        data = await file.read()
        branding_service.upload_sp_logo(
            requesting_user,
            sp_id=sp_id,
            data=data,
            filename=file.filename,
        )
        return None
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{sp_id}/logo", status_code=status.HTTP_204_NO_CONTENT)
def delete_sp_logo(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Remove a custom logo from a service provider.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        branding_service.delete_sp_logo(requesting_user, sp_id=sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# My Apps (user-facing)
# =============================================================================

my_apps_router = APIRouter(prefix="/api/v1", tags=["My Apps"])


@my_apps_router.get("/my-apps", response_model=UserAppList)
def get_my_apps(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """Get applications accessible to the current user.

    Any authenticated user can call this endpoint.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return sp_service.get_user_accessible_apps(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
