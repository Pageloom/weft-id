"""REST API endpoints for downstream SAML Service Provider management."""

from typing import Annotated

from api_dependencies import get_current_user_api, require_admin_api, require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query, Request, UploadFile, status
from schemas.scim_admin import (
    ScimConfig,
    ScimConfigUpdate,
    ScimCredentialCreated,
    ScimCredentialImport,
    ScimCredentialList,
    ScimQueueStatus,
    ScimRetryResult,
    ScimSyncLogList,
)
from schemas.service_providers import (
    AssertionPreview,
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
from services.exceptions import RateLimitError, ServiceError
from services.scim import admin as scim_admin_service
from utils.ratelimit import MINUTE, ratelimit
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
    - assertion_encryption_algorithm: Encryption algorithm (aes256-cbc, aes256-gcm)
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
# Assertion Preview
# =============================================================================


@router.get("/{sp_id}/assertion-preview/{user_id}", response_model=AssertionPreview)
def preview_assertion(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    user_id: str,
):
    """Preview what a SAML assertion would contain for a specific user.

    Requires super_admin role.

    Returns the identity attributes, NameID, group claims, and access status
    that would be included in a SAML assertion to this SP for this user,
    without building or signing actual XML.

    Path parameters:
    - sp_id: UUID of the Service Provider
    - user_id: UUID of the target user
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return sp_service.preview_assertion(requesting_user, sp_id, user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Outbound SCIM (admin)
# =============================================================================


@router.get("/{sp_id}/scim/config", response_model=ScimConfig)
def get_scim_config_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Get the outbound SCIM configuration for one Service Provider.

    Requires super_admin role.

    Response fields:
    - sp_id: SP UUID.
    - scim_enabled: Whether SCIM push is active for this SP.
    - scim_target_url: Downstream SCIM 2.0 base URL.
    - scim_kind: Application-type preset (`generic`, `slack`, `github`,
      `atlassian`, `gitlab`). Unknown values fall back to `generic` at
      push time.
    - scim_membership_mode: Group push mode (`effective` flattens via
      `group_lineage`, `direct` uses only direct membership rows).
    - scim_log_retention: How long sync activity is retained (`3`, `6`,
      `12`, `24` months, or `forever`).
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return scim_admin_service.get_scim_config(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.put("/{sp_id}/scim/config", response_model=ScimConfig)
def update_scim_config_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    data: ScimConfigUpdate,
):
    """Update the outbound SCIM configuration for one Service Provider.

    Requires super_admin role.

    Request body (all fields optional, at least one required):
    - scim_enabled: Toggle SCIM push on/off. Requires a `scim_target_url`
      to already be set or set in the same payload.
    - scim_target_url: Downstream SCIM 2.0 base URL.
    - scim_kind: Application-type preset.
    - scim_membership_mode: Group push mode.
    - scim_log_retention: Retention selector value.

    Emits a `scim_config_updated` audit event with a `changed_fields`
    metadata list. Returns the new configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return scim_admin_service.update_scim_config(requesting_user, sp_id, data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{sp_id}/scim/credentials", response_model=ScimCredentialList)
def list_scim_credentials_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """List still-usable bearer credentials for an SP.

    Requires super_admin role.

    Includes credentials whose `revoked_at` is in the future (inside the
    rotation overlap window). Plaintext is never returned here -- only
    metadata. Use `POST` to mint a fresh credential.

    Response fields per item: id, sp_id, created_by_user_id, created_at,
    revoked_at, last_used_at.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return scim_admin_service.list_credentials(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/{sp_id}/scim/credentials",
    response_model=ScimCredentialCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_scim_credential_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Mint a fresh outbound SCIM bearer credential for an SP.

    Requires super_admin role.

    No request body. The server generates a 192-bit URL-safe token,
    encrypts it for storage, and returns the plaintext ONCE in the
    response. Capture and store it securely; subsequent reads return
    metadata only.

    Emits a `scim_token_created` audit event with the new credential id
    in metadata.

    Response fields: id, sp_id, created_at, plaintext, rotated_from_id
    (null for fresh tokens), rotated_from_revoke_at (null for fresh
    tokens).

    Rate limit: 10 mints per minute per super-admin user. Defence in
    depth against a runaway script -- the role is highly privileged but
    the table is small and a tight cap is cheap.
    """
    # Defence-in-depth: cap credential mints to 10/min per super-admin.
    # The role gate already prevents random callers; this just stops a
    # buggy or malicious script from spraying tokens.
    try:
        ratelimit.prevent(
            "scim_credential_create:user:{user_id}",
            limit=10,
            timespan=MINUTE,
            user_id=str(admin["id"]),
        )
    except RateLimitError as exc:
        raise translate_to_http_exception(exc)

    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return scim_admin_service.create_credential(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/{sp_id}/scim/credentials/import",
    response_model=ScimCredentialCreated,
    status_code=status.HTTP_201_CREATED,
)
def import_scim_credential_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    data: ScimCredentialImport,
):
    """Store an externally-supplied bearer token for an SP.

    Requires super_admin role.

    Use this when the downstream SCIM receiver mints the token on its
    side and expects the client to send it back verbatim (Authentik,
    some self-hosted SCIM servers). For receivers that accept any token
    the client picks (Slack, GitHub, most SaaS), use `POST /credentials`
    instead.

    Request body: `{"plaintext": "<token from downstream provider>"}`.
    The token is stripped of surrounding whitespace; embedded whitespace
    is rejected. The plaintext is encrypted at rest exactly as for
    generated tokens.

    Emits a `scim_token_imported` audit event with the new credential id
    in metadata.

    Rate limit: 10 imports per minute per super-admin user, shared with
    the generate-token endpoint.
    """
    try:
        ratelimit.prevent(
            "scim_credential_create:user:{user_id}",
            limit=10,
            timespan=MINUTE,
            user_id=str(admin["id"]),
        )
    except RateLimitError as exc:
        raise translate_to_http_exception(exc)

    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return scim_admin_service.import_credential(requesting_user, sp_id, data.plaintext)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/{sp_id}/scim/credentials/{credential_id}/rotate",
    response_model=ScimCredentialCreated,
)
def rotate_scim_credential_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    credential_id: str,
    overlap_hours: Annotated[int, Query(ge=0, le=720)] = 24,
):
    """Rotate an outbound SCIM bearer credential.

    Requires super_admin role.

    Creates a fresh credential AND schedules the named existing
    credential for revocation after `overlap_hours` (default 24, max
    720 = 30 days). Both tokens are accepted by the worker during the
    overlap window so an in-flight push cannot fail mid-rotation.

    Query parameters:
    - overlap_hours: Hours the existing credential stays valid after
      rotation (default 24, range 0..720). Pass 0 for immediate
      revocation.

    Emits a `scim_token_rotated` audit event with old_credential_id,
    new_credential_id, and overlap_hours in metadata.

    Response fields: id (new credential), sp_id, created_at, plaintext,
    rotated_from_id (old credential), rotated_from_revoke_at.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return scim_admin_service.rotate_credential(
            requesting_user, sp_id, credential_id, overlap_hours=overlap_hours
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete(
    "/{sp_id}/scim/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_scim_credential_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    credential_id: str,
):
    """Immediately revoke an outbound SCIM bearer credential.

    Requires super_admin role.

    No grace period. Use the rotate endpoint for the safer flow. Emits
    a `scim_token_revoked` audit event.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        scim_admin_service.revoke_credential(requesting_user, sp_id, credential_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{sp_id}/scim/sync-log", response_model=ScimSyncLogList)
def list_scim_sync_log_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
    status_filter: Annotated[str | None, Query(alias="status", max_length=20)] = None,
):
    """List recent sync activity for one SP.

    Requires super_admin role.

    Ordered by `completed_at DESC NULLS FIRST` so in-flight rows
    (`pending`, `running`) surface ahead of completed ones.

    Query parameters:
    - page: 1-indexed page number (default 1).
    - page_size: Rows per page (default 50, max 200).
    - status: Optional filter. One of `pending`, `running`, `done`,
      `failed`, `dead_letter`.

    Response: items (list of sync log entries), total, page, page_size.
    Each entry: id, sp_id, resource_type, resource_id, status, attempt,
    error, started_at, completed_at, created_at.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return scim_admin_service.list_sync_log(
            requesting_user, sp_id, page=page, page_size=page_size, status=status_filter
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{sp_id}/scim/queue-status", response_model=ScimQueueStatus)
def get_scim_queue_status_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Get a snapshot of the push queue for one SP.

    Requires super_admin role.

    Response fields:
    - sp_id: SP UUID.
    - pending: Count of queue rows awaiting a push attempt.
    - dead_lettered: Count of queue rows the worker has given up on
      after 5 failures (or a permanent error). Use the retry endpoint
      to revive them after fixing the underlying issue.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return scim_admin_service.get_queue_status(requesting_user, sp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/{sp_id}/scim/queue/retry-dead-lettered",
    response_model=ScimRetryResult,
)
def retry_dead_lettered_endpoint(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    sp_id: str,
):
    """Revive every dead-lettered queue row for one SP.

    Requires super_admin role.

    Clears `dead_letter_at`, resets `attempts` and `next_attempt_at` so
    the worker re-attempts the row on its next pass. `last_error` is
    preserved as a breadcrumb.

    No request body. Response fields: sp_id, revived (count of rows
    revived).
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return scim_admin_service.retry_dead_lettered(requesting_user, sp_id)
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

    Any authenticated user can call this endpoint. The returned list merges
    SAML service providers and forward-auth proxy apps, sorted by name.

    Each item carries:

    * ``id`` - the app's unique identifier
    * ``name`` - display name
    * ``description`` - optional description
    * ``kind`` - ``"saml"`` for a SAML service provider, ``"proxy"`` for a
      forward-auth proxy app
    * ``launch_url`` - where to navigate to launch the app. For SAML apps this
      is the IdP-initiated launch path (``/saml/idp/launch/{id}``); for proxy
      apps this is the app's external URL (navigating to it trips the
      forward-auth handshake).
    * ``entity_id`` - SAML entity ID (SAML apps only; ``null`` for proxy apps)
    * ``has_logo`` - whether a custom logo is uploaded (SAML apps only;
      ``false`` for proxy apps)
    * ``logo_updated_at`` - when the logo was last updated (SAML apps only;
      ``null`` for proxy apps)
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return sp_service.get_user_accessible_apps(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
