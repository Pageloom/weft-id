"""SAML Identity Provider API endpoints."""

from typing import Annotated

from api_dependencies import require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, Field
from schemas.saml import (
    CertificateRotationResult,
    DomainBinding,
    DomainBindingCreate,
    DomainBindingList,
    IdPConfig,
    IdPCreate,
    IdPListResponse,
    IdPMetadataImport,
    IdPMetadataImportXML,
    IdPSPCertificate,
    IdPUpdate,
    MetadataRefreshResult,
    ProviderPresets,
    SAMLDebugEntryAPI,
    SAMLDebugEntryDetailAPI,
    UnboundDomain,
)
from services import saml as saml_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/saml", tags=["SAML"])


def _get_base_url(request: Request) -> str:
    """Get base URL from request for building SAML URLs (always HTTPS)."""
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"https://{host}"


# =============================================================================
# Provider Presets (Phase 4)
# =============================================================================


@router.get("/provider-presets/{provider_type}", response_model=ProviderPresets)
def get_provider_presets(
    provider_type: str,
    _user: Annotated[dict, Depends(require_super_admin_api)],
):
    """
    Get provider-specific attribute mapping presets and setup guide.

    Requires super_admin role (IdP configuration is a super admin operation).

    Returns known-good attribute mappings for common IdP providers.
    These presets help configure attribute mapping correctly for:
    - Okta: Uses email, firstName, lastName
    - Azure AD: Uses full URN claim names
    - Google: Uses email, first_name, last_name
    - Generic: Uses default mapping (email, firstName, lastName)

    Path parameters:
    - provider_type: One of 'okta', 'azure_ad', 'google', 'generic'

    Returns:
    - provider_type: The provider type
    - attribute_mapping: Dictionary of field names to SAML attribute names
    - setup_guide_url: URL to official setup documentation (if available)
    """
    result = saml_service.get_provider_presets(provider_type)
    if result is None:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=404,
            detail=f"Unknown provider type: {provider_type}. "
            f"Valid types: okta, azure_ad, google, generic",
        )
    return result


# =============================================================================
# IdP CRUD Endpoints
# =============================================================================


@router.get("/idps", response_model=IdPListResponse)
def list_identity_providers(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """
    List all SAML Identity Providers for the tenant.

    Requires super_admin role.

    Returns list of IdPs with basic info (id, name, provider_type, enabled status).
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.list_identity_providers(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps", response_model=IdPConfig, status_code=status.HTTP_201_CREATED)
def create_identity_provider(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_data: IdPCreate,
):
    """
    Create a new SAML Identity Provider.

    Requires super_admin role.

    Request body:
    - name: Display name for the IdP
    - provider_type: One of okta, azure_ad, google, generic
    - entity_id: IdP's SAML Entity ID
    - sso_url: IdP's Single Sign-On URL
    - slo_url: Optional Single Logout URL
    - certificate_pem: IdP's signing certificate (PEM format)
    - metadata_url: Optional metadata URL for auto-refresh
    - attribute_mapping: Map of SAML attributes to user fields
    - is_enabled: Whether the IdP is active
    - is_default: Whether this is the default IdP
    - require_platform_mfa: Require additional MFA after SAML auth
    - jit_provisioning: Enable just-in-time user creation

    Returns the created IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return saml_service.create_identity_provider(requesting_user, idp_data, base_url)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/idps/{idp_id}", response_model=IdPConfig)
def get_identity_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    Get details of a specific SAML Identity Provider.

    Requires super_admin role.

    Path parameters:
    - idp_id: UUID of the IdP

    Returns full IdP configuration including SP metadata URLs.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.get_identity_provider(requesting_user, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.patch("/idps/{idp_id}", response_model=IdPConfig)
def update_identity_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    idp_update: IdPUpdate,
):
    """
    Update a SAML Identity Provider.

    Requires super_admin role.

    Path parameters:
    - idp_id: UUID of the IdP

    Request body (all fields optional):
    - name: Display name
    - sso_url: Single Sign-On URL
    - slo_url: Single Logout URL
    - certificate_pem: Signing certificate
    - metadata_url: Metadata URL for auto-refresh
    - attribute_mapping: Attribute mapping
    - require_platform_mfa: Require platform MFA
    - jit_provisioning: Enable JIT provisioning

    Returns updated IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.update_identity_provider(requesting_user, idp_id, idp_update)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/idps/{idp_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_identity_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    Delete a SAML Identity Provider.

    Requires super_admin role.

    Path parameters:
    - idp_id: UUID of the IdP

    Returns 204 No Content on success.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        saml_service.delete_identity_provider(requesting_user, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# IdP State Management Endpoints
# =============================================================================


@router.post("/idps/{idp_id}/enable", response_model=IdPConfig)
def enable_identity_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    Enable a SAML Identity Provider.

    Requires super_admin role.

    Path parameters:
    - idp_id: UUID of the IdP

    Returns updated IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.set_idp_enabled(requesting_user, idp_id, enabled=True)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps/{idp_id}/disable", response_model=IdPConfig)
def disable_identity_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    Disable a SAML Identity Provider.

    Requires super_admin role.

    Path parameters:
    - idp_id: UUID of the IdP

    Returns updated IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.set_idp_enabled(requesting_user, idp_id, enabled=False)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps/{idp_id}/verbose-logging/enable", response_model=IdPConfig)
def enable_verbose_logging(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    Enable verbose assertion logging for a SAML Identity Provider.

    Requires super_admin role.

    Temporarily logs raw SAML assertions (XML and parsed attributes) for both
    successful and failed authentications from this IdP. Auto-expires after
    24 hours from activation.

    Path parameters:
    - idp_id: UUID of the IdP

    Returns updated IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.enable_verbose_logging(requesting_user, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps/{idp_id}/verbose-logging/disable", response_model=IdPConfig)
def disable_verbose_logging(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    Disable verbose assertion logging for a SAML Identity Provider.

    Requires super_admin role.

    Path parameters:
    - idp_id: UUID of the IdP

    Returns updated IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.disable_verbose_logging(requesting_user, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps/{idp_id}/set-default", response_model=IdPConfig)
def set_default_identity_provider(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    Set a SAML Identity Provider as the default.

    Requires super_admin role.

    The default IdP is used when no specific IdP is requested during login.
    Only one IdP can be the default at a time.

    Path parameters:
    - idp_id: UUID of the IdP

    Returns updated IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.set_idp_default(requesting_user, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Trust Establishment & Per-IdP SP Certificate Endpoints
# =============================================================================


class EstablishTrustRequest(BaseModel):
    """Request to establish trust on a pending IdP."""

    entity_id: str = Field(..., min_length=1, max_length=2048)
    sso_url: str = Field(..., min_length=1, max_length=2048)
    certificate_pem: str = Field(..., min_length=1, max_length=16000)
    slo_url: str | None = Field(None, max_length=2048)
    metadata_url: str | None = Field(None, max_length=2048)
    metadata_xml: str | None = Field(None, max_length=1000000)


class EstablishTrustFromUrlRequest(BaseModel):
    """Request to establish trust via metadata URL."""

    metadata_url: str = Field(..., min_length=1, max_length=2048)


class EstablishTrustFromXmlRequest(BaseModel):
    """Request to establish trust via metadata XML."""

    metadata_xml: str = Field(..., min_length=1, max_length=1000000)


@router.post("/idps/{idp_id}/establish-trust", response_model=IdPConfig)
def establish_trust(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    trust_data: EstablishTrustRequest,
):
    """
    Establish trust on a pending IdP with manual configuration.

    Requires super_admin role.

    Completes the second step of two-step IdP creation by providing
    the IdP-side configuration (entity_id, sso_url, certificate).
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.establish_idp_trust(
            requesting_user,
            idp_id=idp_id,
            entity_id=trust_data.entity_id,
            sso_url=trust_data.sso_url,
            certificate_pem=trust_data.certificate_pem,
            slo_url=trust_data.slo_url,
            metadata_url=trust_data.metadata_url,
            metadata_xml=trust_data.metadata_xml,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps/{idp_id}/establish-trust-url", response_model=IdPConfig)
def establish_trust_from_url(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    trust_data: EstablishTrustFromUrlRequest,
):
    """
    Establish trust on a pending IdP via metadata URL.

    Requires super_admin role.

    Fetches and parses metadata, then establishes trust.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return saml_service.import_idp_from_metadata_url(
            requesting_user,
            name="",
            provider_type="",
            metadata_url=trust_data.metadata_url,
            base_url=base_url,
            idp_id=idp_id,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps/{idp_id}/establish-trust-xml", response_model=IdPConfig)
def establish_trust_from_xml(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    trust_data: EstablishTrustFromXmlRequest,
):
    """
    Establish trust on a pending IdP via metadata XML.

    Requires super_admin role.

    Parses metadata XML, then establishes trust.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return saml_service.import_idp_from_metadata_xml(
            requesting_user,
            name="",
            provider_type="",
            metadata_xml=trust_data.metadata_xml,
            base_url=base_url,
            idp_id=idp_id,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/idps/{idp_id}/sp-certificate", response_model=IdPSPCertificate)
def get_idp_sp_certificate(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    Get the per-IdP SP certificate.

    Requires super_admin role.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        result = saml_service.get_idp_sp_certificate_for_display(requesting_user, idp_id)
        if result is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Per-IdP SP certificate not found")
        return result
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps/{idp_id}/rotate-sp-certificate", response_model=CertificateRotationResult)
def rotate_idp_sp_certificate(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    grace_period_days: int = Query(default=7, ge=0, le=90),
):
    """
    Rotate the per-IdP SP certificate with grace period.

    Requires super_admin role.

    Parameters:
        grace_period_days: Number of days the old certificate remains valid (0-90, default 7).
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.rotate_idp_sp_certificate(requesting_user, idp_id, grace_period_days)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Metadata Import & Refresh Endpoints
# =============================================================================


@router.post("/idps/import", response_model=IdPConfig, status_code=status.HTTP_201_CREATED)
def import_identity_provider(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    import_data: IdPMetadataImport,
):
    """
    Import a SAML Identity Provider from metadata URL.

    Requires super_admin role.

    Fetches IdP metadata from the provided URL and creates a new IdP
    with the extracted configuration (entity_id, sso_url, certificate).

    Request body:
    - name: Display name for the IdP
    - provider_type: One of okta, azure_ad, google, generic
    - metadata_url: URL to fetch SAML metadata from

    Returns the created IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return saml_service.import_idp_from_metadata_url(
            requesting_user=requesting_user,
            name=import_data.name,
            provider_type=import_data.provider_type,
            metadata_url=import_data.metadata_url,
            base_url=base_url,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps/import-xml", response_model=IdPConfig, status_code=status.HTTP_201_CREATED)
def import_identity_provider_from_xml(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    import_data: IdPMetadataImportXML,
):
    """
    Import a SAML Identity Provider from raw metadata XML.

    Requires super_admin role.

    Parses the provided XML metadata and creates a new IdP with the
    extracted configuration (entity_id, sso_url, certificate).

    Request body:
    - name: Display name for the IdP
    - provider_type: One of okta, azure_ad, google, generic
    - metadata_xml: Raw SAML metadata XML content

    Returns the created IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return saml_service.import_idp_from_metadata_xml(
            requesting_user=requesting_user,
            name=import_data.name,
            provider_type=import_data.provider_type,
            metadata_xml=import_data.metadata_xml,
            base_url=base_url,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


class ReimportMetadataXMLRequest(BaseModel):
    """Request to re-import IdP metadata from pasted XML."""

    metadata_xml: str = Field(..., min_length=1, max_length=1000000)


@router.post("/idps/{idp_id}/reimport-xml", response_model=IdPConfig)
def reimport_idp_metadata_xml(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    body: ReimportMetadataXMLRequest,
):
    """
    Re-import IdP metadata from raw XML on an existing IdP.

    Requires super_admin role.

    Parses the provided XML metadata and updates the IdP's SSO URL,
    SLO URL, and certificate. Use this when an IdP rotates its
    certificate and does not expose a metadata URL.

    Path parameters:
    - idp_id: UUID of the IdP

    Request body:
    - metadata_xml: Raw SAML metadata XML content

    Returns updated IdP configuration.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        saml_service.get_identity_provider(requesting_user, idp_id)
        parsed = saml_service.parse_idp_metadata_xml_to_schema(body.metadata_xml)
        return saml_service.update_identity_provider(
            requesting_user,
            idp_id,
            IdPUpdate(
                sso_url=parsed.sso_url,
                slo_url=parsed.slo_url,
                certificate_pem=parsed.certificate_pem,
            ),
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/idps/{idp_id}/refresh", response_model=MetadataRefreshResult)
def refresh_identity_provider_metadata(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    Refresh IdP metadata from its configured metadata URL.

    Requires super_admin role.

    Fetches the latest metadata from the IdP's metadata_url and updates
    the IdP configuration if changes are detected.

    Path parameters:
    - idp_id: UUID of the IdP

    Returns refresh result with success status and updated fields.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.refresh_idp_from_metadata(requesting_user, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Domain Binding Endpoints (Phase 3)
# =============================================================================


@router.get("/idps/{idp_id}/domains", response_model=DomainBindingList)
def list_idp_domain_bindings(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
):
    """
    List domains bound to a specific IdP.

    Requires super_admin role.

    Path parameters:
    - idp_id: UUID of the IdP

    Returns list of bound domains with binding info.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.list_domain_bindings(requesting_user, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/idps/{idp_id}/domains", response_model=DomainBinding, status_code=status.HTTP_201_CREATED
)
def bind_domain_to_idp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    binding_data: DomainBindingCreate,
):
    """
    Bind a privileged domain to an IdP.

    Requires super_admin role.

    Users with emails matching this domain will be routed to this IdP
    during the email-first login flow.

    Path parameters:
    - idp_id: UUID of the IdP to bind to

    Request body:
    - domain_id: UUID of the privileged domain to bind

    Returns the created domain binding.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.bind_domain_to_idp(requesting_user, idp_id, binding_data.domain_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/idps/{idp_id}/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def unbind_domain_from_idp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    domain_id: str,
):
    """
    Unbind a domain from an IdP.

    Requires super_admin role.

    Security: Cannot unbind if users would lose IdP access. Use the rebind
    endpoint to move users to a different IdP without blocking.

    Path parameters:
    - idp_id: UUID of the IdP (for URL consistency)
    - domain_id: UUID of the domain to unbind

    Returns 204 No Content on success.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        saml_service.unbind_domain_from_idp(requesting_user, domain_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.put("/idps/{idp_id}/domains/{domain_id}", response_model=DomainBinding)
def rebind_domain_to_idp(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    domain_id: str,
):
    """
    Rebind a domain from one IdP to another.

    Requires super_admin role.

    This allows seamless migration of users without the blocking check
    that the unbind endpoint performs.

    Path parameters:
    - idp_id: UUID of the new IdP to bind to
    - domain_id: UUID of the domain to rebind

    Returns the updated domain binding.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.rebind_domain_to_idp(requesting_user, domain_id, idp_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/domains/unbound", response_model=list[UnboundDomain])
def get_unbound_domains(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """
    List privileged domains not bound to any IdP.

    Requires super_admin role.

    Returns list of domains available for binding.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.get_unbound_domains(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# SAML Debug Entries
# =============================================================================


@router.get("/idps/{idp_id}/debug-entries", response_model=list[SAMLDebugEntryAPI])
def list_debug_entries(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    limit: Annotated[int, Query(ge=1, le=200, description="Max entries to return")] = 50,
):
    """
    List SAML debug log entries for an IdP.

    Requires super_admin role.

    Entries are created when verbose assertion logging is enabled and a
    SAML authentication fails. Auto-expires after 24 hours.

    Path parameters:
    - idp_id: UUID of the IdP

    Query parameters:
    - limit: Maximum number of entries (1-200, default 50)

    Returns list of debug entries, most recent first.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        entries = saml_service.list_saml_debug_entries(requesting_user, limit=limit)
        return [
            SAMLDebugEntryAPI(
                id=str(e["id"]),
                error_type=e["error_type"],
                error_detail=e.get("error_detail"),
                idp_id=str(e["idp_id"]) if e.get("idp_id") else None,
                idp_name=e.get("idp_name"),
                request_ip=e.get("request_ip"),
                created_at=e["created_at"],
            )
            for e in entries
            if not idp_id or str(e.get("idp_id", "")) == idp_id
        ]
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/idps/{idp_id}/debug-entries/{entry_id}", response_model=SAMLDebugEntryDetailAPI)
def get_debug_entry(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    idp_id: str,
    entry_id: str,
):
    """
    Get a specific SAML debug log entry with full XML.

    Requires super_admin role.

    Path parameters:
    - idp_id: UUID of the IdP
    - entry_id: UUID of the debug entry

    Returns the debug entry including the raw SAML response XML.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        entry = saml_service.get_saml_debug_entry(requesting_user, entry_id)
        return SAMLDebugEntryDetailAPI(
            id=str(entry["id"]),
            error_type=entry["error_type"],
            error_detail=entry.get("error_detail"),
            idp_id=str(entry["idp_id"]) if entry.get("idp_id") else None,
            idp_name=entry.get("idp_name"),
            request_ip=entry.get("request_ip"),
            created_at=entry["created_at"],
            saml_response_xml=entry.get("saml_response_xml"),
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
