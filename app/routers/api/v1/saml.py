"""SAML Identity Provider API endpoints."""

from typing import Annotated

from api_dependencies import require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request, status
from schemas.saml import (
    DomainBinding,
    DomainBindingCreate,
    DomainBindingList,
    EmailCheckRequest,
    EmailCheckResponse,
    IdPConfig,
    IdPCreate,
    IdPListResponse,
    IdPMetadataImport,
    IdPMetadataImportXML,
    IdPUpdate,
    MetadataRefreshResult,
    SPCertificate,
    SPMetadata,
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
# SP Certificate & Metadata Endpoints
# =============================================================================


@router.get("/sp/certificate", response_model=SPCertificate)
def get_sp_certificate(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """
    Get the Service Provider certificate for SAML.

    Requires super_admin role.

    Creates a certificate if none exists. Returns the certificate
    in PEM format (private key is not exposed).

    Returns SP certificate with id, certificate_pem, expires_at, created_at.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return saml_service.get_or_create_sp_certificate(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/sp/metadata", response_model=SPMetadata)
def get_sp_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """
    Get Service Provider metadata info.

    Requires super_admin role.

    Returns SP metadata including entity_id, acs_url, metadata_url,
    certificate, and certificate expiration. This info is needed
    when configuring the IdP to trust this SP.

    Returns SP metadata for display in admin UI.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return saml_service.get_sp_metadata(requesting_user, base_url)
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
# Authentication Routing Endpoints (Phase 3)
# =============================================================================


@router.post("/auth/check-email", response_model=EmailCheckResponse)
def check_email_auth_route(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    check_request: EmailCheckRequest,
):
    """
    Determine authentication route for an email address.

    No authentication required (used on login page).

    This is the first step of the email-first login flow. Based on the
    email address, returns whether the user should:
    - Show password form (route_type: "password")
    - Redirect to IdP (route_type: "idp" or "idp_jit")
    - Show error (route_type: "not_found", "inactivated", etc.)

    Request body:
    - email: Email address to check

    Returns:
    - route_type: The authentication route
    - idp_id: IdP UUID if route_type is "idp" or "idp_jit"
    - idp_name: IdP display name if available
    """
    try:
        result = saml_service.determine_auth_route(tenant_id, check_request.email)
        # Return public-facing response (without user_id)
        return EmailCheckResponse(
            route_type=result.route_type,
            idp_id=result.idp_id,
            idp_name=result.idp_name,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
