"""OIDC upstream (relying-party) connection API endpoints.

Mirrors the SAML IdP API shape in ``routers.api.v1.saml`` for the consuming
direction of OIDC: list, create, get, patch, delete, enable, disable, and
set-default. The client secret is write-only -- it is accepted on create and
update but never returned; responses expose a ``client_secret_set`` boolean.
"""

from typing import Annotated

from api_dependencies import require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from schemas.oidc_upstream import (
    OIDCConnectionConfig,
    OIDCConnectionCreate,
    OIDCConnectionListResponse,
    OIDCConnectionUpdate,
    OIDCDomainBinding,
    OIDCDomainBindingCreate,
    OIDCDomainBindingList,
    OIDCUnboundDomain,
)
from services import oidc_upstream as oidc_upstream_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception
from utils.urls import tenant_base_url

router = APIRouter(prefix="/api/v1/oidc-upstream", tags=["OIDC Upstream"])


class ClaimMappingUpdate(BaseModel):
    """Request body for updating a connection's claim mapping."""

    claim_mapping: dict[
        Annotated[str, Field(max_length=255)], Annotated[str, Field(max_length=255)]
    ]


def _get_base_url(request: Request) -> str:
    """Get base URL from request for building the callback URL (always HTTPS)."""
    return tenant_base_url(request)


@router.get("/connections", response_model=OIDCConnectionListResponse)
def list_connections(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """
    List all OIDC upstream connections for the tenant.

    Requires super_admin role.

    Returns a list of connections with basic info (id, name, provider_type,
    enabled/default status).
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return oidc_upstream_service.list_connections(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/connections",
    response_model=OIDCConnectionConfig,
    status_code=status.HTTP_201_CREATED,
)
def create_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    data: OIDCConnectionCreate,
):
    """
    Create a new OIDC upstream connection.

    Requires super_admin role.

    Request body:
    - name: Display name for the connection (<=120 chars)
    - provider_type: One of generic, google, entra
    - issuer: The IdP issuer URL (<=2048 chars)
    - discovery_url: Optional discovery document URL (<=2048 chars)
    - authorization_endpoint / token_endpoint / userinfo_endpoint / jwks_uri:
      Optional manual endpoint overrides (<=2048 chars each)
    - client_id: OAuth2 client id (<=255 chars)
    - client_secret: OAuth2 client secret (write-only, encrypted at rest)
    - scopes: Space-separated scopes (<=500 chars)
    - claim_mapping: OIDC claim name -> WeftID attribute key mapping
    - correlation_claim: Claim used to correlate users (default 'sub')
    - group_claim_source: Reserved for deferred group-claims (written, unread)
    - hosted_domain: Google `hd` restriction (<=253 chars)
    - entra_tenant_id: Entra tenant id for authority composition (<=100 chars)
    - is_enabled / is_default / require_platform_mfa / jit_provisioning /
      allow_email_linking: Behavior flags

    Returns the created connection. The client secret is never returned.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return oidc_upstream_service.create_connection(requesting_user, data, base_url)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/connections/{connection_id}", response_model=OIDCConnectionConfig)
def get_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
):
    """
    Get details of a specific OIDC upstream connection.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Returns the full connection configuration including the derived callback
    URL. The client secret is never returned (only ``client_secret_set``).
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return oidc_upstream_service.get_connection(requesting_user, connection_id, base_url)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.patch("/connections/{connection_id}", response_model=OIDCConnectionConfig)
def update_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
    data: OIDCConnectionUpdate,
):
    """
    Update an OIDC upstream connection.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Request body (all fields optional):
    - name, issuer, discovery_url, authorization_endpoint, token_endpoint,
      userinfo_endpoint, jwks_uri, client_id, client_secret, scopes,
      claim_mapping, correlation_claim, group_claim_source, hosted_domain,
      entra_tenant_id, require_platform_mfa, jit_provisioning,
      allow_email_linking

    Returns the updated connection. The client secret is never returned.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return oidc_upstream_service.update_connection(
            requesting_user, connection_id, data, base_url
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connection(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
):
    """
    Delete an OIDC upstream connection.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Returns 204 No Content on success. Fails with 409 if the connection is
    enabled or has linked users.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        oidc_upstream_service.delete_connection(requesting_user, connection_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/connections/{connection_id}/enable", response_model=OIDCConnectionConfig)
def enable_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
):
    """
    Enable an OIDC upstream connection.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Returns the updated connection.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return oidc_upstream_service.set_connection_enabled(
            requesting_user, connection_id, enabled=True, base_url=base_url
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/connections/{connection_id}/disable", response_model=OIDCConnectionConfig)
def disable_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
):
    """
    Disable an OIDC upstream connection.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Returns the updated connection.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return oidc_upstream_service.set_connection_enabled(
            requesting_user, connection_id, enabled=False, base_url=base_url
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/connections/{connection_id}/claim-mapping")
def get_claim_mapping(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
):
    """
    Get a connection's claim mapping (OIDC claim -> WeftID attribute).

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Returns the mapping dict, e.g. ``{"email": "email", "first_name":
    "given_name", "last_name": "family_name"}``.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return {
            "claim_mapping": oidc_upstream_service.get_claim_mapping(requesting_user, connection_id)
        }
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.put("/connections/{connection_id}/claim-mapping", response_model=OIDCConnectionConfig)
def update_claim_mapping(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
    data: ClaimMappingUpdate,
):
    """
    Replace a connection's claim mapping.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Request body:
    - claim_mapping: ``{weftid_attribute: oidc_claim}``. Unknown attribute
      keys (outside the fixed set email/first_name/last_name and the
      14-attribute standard registry) are dropped.

    Returns the updated connection.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return oidc_upstream_service.update_claim_mapping(
            requesting_user, connection_id, data.claim_mapping, base_url
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Domain Binding Endpoints
# =============================================================================


@router.get("/connections/{connection_id}/domains", response_model=OIDCDomainBindingList)
def list_connection_domain_bindings(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
):
    """
    List domains bound to a specific OIDC connection.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Returns list of bound domains with binding info.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return oidc_upstream_service.list_domain_bindings(requesting_user, connection_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/connections/{connection_id}/domains",
    response_model=OIDCDomainBinding,
    status_code=status.HTTP_201_CREATED,
)
def bind_domain_to_connection(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
    binding_data: OIDCDomainBindingCreate,
):
    """
    Bind a privileged domain to an OIDC connection.

    Requires super_admin role.

    Unknown users with emails matching this domain will be routed to this
    connection's JIT flow during the email-first login flow. A domain binds to
    at most one IdP across both protocols; binding a domain already bound to a
    SAML IdP fails with 409.

    Path parameters:
    - connection_id: UUID of the connection to bind to

    Request body:
    - domain_id: UUID of the privileged domain to bind

    Returns the created domain binding.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return oidc_upstream_service.bind_domain_to_connection(
            requesting_user, connection_id, binding_data.domain_id
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete(
    "/connections/{connection_id}/domains/{domain_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unbind_domain_from_connection(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
    domain_id: str,
):
    """
    Unbind a domain from an OIDC connection.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection (for URL consistency)
    - domain_id: UUID of the domain to unbind

    Returns 204 No Content on success.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        oidc_upstream_service.unbind_domain_from_connection(requesting_user, domain_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.put(
    "/connections/{connection_id}/domains/{domain_id}",
    response_model=OIDCDomainBinding,
)
def rebind_domain_to_connection(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
    domain_id: str,
):
    """
    Rebind a domain from one OIDC connection to another.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the new connection to bind to
    - domain_id: UUID of the domain to rebind

    Returns the updated domain binding.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return oidc_upstream_service.rebind_domain_to_connection(
            requesting_user, domain_id, connection_id
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/domains/unbound", response_model=list[OIDCUnboundDomain])
def get_unbound_domains(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """
    List privileged domains not bound to any OIDC connection.

    Requires super_admin role.

    Returns list of domains available for binding.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return oidc_upstream_service.get_unbound_domains(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/connections/{connection_id}/users")
def list_connection_linked_users(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
):
    """
    List users linked to an OIDC upstream connection.

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Returns a list of linked users with link_id, user_id, sub, name, and email.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return oidc_upstream_service.list_connection_linked_users(requesting_user, connection_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete(
    "/connections/{connection_id}/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unlink_user_from_connection(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
    user_id: str,
):
    """
    Disconnect a user from an OIDC upstream connection.

    Requires super_admin role.

    Removes the user's ``(idp_id, sub)`` link, scrubs canonical attributes
    still matching the connection's last-mirrored snapshot, drops the mirror
    rows, and inactivates the user + unverifies their emails (mirroring SAML
    disconnect semantics).

    Path parameters:
    - connection_id: UUID of the connection
    - user_id: UUID of the user to disconnect

    Returns 204 No Content on success. Fails with 404 if the user, connection,
    or link does not exist.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        oidc_upstream_service.unlink_user_from_connection(requesting_user, user_id, connection_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/connections/{connection_id}/set-default", response_model=OIDCConnectionConfig)
def set_default_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
):
    """
    Set an OIDC upstream connection as the default.

    Requires super_admin role.

    The default connection is used when no specific connection is requested
    during login. Only one connection can be the default at a time.

    Path parameters:
    - connection_id: UUID of the connection

    Returns the updated connection.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    base_url = _get_base_url(request)
    try:
        return oidc_upstream_service.set_connection_default(
            requesting_user, connection_id, base_url
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
