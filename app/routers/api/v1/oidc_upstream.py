"""OIDC upstream (relying-party) connection API endpoints.

Mirrors the SAML IdP API shape in ``routers.api.v1.saml`` for the consuming
direction of OIDC: list, create, get, patch, delete, enable, disable,
set-default, and test (discovery and key set fetch). The client secret is
write-only -- it is accepted on create and update but never returned;
responses expose a ``client_secret_set`` boolean.
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
    provider_label, enabled/default status). provider_label is the
    provider's display name (e.g. "LinkedIn").
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
    - provider_type: One of generic, google, entra, microsoft (personal
      Microsoft accounts), linkedin, gitlab, github, discord, facebook,
      apple.
      github, discord and facebook are OAuth2 with fixed endpoints:
      discovery_url, the manual endpoints, hosted_domain and entra_tenant_id
      must be omitted, and issuer / correlation_claim must be omitted or
      equal the preset values (https://github.com, https://discord.com or
      https://www.facebook.com; sub); otherwise 400 oidc_setting_not_supported
    - issuer: The IdP issuer URL (<=2048 chars). Filled from the preset when
      omitted (required for generic; composed from entra_tenant_id for
      entra). For gitlab, set it to a self-managed instance's URL
    - discovery_url: Optional discovery document URL (<=2048 chars). Filled
      from the preset only when the issuer is the preset's issuer
    - authorization_endpoint / token_endpoint / userinfo_endpoint / jwks_uri /
      end_session_endpoint: Optional manual endpoint overrides (<=2048 chars
      each; discovery fills them when the provider publishes a document)
    - client_id: OAuth2 client id (<=255 chars)
    - client_secret: OAuth2 client secret (write-only, encrypted at rest).
      Rejected (400 oidc_setting_not_supported) for apple, whose client
      secret WeftID signs with apple_private_key
    - scopes: Space-separated scopes (<=500 chars)
    - claim_mapping: OIDC claim name -> WeftID attribute key mapping
    - correlation_claim: Claim used to correlate users (default 'sub')
    - group_claim_source: Claim carrying the user's groups (<=255 chars). When
      set, group membership is synced from it on every sign-in; omit/blank to
      leave groups alone
    - group_claim_name_key: Key holding the group name when the claim is a
      list of objects (<=100 chars, default 'name')
    - hosted_domain: Google `hd` restriction (<=253 chars)
    - entra_tenant_id: Entra tenant id for authority composition (<=100 chars)
    - is_enabled / is_default / require_platform_mfa / jit_provisioning /
      allow_email_linking: Behavior flags. allow_email_linking is rejected
      (400) for providers without a trusted verified-email claim (microsoft,
      facebook). For those providers, a user created by jit_provisioning
      must confirm their email address with a code before the sign-in
      completes
    - sign_out_at_idp: On WeftID sign-out, send the browser to the provider's
      end_session_endpoint so the provider session ends too (default false).
      Register the returned post_logout_redirect_uri at the provider first
    - show_on_login: Put a "Continue with <provider>" button for this
      connection on the sign-in page (default false). Shown only while the
      connection is enabled
    - github_allowed_orgs: github only. GitHub organization logins (each
      <=39 chars of letters, digits and hyphens; at most 100). A user must
      belong to at least one; omit for any GitHub account. Stored
      lower-cased. Rejected (400) on other provider types
    - apple_team_id / apple_key_id: apple only. The Apple Developer team id
      and the Sign in with Apple key id (each 10 upper-case letters and
      digits; 422 otherwise)
    - apple_private_key: apple only. The Sign in with Apple .p8 key in PEM
      form (<=2000 chars; write-only, encrypted at rest). Must be an EC P-256
      private key (400 oidc_apple_private_key_invalid otherwise). The three
      apple_* fields are rejected (400 oidc_setting_not_supported) on other
      provider types

    Returns the created connection. The client secret is never returned.
    The response's uses_discovery is false for a provider with fixed
    endpoints (github, discord, facebook). For apple the response carries
    apple_team_id, apple_key_id and apple_private_key_set (never the key).
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
      userinfo_endpoint, jwks_uri, end_session_endpoint, client_id,
      client_secret, scopes, claim_mapping, correlation_claim,
      group_claim_source, group_claim_name_key, hosted_domain,
      entra_tenant_id, require_platform_mfa, jit_provisioning,
      allow_email_linking, sign_out_at_idp, show_on_login,
      github_allowed_orgs, apple_team_id, apple_key_id, apple_private_key.
      An empty string for group_claim_source or group_claim_name_key clears
      the setting. allow_email_linking=true is rejected (400) for providers
      without a trusted verified-email claim (microsoft, facebook). For github,
      github_allowed_orgs replaces the list (an empty list removes the
      restriction). For github, discord and facebook the discovery/endpoint
      fields are rejected as on create. For apple, each apple_* field given
      replaces the stored value (the key is validated as on create) and an
      omitted one is kept; client_secret is rejected

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


@router.post("/connections/{connection_id}/test", response_model=OIDCConnectionConfig)
def test_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_super_admin_api)],
    connection_id: str,
):
    """
    Test an OIDC upstream connection against its provider.

    For an OIDC provider: fetches the IdP's discovery document (ignoring the
    refresh interval), checks its issuer and endpoints, stores the
    discovered endpoints, and fetches the JWKS from the discovered
    ``jwks_uri``. For github and discord: presents the client id, client
    secret and callback URL to the provider's token endpoint with a made-up
    code and reports whether the provider accepts the credentials (GitHub
    also reports a callback URL mismatch). For facebook: requests an app
    access token with the app id and secret (the callback URL is not
    checked). For apple: runs the OIDC checks above, then presents a client
    secret signed with the stored key to Apple's token endpoint with a
    made-up code and reports whether Apple accepts it (the return URL is not
    checked).

    Requires super_admin role.

    Path parameters:
    - connection_id: UUID of the connection

    Returns the updated connection. Fails with 400 (``oidc_connection_test_failed``)
    and the reason when the check fails; with 404 for an unknown connection.
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        return oidc_upstream_service.test_connection(
            requesting_user, connection_id, _get_base_url(request)
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

    Removes the user's link to the connection, scrubs canonical attributes
    still matching the connection's last-mirrored snapshot, and drops the
    mirror rows. When it was the user's last OIDC link, the user is also
    deactivated, their emails unverified and their tokens revoked (mirroring
    SAML disconnect semantics). A user with other links keeps signing in
    through them.

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
