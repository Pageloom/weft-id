"""OAuth2 client management API endpoints."""

from typing import Annotated

import services.oauth2 as oauth2_service
import services.oauth2_client_auth as oauth2_client_auth_service
import services.oauth2_tokens as oauth2_tokens_service
from api_dependencies import require_admin_api, require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from schemas.oauth2 import (
    B2BClientCreate,
    ClientAuthenticationUpdate,
    ClientResponse,
    ClientRoleUpdate,
    ClientSubjectTypeUpdate,
    ClientUpdate,
    ClientWithSecret,
    NormalClientCreate,
)
from schemas.oidc import (
    BackchannelLogoutDeliveryList,
    ClientConsentGrantResponse,
    OIDCClientDiscoveryInfo,
    OIDCClientGroupAssignAdd,
    OIDCClientGroupAssignmentList,
    OIDCClientGroupBulkAssign,
    OIDCClientSettingsUpdate,
)
from services.exceptions import ServiceError
from services.oidc import backchannel as backchannel_service
from services.oidc import clients as oidc_client_service
from services.oidc import consent as consent_service
from services.oidc import subject as oidc_subject_service
from utils.service_errors import translate_to_http_exception
from utils.urls import tenant_base_url

router = APIRouter(prefix="/api/v1/oauth2/clients", tags=["OAuth2 Clients"])


def _client_to_response(
    client: dict, include_secret: bool = False
) -> ClientResponse | ClientWithSecret:
    """Convert database client dict to ClientResponse/ClientWithSecret schema."""
    data = {
        "id": str(client["id"]),
        "client_id": client["client_id"],
        "client_type": client["client_type"],
        "name": client["name"],
        "description": client.get("description"),
        "redirect_uris": client.get("redirect_uris"),
        "post_logout_redirect_uris": client.get("post_logout_redirect_uris") or [],
        "frontchannel_logout_uri": client.get("frontchannel_logout_uri"),
        "frontchannel_logout_session_required": bool(
            client.get("frontchannel_logout_session_required")
        ),
        "backchannel_logout_uri": client.get("backchannel_logout_uri"),
        "backchannel_logout_session_required": bool(
            client.get("backchannel_logout_session_required")
        ),
        "service_user_id": (
            str(client["service_user_id"]) if client.get("service_user_id") else None
        ),
        "is_active": client.get("is_active", True),
        "oidc_enabled": client.get("oidc_enabled", False),
        "available_to_all": client.get("available_to_all", False),
        "can_introspect_tenant_tokens": bool(client.get("can_introspect_tenant_tokens")),
        "dynamically_registered": bool(client.get("dynamically_registered")),
        "logo_uri": client.get("logo_uri"),
        "client_uri": client.get("client_uri"),
        "policy_uri": client.get("policy_uri"),
        "tos_uri": client.get("tos_uri"),
        "initiate_login_uri": client.get("initiate_login_uri"),
        "device_grant_enabled": bool(client.get("device_grant_enabled")),
        "is_public": bool(client.get("is_public")),
        "client_auth_method": client.get("client_auth_method") or "client_secret",
        "jwks": client.get("jwks"),
        "jwks_uri": client.get("jwks_uri"),
        "token_endpoint_auth_signing_alg": client.get("token_endpoint_auth_signing_alg"),
        "require_pushed_authorization_requests": bool(
            client.get("require_pushed_authorization_requests")
        ),
        "subject_type": client.get("subject_type") or "public",
        "sector_identifier_uri": client.get("sector_identifier_uri"),
        "created_at": client["created_at"],
    }
    if include_secret:
        data["client_secret"] = client.get("client_secret")
        return ClientWithSecret(**data)
    return ClientResponse(**data)


def _require_super_admin_for_b2b(client: dict, user: dict) -> None:
    """Raise 403 if the target client is B2B and the caller is not super_admin."""
    if client.get("client_type") == "b2b" and user.get("role") != "super_admin":
        raise HTTPException(
            status_code=403, detail="B2B client management requires super_admin role"
        )


@router.get("", response_model=list[ClientResponse])
def list_clients(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_type: str | None = None,
):
    """
    List all OAuth2 clients for the tenant.

    Requires admin role.

    Query Parameters:
        client_type: Optional filter by type ('normal' or 'b2b')

    Returns:
        List of OAuth2 clients (without secrets)
    """
    clients = oauth2_service.get_all_clients(tenant_id, client_type=client_type)
    return [_client_to_response(client) for client in clients]


@router.post("", response_model=ClientWithSecret, status_code=201)
def create_normal_client(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_data: NormalClientCreate,
):
    """
    Create a new normal OAuth2 client (authorization code flow).

    Requires admin role.

    Request Body:
        name: Client name
        description: Optional client description
        redirect_uris: List of exact redirect URIs (at least one, except for a
            public client, which takes none)
        post_logout_redirect_uris: Optional list of exact URIs the end_session
            endpoint may redirect to after logout (absolute http/https, no fragment)
        frontchannel_logout_uri: Optional URL loaded in an iframe when the
            user's WeftID session ends (absolute http/https, no fragment, same
            scheme, host and port as a redirect URI)
        frontchannel_logout_session_required: Whether that URL receives the
            iss and sid query parameters (default true)
        backchannel_logout_uri: Optional URL WeftID POSTs a signed logout token
            to when the user's WeftID session ends (absolute http/https, no
            fragment)
        backchannel_logout_session_required: Whether the logout token carries
            the sid claim (default true)
        initiate_login_uri: Optional URL of the app that starts a sign-in at
            WeftID (absolute https, no fragment). An OIDC-enabled client with
            one appears in My Apps and launches there with the iss parameter.
        device_grant_enabled: Whether the client may use the OAuth 2.0 device
            authorization grant (RFC 8628) (default false)
        is_public: Create a public client (default false): no secret; it sends
            its client_id alone and may use only the device authorization and
            refresh token grants. Switches the device grant on, takes no
            redirect URIs, post-logout redirect URIs, front-channel logout URI,
            or login initiation URI. Cannot be changed after creation.

    Returns:
        Client details including client_secret (shown only once!; null for a
        public client)

    Note:
        The client_secret is only returned once. Store it securely.
    """
    try:
        client = oauth2_service.create_normal_client(
            tenant_id=tenant_id,
            name=client_data.name,
            redirect_uris=client_data.redirect_uris,
            created_by=str(user["id"]),
            description=client_data.description,
            post_logout_redirect_uris=client_data.post_logout_redirect_uris,
            frontchannel_logout_uri=client_data.frontchannel_logout_uri,
            frontchannel_logout_session_required=client_data.frontchannel_logout_session_required,
            backchannel_logout_uri=client_data.backchannel_logout_uri,
            backchannel_logout_session_required=client_data.backchannel_logout_session_required,
            initiate_login_uri=client_data.initiate_login_uri,
            device_grant_enabled=client_data.device_grant_enabled,
            is_public=client_data.is_public,
        )

        return _client_to_response(client, include_secret=True)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/b2b", response_model=ClientWithSecret, status_code=201)
def create_b2b_client(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_super_admin_api)],
    client_data: B2BClientCreate,
):
    """
    Create a new B2B OAuth2 client (client credentials flow).

    This creates a service user with the specified role and links it to the client.

    Requires super_admin role.

    Request Body:
        name: Client name (used as service user first_name)
        role: Role for service user (member, admin, super_admin)

    Returns:
        Client details including client_secret (shown only once!)

    Note:
        The client_secret is only returned once. Store it securely.
        The service user is automatically created and linked to this client.
    """
    try:
        client = oauth2_service.create_b2b_client(
            tenant_id=tenant_id,
            name=client_data.name,
            role=client_data.role,
            created_by=str(user["id"]),
            description=client_data.description,
        )

        return _client_to_response(client, include_secret=True)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{client_id}", status_code=204)
def delete_client(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
):
    """
    Delete an OAuth2 client.

    This cascades to delete all tokens and authorization codes.
    For B2B clients, the service user remains (must be deleted separately if needed).

    Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Returns:
        204 No Content on success
    """
    # Check B2B access before deletion
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    _require_super_admin_for_b2b(client, user)

    oauth2_service.delete_client(tenant_id, client_id, str(user["id"]))

    return None  # 204 No Content


@router.post("/{client_id}/regenerate-secret", response_model=ClientWithSecret)
def regenerate_client_secret(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
):
    """
    Regenerate the client secret for an OAuth2 client.

    The old secret is immediately invalidated. A public client and a
    private_key_jwt client have no secret (400).

    Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Returns:
        Client details including new client_secret (shown only once!)

    Note:
        The new client_secret is only returned once. Store it securely.
    """
    # Get client
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    _require_super_admin_for_b2b(client, user)

    # Regenerate secret
    try:
        new_secret = oauth2_service.regenerate_client_secret(tenant_id, client_id, str(user["id"]))
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    # Return client with new secret
    client["client_secret"] = new_secret
    return _client_to_response(client, include_secret=True)


@router.put("/{client_id}/authentication", response_model=ClientWithSecret)
def set_client_authentication(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    data: ClientAuthenticationUpdate,
):
    """
    Set how a confidential client authenticates, and its public keys.

    Requires admin role (super_admin for a B2B client). A public client's
    authentication cannot be changed (400).

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Request Body:
        method: "client_secret" (client_secret_basic or client_secret_post) or
            "private_key_jwt" (RFC 7523 client assertions signed with the
            client's key)
        jwks: The client's public keys as a JSON Web Key Set (optional; RSA or
            EC keys, at most 20, no private members)
        jwks_uri: URL of the client's JSON Web Key Set (optional; absolute
            https). Give jwks or jwks_uri, not both; private_key_jwt needs one.

    Switching to private_key_jwt invalidates the client secret at once.
    Switching back to client_secret generates a new secret, returned once in
    ``client_secret`` (null otherwise).

    Returns:
        Client details, with ``client_secret`` after switching to client_secret
    """
    existing = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Client not found")
    _require_super_admin_for_b2b(existing, user)

    try:
        client = oauth2_client_auth_service.set_client_authentication(
            build_requesting_user(user, tenant_id, request),
            client_id,
            method=data.method,
            jwks=data.jwks,
            jwks_uri=data.jwks_uri,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return _client_to_response(client, include_secret=True)


@router.put("/{client_id}/subject", response_model=ClientResponse)
def set_client_subject_type(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    data: ClientSubjectTypeUpdate,
):
    """
    Set whether an app receives public or pairwise subject identifiers.

    Requires admin role. Normal clients (apps) only; 404 for a B2B client.

    Changing it changes the ``sub`` of every user at the app (in ID tokens,
    userinfo, introspection and logout tokens), so the app sees them as new
    users unless it links accounts some other way.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Request Body:
        subject_type: "public" (sub is the WeftID user id) or "pairwise"
            (sub is derived from the user id and the app's sector,
            OpenID Connect Core 8.1)
        sector_identifier_uri: pairwise only (optional). An https URL serving
            a JSON array that lists every redirect URI of the app; it is
            fetched now. Its host is the sector. Without it, all redirect
            URIs must share one host, which is the sector. Must be omitted
            or null for public.

    Returns:
        Client details
    """
    try:
        client = oidc_subject_service.set_client_subject_type(
            build_requesting_user(user, tenant_id, request),
            client_id,
            subject_type=data.subject_type,
            sector_identifier_uri=data.sector_identifier_uri,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return _client_to_response(client)


@router.get("/{client_id}", response_model=ClientResponse)
def get_client(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
):
    """
    Get details for a single OAuth2 client.

    Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Returns:
        Client details (without secret)
    """
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    _require_super_admin_for_b2b(client, user)

    return _client_to_response(client)


@router.patch("/{client_id}", response_model=ClientResponse)
def update_client(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    client_data: ClientUpdate,
):
    """
    Update an OAuth2 client's name, description, redirect URIs, logout settings,
    login initiation URL, device grant switch, PAR requirement, and token
    introspection permission.

    Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Request Body:
        name: New client name (optional)
        description: New description (optional)
        redirect_uris: New redirect URIs for normal clients (optional)
        post_logout_redirect_uris: New post-logout redirect URIs for normal
            clients (optional; absolute http/https, no fragment; [] clears them)
        frontchannel_logout_uri: New front-channel logout URL for normal
            clients (optional; same scheme, host and port as a redirect URI;
            "" clears it)
        frontchannel_logout_session_required: Whether the front-channel
            logout URL receives iss and sid (optional, normal clients)
        backchannel_logout_uri: New back-channel logout URL for normal
            clients (optional; absolute http/https, no fragment; "" clears it)
        backchannel_logout_session_required: Whether the logout token carries
            the sid claim (optional, normal clients)
        initiate_login_uri: New login initiation URL for normal clients
            (optional; absolute https, no fragment; "" clears it)
        device_grant_enabled: Whether the client may use the OAuth 2.0 device
            authorization grant (optional, normal clients only)
        require_pushed_authorization_requests: Whether the client may only
            start an authorization through the pushed authorization request
            endpoint, /oauth2/par (optional, normal confidential clients only)
        can_introspect_tenant_tokens: Whether the client may introspect every
            token in the tenant, not just its own (optional, any client type
            except a public client)

    Whether a client is public is fixed at creation. A public client keeps the
    device grant on and takes no redirect URIs, post-logout redirect URIs,
    front-channel logout URL, or login initiation URL (400).

    Returns:
        Updated client details
    """
    # Check B2B access before update
    existing = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Client not found")
    _require_super_admin_for_b2b(existing, user)

    try:
        client = oauth2_service.update_client(
            tenant_id=tenant_id,
            client_id=client_id,
            actor_user_id=str(user["id"]),
            name=client_data.name,
            description=client_data.description,
            redirect_uris=client_data.redirect_uris,
            post_logout_redirect_uris=client_data.post_logout_redirect_uris,
            frontchannel_logout_uri=client_data.frontchannel_logout_uri,
            frontchannel_logout_session_required=client_data.frontchannel_logout_session_required,
            backchannel_logout_uri=client_data.backchannel_logout_uri,
            backchannel_logout_session_required=client_data.backchannel_logout_session_required,
            initiate_login_uri=client_data.initiate_login_uri,
            device_grant_enabled=client_data.device_grant_enabled,
            require_pushed_authorization_requests=(
                client_data.require_pushed_authorization_requests
            ),
        )

        if not client:
            raise HTTPException(status_code=404, detail="Client not found")

        if client_data.can_introspect_tenant_tokens is not None:
            client = oauth2_tokens_service.set_tenant_introspection(
                build_requesting_user(user, tenant_id, request),
                client_id,
                client_data.can_introspect_tenant_tokens,
            )

        return _client_to_response(client)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.patch("/{client_id}/role", response_model=ClientResponse)
def update_client_role(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_super_admin_api)],
    client_id: str,
    role_data: ClientRoleUpdate,
):
    """
    Update the service user role for a B2B OAuth2 client.

    Requires super_admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_b2b_abc123")

    Request Body:
        role: New role ('member', 'admin', 'super_admin')

    Returns:
        Updated client details
    """
    try:
        client = oauth2_service.update_b2b_client_role(
            tenant_id=tenant_id,
            client_id=client_id,
            role=role_data.role,
            actor_user_id=str(user["id"]),
        )

        if not client:
            raise HTTPException(status_code=404, detail="Client not found")

        return _client_to_response(client)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{client_id}/deactivate", response_model=ClientResponse)
def deactivate_client(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
):
    """
    Deactivate an OAuth2 client (soft delete).

    Deactivated clients cannot request new tokens. All existing tokens are revoked.

    Requires admin role. B2B clients require super_admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Returns:
        Updated client details
    """
    # Check B2B access before deactivation
    existing = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Client not found")
    _require_super_admin_for_b2b(existing, user)

    client = oauth2_service.deactivate_client(tenant_id, client_id, str(user["id"]))

    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    return _client_to_response(client)


@router.post("/{client_id}/reactivate", response_model=ClientResponse)
def reactivate_client(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
):
    """
    Reactivate a deactivated OAuth2 client.

    Requires admin role. B2B clients require super_admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Returns:
        Updated client details
    """
    # Check B2B access before reactivation
    existing = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Client not found")
    _require_super_admin_for_b2b(existing, user)

    client = oauth2_service.reactivate_client(tenant_id, client_id, str(user["id"]))

    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    return _client_to_response(client)


# =============================================================================
# OIDC settings and group-based access control (normal / App clients only)
# =============================================================================


@router.patch("/{client_id}/oidc", response_model=ClientResponse)
def update_oidc_settings(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    data: OIDCClientSettingsUpdate,
):
    """Update an App's OIDC settings.

    Requires admin role. Applies only to normal (authorization-code) clients;
    B2B service accounts return 400.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Request Body (both optional, supply at least one):
        oidc_enabled: Turn the client into an OpenID Provider relying party.
            When true, the token endpoint issues a signed RS256 ID token (when
            the openid scope is requested) and group-based access control is
            enforced at authorize time.
        available_to_all: When true, every active tenant user may sign in and
            group assignments become organisational only. When false, only
            members of assigned groups (and their descendants) may sign in.

    Note:
        WeftID does not model a per-client allowed-scope allowlist. Released
        claims are gated by the scopes the relying party REQUESTS at authorize
        time; there is no per-client scope field to manage here.

    Returns:
        Updated client details.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        client = oidc_client_service.set_oidc_settings(
            requesting_user,
            client_id,
            oidc_enabled=data.oidc_enabled,
            available_to_all=data.available_to_all,
        )
        return _client_to_response(client)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{client_id}/oidc/urls", response_model=OIDCClientDiscoveryInfo)
def get_oidc_urls(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
):
    """Get the tenant's OIDC endpoint URLs to configure in the downstream app.

    Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Returns:
        Read-only URLs derived from the request host: issuer, discovery_url
        (/.well-known/openid-configuration), jwks_uri, authorization_endpoint,
        token_endpoint, userinfo_endpoint.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return oidc_client_service.get_client_discovery_info(
            requesting_user, client_id, tenant_base_url(request)
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/{client_id}/groups", response_model=OIDCClientGroupAssignmentList)
def list_oidc_client_groups(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
):
    """List groups assigned to an OIDC client.

    Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Returns:
        items (each with id, oauth2_client_id, group_id, group_name,
        group_description, group_type, assigned_by, assigned_at) and total.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return oidc_client_service.list_client_group_assignments(requesting_user, client_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{client_id}/groups", status_code=status.HTTP_201_CREATED)
def assign_oidc_client_group(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    data: OIDCClientGroupAssignAdd,
):
    """Assign a group to an OIDC client.

    Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Request Body:
        group_id: UUID of the group to grant access.

    Returns:
        The created assignment.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return oidc_client_service.assign_client_to_group(requesting_user, client_id, data.group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{client_id}/groups/bulk", status_code=status.HTTP_201_CREATED)
def bulk_assign_oidc_client_groups(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    data: OIDCClientGroupBulkAssign,
):
    """Bulk-assign groups to an OIDC client.

    Requires admin role. Duplicate assignments are silently skipped.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Request Body:
        group_ids: List of group UUIDs to grant access.

    Returns:
        {"status": "ok", "assigned": <count of new assignments>}
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        count = oidc_client_service.bulk_assign_client_to_groups(
            requesting_user, client_id, data.group_ids
        )
        return {"status": "ok", "assigned": count}
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{client_id}/groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_oidc_client_group(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    group_id: str,
):
    """Remove a group assignment from an OIDC client.

    Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")
        group_id: UUID of the group to revoke.

    Returns:
        204 No Content on success.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        oidc_client_service.remove_client_group_assignment(requesting_user, client_id, group_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Remembered consent (per client)
# =============================================================================


@router.get("/{client_id}/consents", response_model=list[ClientConsentGrantResponse])
def list_client_consents(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
):
    """List the users who have allowed this App and the scopes they granted.

    Requires admin role. Only Apps (authorization-code clients) have consent.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Response (per grant):
    - id: grant UUID (use this to revoke)
    - user_id, user_email, user_name: the granting user
    - scopes: the granted scope set (union of every Allow)
    - granted_at / updated_at: first Allow and last widening
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return consent_service.list_client_grants(requesting_user, client_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{client_id}/consents/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_client_consent(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    grant_id: str,
):
    """Revoke one user's remembered consent for this App.

    The user sees the consent page again on their next sign-in to the App.
    Existing tokens are not revoked. Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")
        grant_id: UUID of the grant (from the consents listing)

    Returns:
        204 No Content on success; 404 when the grant does not belong to the App.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        consent_service.revoke_client_grant(requesting_user, client_id, grant_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return None


# =============================================================================
# Back-channel logout deliveries (per client)
# =============================================================================


@router.get(
    "/{client_id}/backchannel-logout-deliveries",
    response_model=BackchannelLogoutDeliveryList,
)
def list_backchannel_logout_deliveries(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    delivery_status: Annotated[
        str | None,
        Query(
            alias="status",
            max_length=50,
            description="Only deliveries in this status (pending, delivered, failed)",
        ),
    ] = None,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(25, ge=1, le=250, description="Number of results per page"),
):
    """List the back-channel logout tokens sent to this App, newest first.

    One delivery is recorded per ended session (sign-out, session end, user
    deactivation or deletion) the App received an ID token in. Deliveries are
    kept for 30 days after they finish. Requires admin role. Only Apps
    (authorization-code clients) take part in back-channel logout.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Query Parameters:
        status: Only deliveries in this status: pending, delivered or failed
        page: Page number (default: 1)
        limit: Results per page (default: 25, max: 250)

    Response:
    - items: deliveries (id, user_id, user_name, user_email, status, attempts,
      last_http_status, last_error, created_at, last_attempt_at,
      next_attempt_at, completed_at)
    - total: deliveries matching the status filter
    - page, limit: the page returned
    - counts: pending, delivered and failed totals (all statuses)
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return backchannel_service.list_backchannel_logout_deliveries(
            requesting_user, client_id, status=delivery_status, page=page, limit=limit
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
