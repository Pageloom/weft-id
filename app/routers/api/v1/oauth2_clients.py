"""OAuth2 client management API endpoints."""

from typing import Annotated

import services.oauth2 as oauth2_service
from api_dependencies import require_admin_api, require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, HTTPException, Request, status
from schemas.oauth2 import (
    B2BClientCreate,
    ClientResponse,
    ClientRoleUpdate,
    ClientUpdate,
    ClientWithSecret,
    NormalClientCreate,
)
from schemas.oidc import (
    OIDCClientDiscoveryInfo,
    OIDCClientGroupAssignAdd,
    OIDCClientGroupAssignmentList,
    OIDCClientGroupBulkAssign,
    OIDCClientSettingsUpdate,
)
from services.exceptions import ServiceError
from services.oidc import clients as oidc_client_service
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
        "service_user_id": (
            str(client["service_user_id"]) if client.get("service_user_id") else None
        ),
        "is_active": client.get("is_active", True),
        "oidc_enabled": client.get("oidc_enabled", False),
        "available_to_all": client.get("available_to_all", False),
        "created_at": client["created_at"],
    }
    if include_secret:
        data["client_secret"] = client["client_secret"]
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
        redirect_uris: List of exact redirect URIs

    Returns:
        Client details including client_secret (shown only once!)

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

    The old secret is immediately invalidated.

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
    new_secret = oauth2_service.regenerate_client_secret(tenant_id, client_id, str(user["id"]))

    # Return client with new secret
    client["client_secret"] = new_secret
    return _client_to_response(client, include_secret=True)


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
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: str,
    client_data: ClientUpdate,
):
    """
    Update an OAuth2 client's name, description, and/or redirect URIs.

    Requires admin role.

    Path Parameters:
        client_id: The client_id (e.g., "weft-id_client_abc123")

    Request Body:
        name: New client name (optional)
        description: New description (optional)
        redirect_uris: New redirect URIs for normal clients (optional)

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
        )

        if not client:
            raise HTTPException(status_code=404, detail="Client not found")

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
