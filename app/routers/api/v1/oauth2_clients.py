"""OAuth2 client management API endpoints."""

from typing import Annotated

import services.oauth2 as oauth2_service
from api_dependencies import require_admin_api
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, HTTPException
from schemas.oauth2 import (
    B2BClientCreate,
    ClientResponse,
    ClientWithSecret,
    NormalClientCreate,
)
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

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
        "created_at": client["created_at"],
    }
    if include_secret:
        data["client_secret"] = client["client_secret"]
        return ClientWithSecret(**data)
    return ClientResponse(**data)


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
    user: Annotated[dict, Depends(require_admin_api)],
    client_data: B2BClientCreate,
):
    """
    Create a new B2B OAuth2 client (client credentials flow).

    This creates a service user with the specified role and links it to the client.

    Requires admin role.

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
        client_id: The client_id (e.g., "loom_client_abc123")

    Returns:
        204 No Content on success
    """
    rows_deleted = oauth2_service.delete_client(tenant_id, client_id, str(user["id"]))

    if rows_deleted == 0:
        raise HTTPException(status_code=404, detail="Client not found")

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
        client_id: The client_id (e.g., "loom_client_abc123")

    Returns:
        Client details including new client_secret (shown only once!)

    Note:
        The new client_secret is only returned once. Store it securely.
    """
    # Get client
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    # Regenerate secret
    new_secret = oauth2_service.regenerate_client_secret(tenant_id, client_id, str(user["id"]))

    # Return client with new secret
    client["client_secret"] = new_secret
    return _client_to_response(client, include_secret=True)
