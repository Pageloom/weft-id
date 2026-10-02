"""Dynamic client registration administration API.

The registration policy, the default access for registered clients, and the
initial access tokens that authorize registrations. The registration protocol
endpoints themselves (RFC 7591 / RFC 7592) live under ``/oauth2/register``.
"""

from typing import Annotated

import services.oauth2_registration as registration_service
from api_dependencies import require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Path, Request, status
from schemas.oauth2 import (
    InitialAccessTokenCreate,
    InitialAccessTokenCreated,
    InitialAccessTokenResponse,
    RegistrationAccessTokenReset,
    RegistrationSettings,
    RegistrationSettingsUpdate,
)
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception
from utils.urls import tenant_base_url

router = APIRouter(prefix="/api/v1/oauth2/registration", tags=["OAuth2 Client Registration"])


@router.get("/settings", response_model=RegistrationSettings)
def get_registration_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
):
    """
    Get the tenant's dynamic client registration settings.

    Requires admin role.

    Returns:
        policy ("off", "token_required", or "open"), default_access ("none" or
        "all"), and registration_endpoint (null while the policy is off)
    """
    try:
        return registration_service.get_registration_settings(
            build_requesting_user(user, tenant_id, request), tenant_base_url(request)
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.patch("/settings", response_model=RegistrationSettings)
def update_registration_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    data: RegistrationSettingsUpdate,
):
    """
    Change the dynamic client registration settings.

    Requires admin role.

    Request Body:
        policy: "off" (registration endpoint closed), "token_required" (an
            initial access token is required), or "open" (anyone who can reach
            the tenant may register a client). Optional.
        default_access: "none" (a registered client is available to no one
            until an admin assigns groups) or "all" (available to every user).
            Optional; applies to clients registered from now on.

    Returns:
        The updated settings
    """
    try:
        return registration_service.update_registration_settings(
            build_requesting_user(user, tenant_id, request), data, tenant_base_url(request)
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.get("/initial-access-tokens", response_model=list[InitialAccessTokenResponse])
def list_initial_access_tokens(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
):
    """
    List initial access tokens, newest first, including expired and revoked
    ones. Token values are never returned.

    Requires admin role.

    Returns:
        Tokens with id, name, creator, created/expiry/revoked/last-used times,
        the number of clients each registered, and status (active, expired,
        revoked)
    """
    try:
        return registration_service.list_initial_access_tokens(
            build_requesting_user(user, tenant_id, request)
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/initial-access-tokens",
    response_model=InitialAccessTokenCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_initial_access_token(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    data: InitialAccessTokenCreate,
):
    """
    Issue an initial access token. A client presents it as
    ``Authorization: Bearer <token>`` when registering.

    Requires admin role.

    Request Body:
        name: Who or what the token is for (required, max 255)
        expires_in_days: Days until the token stops working, 1 to 365
            (optional; omit for no expiry)

    Returns:
        The token record plus ``token``, the value. It is shown only once.
    """
    try:
        return registration_service.create_initial_access_token(
            build_requesting_user(user, tenant_id, request), data
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/initial-access-tokens/{token_id}/revoke", response_model=InitialAccessTokenResponse)
def revoke_initial_access_token(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    token_id: Annotated[str, Path(max_length=50)],
):
    """
    Revoke an initial access token. Clients it already registered keep working.

    Requires admin role.

    Path Parameters:
        token_id: The token's id

    Returns:
        The revoked token record. 404 when it does not exist or is already
        revoked.
    """
    try:
        return registration_service.revoke_initial_access_token(
            build_requesting_user(user, tenant_id, request), token_id
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/clients/{client_id}/reset-registration-token",
    response_model=RegistrationAccessTokenReset,
)
def reset_registration_access_token(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin_api)],
    client_id: Annotated[str, Path(max_length=255)],
):
    """
    Issue a new registration access token for a dynamically registered client.
    The old token stops working at once, so whoever held it can no longer
    read, change or delete the registration.

    Requires admin role.

    Path Parameters:
        client_id: The registered client's client_id

    Returns:
        ``client_id`` and the new ``registration_access_token`` (shown only
        once). 404 when no dynamically registered client has this client_id.
    """
    try:
        token = registration_service.reset_registration_access_token(
            build_requesting_user(user, tenant_id, request), client_id
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return RegistrationAccessTokenReset(client_id=client_id, registration_access_token=token)
