"""Account Passkeys API endpoints.

API-first mirror of the HTML passkey routes in ``routers.account_passkeys``.
Reuses the same service functions so behavior is identical.
"""

from typing import Annotated

from api_dependencies import get_current_user_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request, Response
from schemas.webauthn import (
    CompleteRegistrationRequest,
    CompleteRegistrationResponse,
    PasskeyResponse,
    RenamePasskeyRequest,
)
from services import webauthn as webauthn_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/account/passkeys", tags=["Account Passkeys"])


@router.get("", response_model=list[PasskeyResponse])
def list_passkeys(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    List the current user's passkeys.

    Response:
    - id: database UUID of the passkey (use this for rename/delete)
    - name: user-chosen label (<= 100 chars)
    - transports: authenticator transport hints, or null
    - backup_eligible / backup_state: indicates platform authenticators (synced passkeys)
    - created_at / last_used_at: ISO-8601 timestamps
    """
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        return webauthn_service.list_credentials(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/begin-registration")
def begin_registration(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Start a passkey registration ceremony.

    Returns ``PublicKeyCredentialCreationOptions`` in the shape the browser's
    ``navigator.credentials.create()`` expects (under the ``publicKey`` key).
    The challenge is stashed in the session with a 5-minute TTL.

    No request body is required.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        result = webauthn_service.begin_registration(requesting_user, request)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return {"publicKey": result.public_key}


@router.post("/complete-registration", response_model=CompleteRegistrationResponse)
def complete_registration(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    payload: CompleteRegistrationRequest,
):
    """
    Finish a passkey registration ceremony.

    Request body:
    - name: user-chosen label (1-100 chars)
    - response: the PublicKeyCredential JSON returned by
      ``navigator.credentials.create()``

    Response:
    - credential: the newly stored passkey
    - backup_codes: one-time backup codes, returned ONCE on the user's first
      successful passkey registration if they had no prior backup codes. Null
      on all subsequent registrations.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        return webauthn_service.complete_registration(requesting_user, request, payload)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.patch("/{credential_id}", response_model=PasskeyResponse)
def rename_passkey(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    credential_id: str,
    payload: RenamePasskeyRequest,
):
    """
    Rename one of the current user's passkeys.

    Path parameters:
    - credential_id: passkey database UUID (from ``GET /api/v1/account/passkeys``)

    Request body:
    - name: new label (1-100 chars)
    """
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        return webauthn_service.rename_credential(requesting_user, credential_id, payload.name)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{credential_id}", status_code=204, response_class=Response)
def delete_passkey(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    credential_id: str,
):
    """
    Delete one of the current user's passkeys.

    Path parameters:
    - credential_id: passkey database UUID (from ``GET /api/v1/account/passkeys``)
    """
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        webauthn_service.delete_credential(requesting_user, credential_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return Response(status_code=204)
