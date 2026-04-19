"""Admin Passkey API endpoints.

Admin view and revoke of other users' passkeys. Routes live under
``/api/v1/users/{user_id}/passkeys`` so they nest under the users namespace
in OpenAPI.

Authorisation is enforced inside the service functions (``admin_list_credentials``
and ``admin_revoke_credential`` both call ``require_admin``).
"""

from typing import Annotated

from api_dependencies import get_current_user_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request, Response
from schemas.webauthn import PasskeyResponse
from services import webauthn as webauthn_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


@router.get("/{user_id}/passkeys", response_model=list[PasskeyResponse])
def list_user_passkeys(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    user_id: str,
):
    """
    List a target user's registered passkeys. Admin role required.

    Path parameters:
    - user_id: target user's UUID

    Response fields match ``GET /api/v1/account/passkeys``.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        return webauthn_service.admin_list_credentials(requesting_user, user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{user_id}/passkeys/{credential_id}", status_code=204, response_class=Response)
def revoke_user_passkey(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    user_id: str,
    credential_id: str,
):
    """
    Revoke one of a target user's passkeys. Admin role required.

    Emits ``passkey_deleted`` with ``metadata.revoked_by_admin = true`` so
    audit queries can distinguish admin revocations from self-deletions.

    Path parameters:
    - user_id: target user's UUID
    - credential_id: passkey database UUID
    """
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        webauthn_service.admin_revoke_credential(requesting_user, user_id, credential_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return Response(status_code=204)
