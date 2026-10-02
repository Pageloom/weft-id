"""Account Authorized Apps API endpoints.

API-first mirror of the HTML "Authorized Apps" page under User Settings
(``routers.account``). Reuses the same service functions so behavior is
identical: a user sees and revokes only their own consent grants.
"""

from typing import Annotated

from api_dependencies import get_current_user_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Path, Request, status
from schemas.oidc import ConsentGrantResponse
from services.exceptions import ServiceError
from services.oidc import consent as consent_service
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/account/authorized-apps", tags=["Account Authorized Apps"])


@router.get("", response_model=list[ConsentGrantResponse])
def list_authorized_apps(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    List the applications the current user has allowed to access their account.

    Response (per grant):
    - id: grant UUID (use this to revoke)
    - client_id: the application's public client_id
    - client_name, client_description, client_is_active: the application
    - scopes: the granted scope set (union of every Allow)
    - granted_at / updated_at: first Allow and last widening
    """
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        return consent_service.list_my_grants(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_authorized_app(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    grant_id: Annotated[str, Path(max_length=50)],
):
    """
    Revoke one of the current user's consent grants.

    The application shows the consent page again on the next sign-in.
    Existing tokens are not revoked.

    Path Parameters:
        grant_id: UUID of the grant (from the listing)

    Returns:
        204 No Content on success; 404 when the grant is not the caller's.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        consent_service.revoke_my_grant(requesting_user, grant_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
    return None
