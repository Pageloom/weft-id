"""User password API endpoints."""

from typing import Annotated

import routers.api.v1.users as _pkg
from api_dependencies import get_current_user_api, require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from routers.auth._helpers import _get_client_ip
from schemas.api import PasswordChange
from services.exceptions import RateLimitError, ServiceError
from utils.ratelimit import HOUR, ratelimit
from utils.service_errors import translate_to_http_exception

router = APIRouter()


@router.put("/me/password")
def change_password(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    body: PasswordChange,
):
    """
    Change the current user's password.

    Requires the current password for verification and validates the new
    password against the tenant's strength policy (length, zxcvbn score,
    HIBP breach check).

    Supports authentication via:
    - Bearer token (OAuth2)
    - Session cookie

    Request Body:
        current_password: The user's current password
        new_password: The desired new password

    Returns:
        204 No Content on success

    Errors:
        400: invalid_current_password, password_too_weak, no_password
        401: Not authenticated
        429: Too many password change attempts
    """
    try:
        ratelimit.prevent("pw_change:user:{user_id}", limit=5, timespan=HOUR, user_id=user["id"])
        ratelimit.prevent("pw_change:ip:{ip}", limit=10, timespan=HOUR, ip=_get_client_ip(request))
    except RateLimitError as exc:
        raise translate_to_http_exception(exc)

    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        _pkg.users_service.change_password(
            requesting_user, body.current_password, body.new_password
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    from starlette.responses import Response

    return Response(status_code=204)


@router.post("/{user_id}/force-password-reset")
def force_password_reset(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    user_id: str,
):
    """
    Force a user to change their password on next login.

    Sets a flag on the user that forces them to change their password
    before they can access the application. Any active sessions for
    the user are invalidated immediately.

    Requires admin role. Admins can force reset on any user.

    Path Parameters:
        user_id: UUID of the target user

    Returns:
        204 No Content on success

    Errors:
        400: cannot_force_reset_self, no_password, user_inactivated
        403: Not authorized (requires admin)
        404: User not found
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)
    try:
        _pkg.users_service.force_password_reset(requesting_user, user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    from starlette.responses import Response

    return Response(status_code=204)
