"""User profile API endpoints."""

from typing import Annotated

import routers.api.v1.users as _pkg
from api_dependencies import get_current_user_api, require_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends
from schemas.api import (
    UserProfile,
    UserProfileUpdate,
)
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter()


@router.get("/roles", response_model=list[str])
def list_roles(
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """
    List available user roles.

    Requires admin role.

    Returns:
        List of role names: member, admin, super_admin
    """
    return _pkg.users_service.get_available_roles()


@router.get("/me", response_model=UserProfile)
def get_current_user_profile(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
):
    """
    Get the current user's profile.

    Supports authentication via:
    - Bearer token (OAuth2)
    - Session cookie

    Returns:
        User profile including id, email, name, role, timezone, locale, MFA status
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    return _pkg.users_service.get_current_user_profile(requesting_user, user)


@router.patch("/me", response_model=UserProfile)
def update_current_user_profile(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    profile_update: UserProfileUpdate,
):
    """
    Update the current user's profile.

    Supports authentication via:
    - Bearer token (OAuth2)
    - Session cookie

    Request Body:
        first_name: User's first name (optional)
        last_name: User's last name (optional)
        timezone: IANA timezone (optional, e.g., "America/New_York")
        locale: Two-letter locale code (optional, e.g., "en")

    Returns:
        Updated user profile

    Note:
        Only provided fields are updated. Omitted fields remain unchanged.
    """
    requesting_user = build_requesting_user(user, tenant_id, None)
    try:
        return _pkg.users_service.update_current_user_profile(requesting_user, user, profile_update)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
