"""User groups API endpoints."""

from typing import Annotated

import routers.api.v1.users as _pkg
from api_dependencies import get_current_user_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from schemas.groups import EffectiveMembershipList
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception

router = APIRouter()


@router.get("/{user_id}/effective-groups", response_model=EffectiveMembershipList)
def get_user_effective_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    user_id: str,
):
    """
    Get all groups a user is effectively in (direct + inherited).

    Accessible by admins or the user themselves.

    Returns:
        List of effective group memberships with is_direct flag
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        return _pkg.groups_service.get_effective_memberships(requesting_user, user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
