"""User groups API endpoints."""

from typing import Annotated

import routers.api.v1.users as _pkg
from api_dependencies import get_current_user_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from schemas.groups import EffectiveMembershipList, UserGroupsAdd
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


@router.get("/{user_id}/groups", response_model=EffectiveMembershipList)
def get_user_direct_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    user_id: str,
):
    """
    Get a user's direct group memberships.

    Accessible by admins or the user themselves.

    Returns:
        List of direct group memberships
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        return _pkg.groups_service.get_direct_memberships(requesting_user, user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post("/{user_id}/groups", status_code=200)
def add_user_to_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    user_id: str,
    body: UserGroupsAdd,
):
    """
    Add a user to one or more groups.

    If a single group_id is provided, uses single add. If multiple, uses bulk add.
    Requires admin role.

    Returns:
        Count of groups added and the group_ids provided
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        if len(body.group_ids) == 1:
            _pkg.groups_service.add_member(requesting_user, body.group_ids[0], user_id)
            return {"added": 1, "group_ids": body.group_ids}
        else:
            count = _pkg.groups_service.bulk_add_user_to_groups(
                requesting_user, user_id, body.group_ids
            )
            return {"added": count, "group_ids": body.group_ids}
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete("/{user_id}/groups/{group_id}", status_code=204)
def remove_user_from_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user_api)],
    user_id: str,
    group_id: str,
):
    """
    Remove a user from a group.

    Requires admin role.
    """
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        _pkg.groups_service.remove_member(requesting_user, group_id, user_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
