"""Group member management routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from services import groups as groups_service
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceError,
)
from utils.service_errors import render_error_page

router = APIRouter(
    prefix="/admin/groups",
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)


@router.post("/{group_id}/members/add")
def add_member(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    user_id: Annotated[str, Form()],
):
    """Add a member to the group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        groups_service.add_member(requesting_user, group_id, user_id)
    except (NotFoundError, ConflictError) as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}?success=member_added",
        status_code=303,
    )


@router.post("/{group_id}/members/bulk")
def bulk_add_members(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    user_ids: Annotated[list[str], Form()],
):
    """Add multiple members to the group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        count = groups_service.bulk_add_members(requesting_user, group_id, user_ids)
    except (NotFoundError, ForbiddenError) as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}?success=members_bulk_added&count={count}",
        status_code=303,
    )


@router.post("/{group_id}/members/{user_id}/remove")
def remove_member(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    user_id: str,
):
    """Remove a member from the group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        groups_service.remove_member(requesting_user, group_id, user_id)
    except NotFoundError as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}?success=member_removed",
        status_code=303,
    )
