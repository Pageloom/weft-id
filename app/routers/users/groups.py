"""User group membership management routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_current_user,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from pages import has_page_access
from services import groups as groups_service
from services.exceptions import ConflictError, ForbiddenError, NotFoundError, ServiceError
from utils.service_errors import render_error_page

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
)


@router.post("/{user_id}/groups/add")
def add_user_to_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    group_id: Annotated[str, Form()],
):
    """Add a user to a single group (from user detail page)."""
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        groups_service.add_member(requesting_user, group_id, user_id)
    except (NotFoundError, ConflictError, ForbiddenError) as exc:
        return RedirectResponse(
            url=f"/users/{user_id}?error={exc.code}#groups",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/users/{user_id}?success=group_added#groups",
        status_code=303,
    )


@router.post("/{user_id}/groups/bulk")
def bulk_add_user_to_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    group_ids: Annotated[list[str], Form()],
):
    """Add a user to multiple groups (from user detail page)."""
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        count = groups_service.bulk_add_user_to_groups(requesting_user, user_id, group_ids)
    except (NotFoundError, ForbiddenError) as exc:
        return RedirectResponse(
            url=f"/users/{user_id}?error={exc.code}#groups",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/users/{user_id}?success=groups_bulk_added&count={count}#groups",
        status_code=303,
    )


@router.post("/{user_id}/groups/{group_id}/remove")
def remove_user_from_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    user_id: str,
    group_id: str,
):
    """Remove a user from a group (from user detail page)."""
    if not has_page_access("/users/user", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        groups_service.remove_member(requesting_user, group_id, user_id)
    except (NotFoundError, ForbiddenError) as exc:
        return RedirectResponse(
            url=f"/users/{user_id}?error={exc.code}#groups",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/users/{user_id}?success=group_removed#groups",
        status_code=303,
    )
