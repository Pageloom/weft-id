"""Group member management routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from services import groups as groups_service
from services.exceptions import (
    ForbiddenError,
    NotFoundError,
    ServiceError,
)
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/admin/groups",
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)


def _parse_member_query_params(request: Request) -> dict:
    """Parse common query params for member list pages."""
    search = request.query_params.get("search", "").strip()
    sort_field = request.query_params.get("sort", "name")
    sort_order = request.query_params.get("order", "asc")

    # Parse role filter (comma-separated)
    role_param = request.query_params.get("role", "").strip()
    roles: list[str] | None = None
    if role_param:
        allowed_roles = {"member", "admin", "super_admin"}
        roles = [r.strip() for r in role_param.split(",") if r.strip() in allowed_roles]
        if not roles:
            roles = None

    # Parse status filter (comma-separated)
    status_param = request.query_params.get("status", "").strip()
    statuses: list[str] | None = None
    if status_param:
        allowed_statuses = {"active", "inactivated", "anonymized"}
        statuses = [s.strip() for s in status_param.split(",") if s.strip() in allowed_statuses]
        if not statuses:
            statuses = None

    try:
        page = max(1, int(request.query_params.get("page", "1")))
    except ValueError:
        page = 1

    try:
        page_size = int(request.query_params.get("size", "25"))
        if page_size not in (10, 25, 50, 100):
            page_size = 25
    except ValueError:
        page_size = 25

    # Validate sort field and order
    allowed_sort_fields = ["name", "email", "role", "status", "created_at", "last_activity_at"]
    if sort_field not in allowed_sort_fields:
        sort_field = "name"
    if sort_order not in ("asc", "desc"):
        sort_order = "asc"

    return {
        "search": search,
        "sort_field": sort_field,
        "sort_order": sort_order,
        "roles": roles,
        "statuses": statuses,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{group_id}/members", response_class=HTMLResponse)
def member_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Redirect to the membership tab (members management is now inline)."""
    qs = request.url.query
    location = f"/admin/groups/{group_id}/membership"
    if qs:
        location += f"?{qs}"
    return RedirectResponse(url=location, status_code=301)


@router.get("/{group_id}/members/add", response_class=HTMLResponse)
def add_members_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Display page to search and add members to a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    params = _parse_member_query_params(request)

    try:
        group = groups_service.get_group(requesting_user, group_id)
        result = groups_service.list_available_users_paginated(
            requesting_user,
            group_id,
            search=params["search"] or None,
            roles=params["roles"],
            statuses=params["statuses"],
            sort_field=params["sort_field"],
            sort_order=params["sort_order"],
            page=params["page"],
            page_size=params["page_size"],
        )
    except NotFoundError:
        return render_error_page(
            request,
            tenant_id,
            NotFoundError(message="Group not found", code="group_not_found"),
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    total_count = result.total
    page_size = params["page_size"]
    page = params["page"]
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    page = min(page, total_pages)
    offset = (page - 1) * page_size

    pagination = {
        "page": page,
        "page_size": page_size,
        "total_count": total_count,
        "total_pages": total_pages,
        "has_previous": page > 1,
        "has_next": page < total_pages,
        "start_index": offset + 1 if total_count > 0 else 0,
        "end_index": min(offset + page_size, total_count),
    }

    success = request.query_params.get("success")
    success_count = request.query_params.get("count")

    return templates.TemplateResponse(
        "groups_members_add.html",
        get_template_context(
            request,
            tenant_id,
            group=group,
            users=result.items,
            pagination=pagination,
            search=params["search"],
            sort_field=params["sort_field"],
            sort_order=params["sort_order"],
            roles=params["roles"] or [],
            statuses=params["statuses"] or [],
            success=success,
            success_count=success_count,
        ),
    )


@router.post("/{group_id}/members/add")
def add_members_submit(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    user_ids: Annotated[list[str], Form()],
    return_page: Annotated[str, Form(alias="r_page")] = "1",
    return_size: Annotated[str, Form(alias="r_size")] = "25",
    return_sort: Annotated[str, Form(alias="r_sort")] = "name",
    return_order: Annotated[str, Form(alias="r_order")] = "asc",
    return_search: Annotated[str, Form(alias="r_search")] = "",
    return_role: Annotated[str, Form(alias="r_role")] = "",
    return_status: Annotated[str, Form(alias="r_status")] = "",
):
    """Add selected users to the group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        count = groups_service.bulk_add_members(requesting_user, group_id, user_ids)
    except (NotFoundError, ForbiddenError) as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}/membership?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Redirect back to add page preserving current view state
    url = f"/admin/groups/{group_id}/members/add?success=members_added&count={count}"
    url += f"&page={return_page}&size={return_size}&sort={return_sort}&order={return_order}"
    if return_search:
        url += f"&search={return_search}"
    if return_role:
        url += f"&role={return_role}"
    if return_status:
        url += f"&status={return_status}"
    return RedirectResponse(url=url, status_code=303)


@router.post("/{group_id}/members/bulk-remove")
def bulk_remove_members(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    user_ids: Annotated[list[str], Form()],
):
    """Remove selected members from the group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        count = groups_service.bulk_remove_members(requesting_user, group_id, user_ids)
    except (NotFoundError, ForbiddenError) as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}/membership?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/membership?success=members_removed&count={count}",
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
            url=f"/admin/groups/{group_id}/membership?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/membership?success=member_removed",
        status_code=303,
    )
