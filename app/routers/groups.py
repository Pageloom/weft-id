"""Group management routes (admin only)."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child
from schemas.groups import GroupCreate, GroupUpdate
from services import groups as groups_service
from services import service_providers as sp_service
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from utils.service_errors import render_error_page
from utils.template_context import get_template_context

router = APIRouter(
    prefix="/admin/groups",
    tags=["admin-groups"],
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
def groups_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the groups list."""
    first_child = get_first_accessible_child("/admin/groups", user.get("role"))
    if first_child:
        return RedirectResponse(url=first_child, status_code=303)
    return RedirectResponse(url="/admin", status_code=303)


@router.get("/list", response_class=HTMLResponse)
def groups_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    search: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=10, le=100)] = 25,
):
    """Display list of groups."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        result = groups_service.list_groups(
            requesting_user,
            search=search,
            page=page,
            page_size=size,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "groups_list.html",
        get_template_context(
            request,
            tenant_id,
            groups=result.items,
            pagination={
                "page": result.page,
                "page_size": result.limit,
                "total": result.total,
                "total_pages": max(1, (result.total + result.limit - 1) // result.limit),
            },
            search=search or "",
            success=success,
            error=error,
        ),
    )


@router.get("/new", response_class=HTMLResponse)
def new_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display form to create a new group."""
    error = request.query_params.get("error")
    name = request.query_params.get("name", "")
    description = request.query_params.get("description", "")

    return templates.TemplateResponse(
        "groups_new.html",
        get_template_context(
            request,
            tenant_id,
            error=error,
            name=name,
            description=description,
        ),
    )


@router.post("/new")
def create_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
):
    """Create a new group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        group_data = GroupCreate(name=name, description=description or None)
        group = groups_service.create_group(requesting_user, group_data)
    except (ValidationError, ConflictError) as exc:
        # Redirect back to form with error
        return RedirectResponse(
            url=f"/admin/groups/new?error={exc.code}&name={name}&description={description}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group.id}?success=created",
        status_code=303,
    )


@router.get("/{group_id}", response_class=HTMLResponse)
def group_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Display group details with members and relationships."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        group = groups_service.get_group(requesting_user, group_id)
        members = groups_service.list_members(requesting_user, group_id)
        parents = groups_service.list_parents(requesting_user, group_id)
        children = groups_service.list_children(requesting_user, group_id)

        # Get available options for dropdowns (via service layer)
        available_users = groups_service.list_available_users_for_group(requesting_user, group_id)
        available_parents = groups_service.list_available_parents(requesting_user, group_id)
        available_children = groups_service.list_available_children(requesting_user, group_id)

        # Fetch effective members only if the group has children
        effective_members = None
        if group.child_count > 0:
            effective_members = groups_service.get_effective_members(requesting_user, group_id)

        # Fetch assigned service providers
        assigned_sps = []
        try:
            sp_result = sp_service.list_group_sp_assignments(requesting_user, group_id)
            assigned_sps = sp_result.items
        except ServiceError:
            pass

    except NotFoundError:
        return render_error_page(
            request,
            tenant_id,
            NotFoundError(message="Group not found", code="group_not_found"),
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "groups_detail.html",
        get_template_context(
            request,
            tenant_id,
            group=group,
            members=members.items,
            parents=parents.items,
            children=children.items,
            available_users=available_users,
            available_parents=available_parents,
            available_children=available_children,
            effective_members=effective_members,
            assigned_sps=assigned_sps,
            success=success,
            error=error,
        ),
    )


@router.post("/{group_id}/edit")
def update_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
):
    """Update group details."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        group_data = GroupUpdate(name=name, description=description)
        groups_service.update_group(requesting_user, group_id, group_data)
    except (ValidationError, ConflictError, NotFoundError) as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}?success=updated",
        status_code=303,
    )


@router.post("/{group_id}/delete")
def delete_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Delete a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        groups_service.delete_group(requesting_user, group_id)
    except NotFoundError:
        return RedirectResponse(
            url="/admin/groups/list?error=group_not_found",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/groups/list?success=deleted",
        status_code=303,
    )


# =============================================================================
# Member Management
# =============================================================================


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


# =============================================================================
# Relationship Management
# =============================================================================


@router.post("/{group_id}/children/add")
def add_child(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    child_group_id: Annotated[str, Form()],
):
    """Add a child group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        groups_service.add_child(requesting_user, group_id, child_group_id)
    except (NotFoundError, ConflictError, ValidationError) as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}?success=child_added",
        status_code=303,
    )


@router.post("/{group_id}/children/{child_group_id}/remove")
def remove_child(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    child_group_id: str,
):
    """Remove a child group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        groups_service.remove_child(requesting_user, group_id, child_group_id)
    except NotFoundError as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}?success=child_removed",
        status_code=303,
    )


@router.post("/{group_id}/parents/add")
def add_parent(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    parent_group_id: Annotated[str, Form()],
):
    """Add a parent group (by making this group a child of the parent)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        # Adding a parent = making this group a child of that parent
        groups_service.add_child(requesting_user, parent_group_id, group_id)
    except (NotFoundError, ConflictError, ValidationError) as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}?success=parent_added",
        status_code=303,
    )


@router.post("/{group_id}/parents/{parent_group_id}/remove")
def remove_parent(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    parent_group_id: str,
):
    """Remove a parent group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        # Removing a parent = removing this group as a child of that parent
        groups_service.remove_child(requesting_user, parent_group_id, group_id)
    except NotFoundError as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}?success=parent_removed",
        status_code=303,
    )
