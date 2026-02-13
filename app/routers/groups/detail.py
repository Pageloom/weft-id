"""Group detail, update, and delete routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from schemas.groups import GroupUpdate
from services import groups as groups_service
from services import service_providers as sp_service
from services.exceptions import (
    ConflictError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from utils.service_errors import render_error_page
from utils.template_context import get_template_context

router = APIRouter(
    prefix="/admin/groups",
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)
templates = Jinja2Templates(directory="templates")


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
        parents = groups_service.list_parents(requesting_user, group_id)
        children = groups_service.list_children(requesting_user, group_id)

        # Get available options for hierarchy dropdowns (via service layer)
        available_parents = groups_service.list_available_parents(requesting_user, group_id)
        available_children = groups_service.list_available_children(requesting_user, group_id)

        # Fetch effective member count only if the group has children
        effective_member_count = None
        if group.child_count > 0:
            eff = groups_service.get_effective_members(
                requesting_user, group_id, page=1, page_size=1
            )
            effective_member_count = eff.total

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
            parents=parents.items,
            children=children.items,
            available_parents=available_parents,
            available_children=available_children,
            effective_member_count=effective_member_count,
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
