"""Group relationship management routes (parent/child)."""

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
    NotFoundError,
    ServiceError,
    ValidationError,
)
from utils.service_errors import render_error_page

router = APIRouter(
    prefix="/admin/groups",
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)


@router.post("/{group_id}/relationships/clear")
def clear_relationships(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
):
    """Remove all parent and child relationships for a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        groups_service.remove_all_relationships(requesting_user, group_id)
    except NotFoundError as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}/delete?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/delete?success=relationships_cleared",
        status_code=303,
    )


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
            url=f"/admin/groups/{group_id}/relationships?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/relationships?success=child_added",
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
            url=f"/admin/groups/{group_id}/relationships?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/relationships?success=child_removed",
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
            url=f"/admin/groups/{group_id}/relationships?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/relationships?success=parent_added",
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
            url=f"/admin/groups/{group_id}/relationships?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/relationships?success=parent_removed",
        status_code=303,
    )
