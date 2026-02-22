"""Group application (SP) assignment routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from services import service_providers as sp_service
from services.exceptions import (
    ConflictError,
    NotFoundError,
    ServiceError,
)
from utils.service_errors import render_error_page

router = APIRouter(
    prefix="/admin/groups",
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)


@router.post("/{group_id}/applications/add")
def assign_sp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    sp_id: Annotated[str, Form()],
):
    """Assign an SP to the group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        sp_service.assign_sp_to_group(requesting_user, sp_id, group_id)
    except (NotFoundError, ConflictError) as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}/applications?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/applications?success=sp_assigned",
        status_code=303,
    )


@router.post("/{group_id}/applications/{sp_id}/remove")
def remove_sp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    group_id: str,
    sp_id: str,
):
    """Remove an SP assignment from the group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        sp_service.remove_sp_group_assignment(requesting_user, sp_id, group_id)
    except NotFoundError as exc:
        return RedirectResponse(
            url=f"/admin/groups/{group_id}/applications?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"/admin/groups/{group_id}/applications?success=sp_removed",
        status_code=303,
    )
