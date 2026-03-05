"""Group creation routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from schemas.groups import GroupCreate
from services import groups as groups_service
from services.exceptions import (
    ConflictError,
    ServiceError,
    ValidationError,
)
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/admin/groups",
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
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
        request,
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
