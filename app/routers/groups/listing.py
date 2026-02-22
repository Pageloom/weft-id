"""Group listing routes."""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child
from services import groups as groups_service
from services.exceptions import ServiceError
from utils.service_errors import render_error_page
from utils.template_context import get_template_context

router = APIRouter(
    prefix="/admin/groups",
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
    view: Annotated[str, Query()] = "graph",
):
    """Display list of groups."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Normalize view param
    if view not in ("list", "graph"):
        view = "list"

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
            view=view,
            success=success,
            error=error,
        ),
    )
