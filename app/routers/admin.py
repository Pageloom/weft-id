"""Admin routes for event log viewer and exports."""

from pathlib import Path
from typing import Annotated

from dependencies import (
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child
from services import bg_tasks as bg_tasks_service
from services import event_log as event_log_service
from services import exports as exports_service
from services.exceptions import NotFoundError, ServiceError
from services.types import RequestingUser
from utils.service_errors import render_error_page
from utils.template_context import get_template_context

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],  # All routes require admin role
    include_in_schema=False,
)
templates = Jinja2Templates(directory="templates")


def _to_requesting_user(user: dict, tenant_id: str) -> RequestingUser:
    """Convert route user dict to RequestingUser for service layer."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=user.get("role", "member"),
    )


@router.get("/", response_class=HTMLResponse)
def admin_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible admin page."""
    first_child = get_first_accessible_child("/admin", user.get("role"))

    if first_child:
        return RedirectResponse(url=first_child, status_code=303)

    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/events", response_class=HTMLResponse)
def event_log_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display paginated event log list."""
    requesting_user = _to_requesting_user(user, tenant_id)

    # Parse pagination params
    try:
        page = max(1, int(request.query_params.get("page", "1")))
    except ValueError:
        page = 1

    try:
        page_size = int(request.query_params.get("size", "50"))
        if page_size not in [25, 50, 100]:
            page_size = 50
    except ValueError:
        page_size = 50

    try:
        result = event_log_service.list_events(
            requesting_user,
            page=page,
            limit=page_size,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Calculate pagination metadata
    total_pages = max(1, (result.total + page_size - 1) // page_size)
    page = min(page, total_pages)
    offset = (page - 1) * page_size

    pagination = {
        "page": page,
        "page_size": page_size,
        "total_count": result.total,
        "total_pages": total_pages,
        "has_previous": page > 1,
        "has_next": page < total_pages,
        "start_index": offset + 1 if result.total > 0 else 0,
        "end_index": min(offset + page_size, result.total),
    }

    success = request.query_params.get("success")

    return templates.TemplateResponse(
        "admin_events.html",
        get_template_context(
            request,
            tenant_id,
            events=result.items,
            pagination=pagination,
            success=success,
        ),
    )


@router.get("/events/{event_id}", response_class=HTMLResponse)
def event_log_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    event_id: str,
):
    """Display single event log detail with full metadata."""
    requesting_user = _to_requesting_user(user, tenant_id)

    try:
        event = event_log_service.get_event(requesting_user, event_id)
    except NotFoundError:
        return RedirectResponse(url="/admin/events?error=not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return templates.TemplateResponse(
        "admin_event_detail.html",
        get_template_context(
            request,
            tenant_id,
            event=event,
        ),
    )


@router.post("/events/export")
def trigger_export(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Trigger event log export job."""
    requesting_user = _to_requesting_user(user, tenant_id)

    try:
        bg_tasks_service.create_export_task(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/admin/exports?success=export_started", status_code=303)


@router.get("/exports", response_class=HTMLResponse)
def exports_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display list of available exports."""
    requesting_user = _to_requesting_user(user, tenant_id)

    try:
        result = exports_service.list_exports(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "admin_exports.html",
        get_template_context(
            request,
            tenant_id,
            exports=result.items,
            success=success,
            error=error,
        ),
    )


@router.get("/exports/download/{export_id}")
def download_export(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    export_id: str,
):
    """Download an export file."""
    requesting_user = _to_requesting_user(user, tenant_id)

    try:
        download_info = exports_service.get_download(requesting_user, export_id)
    except NotFoundError:
        return RedirectResponse(url="/admin/exports?error=not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    if download_info["storage_type"] == "spaces":
        # Redirect to signed S3 URL
        return RedirectResponse(url=download_info["url"], status_code=302)
    else:
        # Serve local file
        file_path = Path(download_info["path"])
        if not file_path.exists():
            return RedirectResponse(url="/admin/exports?error=file_missing", status_code=303)

        return FileResponse(
            path=file_path,
            filename=download_info["filename"],
            media_type=download_info.get("content_type", "application/gzip"),
        )
