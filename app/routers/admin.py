"""Admin routes for event log viewer."""

from datetime import date
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import get_first_accessible_child
from services import bg_tasks as bg_tasks_service
from services import event_log as event_log_service
from services import reactivation as reactivation_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.email import (
    send_account_reactivated_notification,
    send_reactivation_denied_notification,
)
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],  # All routes require admin role
    include_in_schema=False,
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


@router.get("/audit/", response_class=HTMLResponse)
@router.get("/audit", response_class=HTMLResponse)
def audit_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible audit page."""
    first_child = get_first_accessible_child("/admin/audit", user.get("role"))

    if first_child:
        return RedirectResponse(url=first_child, status_code=303)

    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/todo/", response_class=HTMLResponse)
@router.get("/todo", response_class=HTMLResponse)
def todo_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible todo page."""
    first_child = get_first_accessible_child("/admin/todo", user.get("role"))

    if first_child:
        return RedirectResponse(url=first_child, status_code=303)

    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/audit/events", response_class=HTMLResponse)
def event_log_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display paginated event log list."""
    requesting_user = build_requesting_user(user, tenant_id, request)

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
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "admin_events.html",
        get_template_context(
            request,
            tenant_id,
            events=result.items,
            pagination=pagination,
            success=success,
            error=error,
        ),
    )


@router.get("/audit/events/{event_id}", response_class=HTMLResponse)
def event_log_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    event_id: str,
):
    """Display single event log detail with full metadata."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        event = event_log_service.get_event(requesting_user, event_id)
    except NotFoundError:
        return RedirectResponse(url="/admin/audit/events?error=not_found", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return templates.TemplateResponse(
        request,
        "admin_event_detail.html",
        get_template_context(
            request,
            tenant_id,
            event=event,
        ),
    )


@router.post("/audit/events/export")
def trigger_export(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    start_date: Annotated[str, Form()] = "",
    end_date: Annotated[str, Form()] = "",
):
    """Trigger event log XLSX export job with optional date range."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        parsed_start = date.fromisoformat(start_date) if start_date else None
        parsed_end = date.fromisoformat(end_date) if end_date else None
    except ValueError:
        return RedirectResponse(url="/admin/audit/events?error=invalid_date", status_code=303)

    try:
        bg_tasks_service.create_export_task(
            requesting_user, start_date=parsed_start, end_date=parsed_end
        )
    except ValidationError:
        return RedirectResponse(url="/admin/audit/events?error=invalid_date_range", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/account/background-jobs?success=export_started", status_code=303)


# =============================================================================
# User Audit Export
# =============================================================================


@router.get("/audit/user-export", response_class=HTMLResponse)
def user_export_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    success: str | None = None,
):
    """Display user audit export page."""
    return templates.TemplateResponse(
        request,
        "admin_user_export.html",
        get_template_context(
            request,
            tenant_id,
            success=success,
        ),
    )


@router.post("/audit/user-export")
def trigger_user_export(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Trigger user audit XLSX export job."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        bg_tasks_service.create_user_export_task(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/account/background-jobs?success=export_started", status_code=303)


# =============================================================================
# Reactivation Requests
# =============================================================================


@router.get("/todo/reactivation", response_class=HTMLResponse)
def reactivation_requests_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display pending reactivation requests."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        requests = reactivation_service.list_pending_requests(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "admin_reactivation_requests.html",
        get_template_context(
            request,
            tenant_id,
            requests=requests,
            success=success,
            error=error,
        ),
    )


@router.get("/todo/reactivation/history", response_class=HTMLResponse)
def reactivation_requests_history(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display previously decided reactivation requests."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        requests = reactivation_service.list_previous_requests(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return templates.TemplateResponse(
        request,
        "admin_reactivation_history.html",
        get_template_context(
            request,
            tenant_id,
            requests=requests,
        ),
    )


@router.post("/todo/reactivation/{request_id}/approve")
def approve_reactivation_request(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    request_id: str,
):
    """Approve a reactivation request."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        result = reactivation_service.approve_request(requesting_user, request_id)
    except NotFoundError:
        return RedirectResponse(
            url="/admin/todo/reactivation?error=request_not_found",
            status_code=303,
        )
    except ValidationError as exc:
        return RedirectResponse(
            url=f"/admin/todo/reactivation?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Send notification email to the reactivated user
    if result.email:
        login_url = str(request.url_for("login_page"))
        send_account_reactivated_notification(
            result.email, login_url, tenant_id=requesting_user["tenant_id"]
        )

    return RedirectResponse(
        url="/admin/todo/reactivation?success=approved",
        status_code=303,
    )


@router.post("/todo/reactivation/{request_id}/deny")
def deny_reactivation_request(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    request_id: str,
):
    """Deny a reactivation request."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        result = reactivation_service.deny_request(requesting_user, request_id)
    except NotFoundError:
        return RedirectResponse(
            url="/admin/todo/reactivation?error=request_not_found",
            status_code=303,
        )
    except ValidationError as exc:
        return RedirectResponse(
            url=f"/admin/todo/reactivation?error={exc.code}",
            status_code=303,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    # Send notification email to the denied user
    if result.email:
        send_reactivation_denied_notification(result.email, tenant_id=requesting_user["tenant_id"])

    return RedirectResponse(
        url="/admin/todo/reactivation?success=denied",
        status_code=303,
    )
