"""Audit routes: event log viewer and index redirect.

Promoted to top-level ``/audit`` from ``/admin/audit`` as part of the nav
restructure (see ``.claude/ITERATION_nav_restructure.md``). This module was
formerly ``routers/admin.py``, which also owned the bare ``/admin`` wrapper
page; that wrapper is retired in this iteration (bare ``/admin`` and
``/admin/`` now 301 to ``/dashboard`` via ``routers.legacy_redirects``).
SAML Debug Log stays in ``routers.saml.admin.debug`` (only its path moved
to ``/audit/saml-debug``); User Export moved to ``/directory/exports`` in
Iteration 1.
"""

from datetime import date
from typing import Annotated

from constants.event_types import DEFAULT_TIERS, VALID_TIERS
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
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.redirects import safe_redirect
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    dependencies=[Depends(require_admin)],  # All routes require admin role
    include_in_schema=False,
)


@router.get("/", response_class=HTMLResponse)
def audit_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible audit page."""
    first_child = get_first_accessible_child("/audit", user.get("role"))

    return safe_redirect(first_child, default="/dashboard")


@router.get("/events", response_class=HTMLResponse)
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

    # Parse tier filter (comma-separated, defaults to security+admin)
    tiers_param = request.query_params.get("tiers", "")
    if tiers_param:
        active_tiers = [t for t in tiers_param.split(",") if t in VALID_TIERS]
    else:
        active_tiers = list(DEFAULT_TIERS)

    try:
        result = event_log_service.list_events(
            requesting_user,
            page=page,
            limit=page_size,
            tiers=active_tiers if active_tiers else None,
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
            active_tiers=active_tiers,
            all_tiers=VALID_TIERS,
            success=success,
            error=error,
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
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        event = event_log_service.get_event(requesting_user, event_id)
    except NotFoundError:
        return RedirectResponse(url="/audit/events?error=not_found", status_code=303)
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


@router.post("/events/export")
def trigger_export(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    start_date: Annotated[str, Form(max_length=20)] = "",
    end_date: Annotated[str, Form(max_length=20)] = "",
):
    """Trigger event log XLSX export job with optional date range."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        parsed_start = date.fromisoformat(start_date) if start_date else None
        parsed_end = date.fromisoformat(end_date) if end_date else None
    except ValueError:
        return RedirectResponse(url="/audit/events?error=invalid_date", status_code=303)

    try:
        bg_tasks_service.create_export_task(
            requesting_user, start_date=parsed_start, end_date=parsed_end
        )
    except ValidationError:
        return RedirectResponse(url="/audit/events?error=invalid_date_range", status_code=303)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/account/background-jobs?success=export_started", status_code=303)
