"""Bulk operations routes for user management."""

import json
import logging
from datetime import date
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError as PydanticValidationError
from schemas.api import BulkChangePrimaryEmailApplyRequest
from services import bg_tasks as bg_tasks_service
from services import emails as emails_service
from services.exceptions import ServiceError
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/users",
    tags=["users-bulk-ops"],
    include_in_schema=False,
)


def _parse_filter_criteria(criteria_json: str) -> dict:
    """Parse filter criteria JSON from the user list page.

    Returns a dict with keys matching the service filter parameters.
    """
    try:
        raw = json.loads(criteria_json)
    except (json.JSONDecodeError, TypeError):
        return {}

    result: dict = {}

    if raw.get("roles"):
        val = raw["roles"]
        negate = isinstance(val, str) and val.startswith("!")
        if negate:
            val = val[1:]
        allowed = {"member", "admin", "super_admin"}
        roles = [r for r in val.split(",") if r in allowed] if isinstance(val, str) else val
        result["roles"] = roles or None
        if negate and result["roles"]:
            result["role_negate"] = True
    if raw.get("statuses"):
        val = raw["statuses"]
        negate = isinstance(val, str) and val.startswith("!")
        if negate:
            val = val[1:]
        allowed_s = {"active", "inactivated", "anonymized"}
        statuses = [s for s in val.split(",") if s in allowed_s] if isinstance(val, str) else val
        result["statuses"] = statuses or None
        if negate and result["statuses"]:
            result["status_negate"] = True
    if raw.get("auth_methods"):
        val = raw["auth_methods"]
        negate = isinstance(val, str) and val.startswith("!")
        if negate:
            val = val[1:]
        result["auth_methods"] = val.split(",") if isinstance(val, str) else val
        if negate and result["auth_methods"]:
            result["auth_method_negate"] = True
    if raw.get("domain"):
        val = raw["domain"]
        if val.startswith("!"):
            result["domain"] = val[1:]
            result["domain_negate"] = True
        else:
            result["domain"] = val
    if raw.get("group_id"):
        val = raw["group_id"]
        if val.startswith("!"):
            result["group_id"] = val[1:]
            result["group_negate"] = True
        else:
            result["group_id"] = val
    if raw.get("group_children") == "0":
        result["group_include_children"] = False
    if raw.get("has_secondary_email"):
        val = raw["has_secondary_email"]
        if val == "yes":
            result["has_secondary_email"] = True
        elif val == "no":
            result["has_secondary_email"] = False
    if raw.get("activity_start"):
        try:
            result["activity_start"] = date.fromisoformat(raw["activity_start"])
        except ValueError:
            pass
    if raw.get("activity_end"):
        try:
            result["activity_end"] = date.fromisoformat(raw["activity_end"])
        except ValueError:
            pass

    return result


def _resolve_user_ids(
    tenant_id: str,
    selection_mode: str,
    user_ids: list[str] | None,
    filter_criteria: str | None,
    search: str | None,
) -> list[str]:
    """Resolve selection into a list of user IDs.

    For 'ids' mode, returns the provided IDs directly.
    For 'filter' mode, queries via the service layer with filter criteria.
    """
    if selection_mode == "filter" and filter_criteria:
        filters = _parse_filter_criteria(filter_criteria)
        return emails_service.resolve_users_from_filter(tenant_id, search=search, **filters)

    return user_ids or []


@router.post("/bulk-ops/secondary-emails/prepare", response_class=HTMLResponse)
def prepare_bulk_secondary_emails(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin)],
    selection_mode: Annotated[str, Form()],
    user_ids: Annotated[list[str] | None, Form()] = None,
    filter_criteria: Annotated[str | None, Form()] = None,
    search: Annotated[str | None, Form()] = None,
):
    """Receive selection from user list and render the bulk email action page."""
    resolved_ids = _resolve_user_ids(tenant_id, selection_mode, user_ids, filter_criteria, search)

    if not resolved_ids:
        return RedirectResponse(
            url="/users/list?error=no_users_selected",
            status_code=303,
        )

    # Fetch user records with primary emails and their secondaries
    users, secondary_emails_by_user = emails_service.list_users_by_ids_with_emails(
        tenant_id, resolved_ids
    )

    if not users:
        return RedirectResponse(
            url="/users/list?error=no_users_found",
            status_code=303,
        )

    context = get_template_context(request, tenant_id)
    context["users"] = users
    context["secondary_emails_by_user"] = secondary_emails_by_user
    context["user_count"] = len(users)

    return templates.TemplateResponse(
        request,
        "users_bulk_secondary_emails.html",
        context,
    )


@router.post("/bulk-ops/secondary-emails")
def submit_bulk_secondary_emails(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin)],
    user_ids: Annotated[list[str], Form()],
    emails: Annotated[list[str], Form()],
):
    """Process the bulk email form submission and create a background job."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Build items list from parallel arrays, filtering out blank emails
    items = []
    for uid, email in zip(user_ids, emails):
        email = email.strip()
        if email:
            items.append({"user_id": uid, "email": email})

    if not items:
        return RedirectResponse(
            url="/users/list?error=no_emails_provided",
            status_code=303,
        )

    try:
        bg_tasks_service.create_bulk_add_emails_task(requesting_user, items)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/account/background-jobs?success=bulk_emails_started",
        status_code=303,
    )


# =============================================================================
# Bulk Change Primary Email
# =============================================================================


@router.post("/bulk-ops/primary-emails/prepare", response_class=HTMLResponse)
def prepare_bulk_primary_emails(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin)],
    selection_mode: Annotated[str, Form()],
    user_ids: Annotated[list[str] | None, Form()] = None,
    filter_criteria: Annotated[str | None, Form()] = None,
    search: Annotated[str | None, Form()] = None,
):
    """Receive selection from user list and render the bulk primary email page."""
    resolved_ids = _resolve_user_ids(tenant_id, selection_mode, user_ids, filter_criteria, search)

    if not resolved_ids:
        return RedirectResponse(
            url="/users/list?error=no_users_selected",
            status_code=303,
        )

    # Fetch user records with primary and secondary emails
    users, secondary_emails_by_user = emails_service.list_users_by_ids_with_emails(
        tenant_id, resolved_ids
    )

    if not users:
        return RedirectResponse(
            url="/users/list?error=no_users_found",
            status_code=303,
        )

    context = get_template_context(request, tenant_id)
    context["users"] = users
    context["secondary_emails_by_user"] = secondary_emails_by_user
    context["user_count"] = len(users)

    return templates.TemplateResponse(
        request,
        "users_bulk_primary_emails.html",
        context,
    )


@router.post("/bulk-ops/primary-emails/preview")
def preview_bulk_primary_emails(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin)],
    user_ids: Annotated[list[str], Form()],
    new_emails: Annotated[list[str], Form()],
):
    """Enqueue a dry-run background job for bulk primary email changes.

    Returns JSON with task_id (page stays in place and polls).
    """
    from fastapi.responses import JSONResponse

    requesting_user = build_requesting_user(user, tenant_id, request)

    # Build items from parallel arrays, filtering out "No change" entries
    items = []
    for uid, email in zip(user_ids, new_emails):
        email = email.strip()
        if email:
            items.append({"user_id": uid, "new_primary_email": email})

    if not items:
        return JSONResponse({"error": "No email changes specified"}, status_code=400)

    try:
        result = bg_tasks_service.create_bulk_primary_email_preview_task(requesting_user, items)
        if result:
            return JSONResponse(
                {
                    "task_id": str(result["id"]),
                    "created_at": result["created_at"].isoformat(),
                }
            )
        return JSONResponse({"error": "Failed to create task"}, status_code=500)
    except ServiceError as exc:
        return JSONResponse({"error": exc.message}, status_code=400)


@router.post("/bulk-ops/primary-emails/apply")
def apply_bulk_primary_emails(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin)],
    items_json: Annotated[str, Form()],
    preview_job_id: Annotated[str, Form()],
):
    """Enqueue execution background job for bulk primary email changes.

    Returns JSON with task_id (page stays in place and polls).
    """
    from fastapi.responses import JSONResponse

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        raw_items = json.loads(items_json)
    except (json.JSONDecodeError, TypeError):
        return JSONResponse({"error": "Invalid items data"}, status_code=400)

    if not raw_items:
        return JSONResponse({"error": "No items specified"}, status_code=400)

    try:
        validated = BulkChangePrimaryEmailApplyRequest(
            items=raw_items,
            preview_job_id=preview_job_id,
        )
    except PydanticValidationError:
        return JSONResponse({"error": "Invalid request data"}, status_code=400)

    items = [
        {
            "user_id": item.user_id,
            "new_primary_email": item.new_primary_email,
            "idp_disposition": item.idp_disposition,
        }
        for item in validated.items
    ]

    try:
        result = bg_tasks_service.create_bulk_primary_email_apply_task(
            requesting_user, items, validated.preview_job_id
        )
        if result:
            return JSONResponse(
                {
                    "task_id": str(result["id"]),
                    "created_at": result["created_at"].isoformat(),
                }
            )
        return JSONResponse({"error": "Failed to create task"}, status_code=500)
    except ServiceError as exc:
        return JSONResponse({"error": exc.message}, status_code=400)


@router.post("/bulk-ops/inactivate")
def submit_bulk_inactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin)],
    selection_mode: Annotated[str, Form()],
    user_ids: Annotated[list[str] | None, Form()] = None,
    filter_criteria: Annotated[str | None, Form()] = None,
    search: Annotated[str | None, Form()] = None,
):
    """Create a background job to inactivate selected users."""
    resolved_ids = _resolve_user_ids(tenant_id, selection_mode, user_ids, filter_criteria, search)

    if not resolved_ids:
        return RedirectResponse(
            url="/users/list?error=no_users_selected",
            status_code=303,
        )

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        bg_tasks_service.create_bulk_inactivate_task(requesting_user, resolved_ids)
    except ServiceError:
        logger.exception("Failed to create bulk inactivate task")
        return RedirectResponse(
            url="/users/list?error=bulk_operation_failed",
            status_code=303,
        )

    return RedirectResponse(
        url="/account/background-jobs?success=bulk_inactivate_started",
        status_code=303,
    )


@router.post("/bulk-ops/reactivate")
def submit_bulk_reactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin)],
    selection_mode: Annotated[str, Form()],
    user_ids: Annotated[list[str] | None, Form()] = None,
    filter_criteria: Annotated[str | None, Form()] = None,
    search: Annotated[str | None, Form()] = None,
):
    """Create a background job to reactivate selected users."""
    resolved_ids = _resolve_user_ids(tenant_id, selection_mode, user_ids, filter_criteria, search)

    if not resolved_ids:
        return RedirectResponse(
            url="/users/list?error=no_users_selected",
            status_code=303,
        )

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        bg_tasks_service.create_bulk_reactivate_task(requesting_user, resolved_ids)
    except ServiceError:
        logger.exception("Failed to create bulk reactivate task")
        return RedirectResponse(
            url="/users/list?error=bulk_operation_failed",
            status_code=303,
        )

    return RedirectResponse(
        url="/account/background-jobs?success=bulk_reactivate_started",
        status_code=303,
    )


@router.post("/bulk-ops/group-assignment")
def submit_bulk_group_assignment(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_admin)],
    group_id: Annotated[str, Form()],
    selection_mode: Annotated[str, Form()],
    user_ids: Annotated[list[str] | None, Form()] = None,
    filter_criteria: Annotated[str | None, Form()] = None,
    search: Annotated[str | None, Form()] = None,
):
    """Create a background job to add selected users to a group."""
    resolved_ids = _resolve_user_ids(tenant_id, selection_mode, user_ids, filter_criteria, search)

    if not resolved_ids:
        return RedirectResponse(
            url="/users/list?error=no_users_selected",
            status_code=303,
        )

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        bg_tasks_service.create_bulk_group_assignment_task(requesting_user, group_id, resolved_ids)
    except ServiceError:
        logger.exception("Failed to create bulk group assignment task")
        return RedirectResponse(
            url="/users/list?error=bulk_operation_failed",
            status_code=303,
        )

    return RedirectResponse(
        url="/account/background-jobs?success=bulk_group_assignment_started",
        status_code=303,
    )
