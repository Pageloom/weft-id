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
        allowed = {"member", "admin", "super_admin"}
        result["roles"] = [r for r in raw["roles"] if r in allowed] or None
    if raw.get("statuses"):
        allowed_s = {"active", "inactivated", "anonymized"}
        result["statuses"] = [s for s in raw["statuses"] if s in allowed_s] or None
    if raw.get("auth_methods"):
        result["auth_methods"] = raw["auth_methods"] or None
    if raw.get("domain"):
        result["domain"] = raw["domain"]
    if raw.get("group_id"):
        result["group_id"] = raw["group_id"]
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
