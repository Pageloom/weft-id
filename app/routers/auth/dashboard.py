"""Dashboard endpoint."""

from typing import Annotated

import services.emails as emails_service
from dependencies import build_requesting_user, get_current_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from services import groups as groups_service
from services import service_providers as sp_service
from utils.templates import templates

router = APIRouter()


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Render dashboard for authenticated users."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Honour the forced-profile-completion gate. The dashboard does not
    # use require_current_user (it pre-dates that dependency style), so we
    # mirror the check inline.
    if user.get("force_profile_completion"):
        return RedirectResponse(url="/account/profile", status_code=303)

    # Fetch user's primary email for display
    from services import users as users_service
    from utils.template_context import get_template_context

    primary_email = emails_service.get_primary_email(tenant_id, user["id"])

    user["email"] = primary_email if primary_email else "N/A"

    # Fetch user's groups and accessible apps for the dashboard
    requesting_user = build_requesting_user(user, tenant_id, request)
    user_groups = groups_service.get_my_groups(requesting_user)
    user_apps = sp_service.get_user_accessible_apps(requesting_user)

    # Banner data: required+unlocked attributes the user is missing. Only
    # unlocked fields appear in the banner (locked-required-missing is an
    # admin-only Todo).
    missing_pairs = users_service.compute_missing_required(tenant_id, str(user["id"]))
    missing_required = [key for key, locked in missing_pairs if not locked]

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        get_template_context(
            request,
            tenant_id,
            user=user,
            user_groups=user_groups.items,
            user_apps=user_apps.items,
            missing_required=missing_required,
        ),
    )
