"""Settings routes (about, index redirect).

Narrowed to Branding and About as part of the nav restructure -- Security
moved to ``routers.security`` (``/security``) and Privileged Domains (now
"Domain Routing") moved to ``routers.identity_providers`` -- see
``.claude/ITERATION_nav_restructure.md``. Branding itself lives in
``routers.settings_branding``.
"""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from pages import get_first_accessible_child
from services.activity import track_activity
from utils.redirects import safe_redirect
from utils.template_context import get_template_context
from utils.templates import templates
from version import __version__

router = APIRouter(
    prefix="/settings",
    tags=["settings"],
    dependencies=[Depends(require_admin)],  # All routes require admin role
    include_in_schema=False,
)


@router.get("/", response_class=HTMLResponse)
@router.get("", response_class=HTMLResponse)
def settings_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible settings page."""
    first_child = get_first_accessible_child("/settings", user.get("role"))

    return safe_redirect(first_child, default="/dashboard")


@router.get("/about", response_class=HTMLResponse)
def settings_about(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display the About WeftID page with version and documentation links."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    return templates.TemplateResponse(
        request,
        "settings_about.html",
        get_template_context(request, tenant_id, version=__version__),
    )
