"""Dashboard endpoint."""

from typing import Annotated

import services.emails as emails_service
from dependencies import get_current_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]):
    """Render dashboard for authenticated users."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Fetch user's primary email for display
    from utils.template_context import get_template_context

    primary_email = emails_service.get_primary_email(tenant_id, user["id"])

    user["email"] = primary_email if primary_email else "N/A"

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        get_template_context(request, tenant_id, user=user),
    )
