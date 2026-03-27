"""Bulk user attribute update page route."""

from typing import Annotated

from dependencies import get_current_user, get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import has_page_access
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_current_user)],
    include_in_schema=False,
)


@router.get("/bulk-update", response_class=HTMLResponse)
def bulk_update_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Render the bulk user attribute update page."""
    if not has_page_access("/users/bulk-update", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    context = get_template_context(request, tenant_id)
    return templates.TemplateResponse(request, "users_bulk_update.html", context)
