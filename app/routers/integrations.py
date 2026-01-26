"""Integration management routes for OAuth2 clients (Apps and B2B)."""

import logging
from typing import Annotated

from dependencies import (
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child, has_page_access
from services import oauth2 as oauth2_service
from services.exceptions import ServiceError
from utils.template_context import get_template_context

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/integrations",
    tags=["integrations"],
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
def integrations_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible integrations sub-page."""
    first_child = get_first_accessible_child("/admin/integrations", user.get("role"))
    if first_child:
        return RedirectResponse(url=first_child, status_code=303)
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/apps", response_class=HTMLResponse)
def apps_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List normal OAuth2 clients (Apps)."""
    if not has_page_access("/admin/integrations/apps", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    clients = oauth2_service.get_all_clients(tenant_id, client_type="normal")

    # Check for pending credentials in session (one-time read)
    pending_credentials = request.session.pop("pending_credentials", None)

    context = get_template_context(
        request,
        tenant_id,
        clients=clients,
        pending_credentials=pending_credentials,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("integrations_apps.html", context)


@router.post("/apps/create", response_class=HTMLResponse)
def apps_create(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: str = Form(""),
    redirect_uris: str = Form(""),
    description: str = Form(""),
):
    """Create a new normal OAuth2 client (App)."""
    if not has_page_access("/admin/integrations/apps", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not name.strip():
        return RedirectResponse(url="/admin/integrations/apps?error=name_required", status_code=303)

    # Parse redirect URIs from textarea (one per line)
    uri_list = [uri.strip() for uri in redirect_uris.strip().splitlines() if uri.strip()]

    if not uri_list:
        return RedirectResponse(
            url="/admin/integrations/apps?error=redirect_uris_required", status_code=303
        )

    try:
        client = oauth2_service.create_normal_client(
            tenant_id=tenant_id,
            name=name.strip(),
            redirect_uris=uri_list,
            created_by=str(user["id"]),
            description=description.strip() or None,
        )

        # Store credentials in session for one-time display
        request.session["pending_credentials"] = {
            "client_id": client["client_id"],
            "client_secret": client["client_secret"],
            "name": client["name"],
        }

        return RedirectResponse(url="/admin/integrations/apps?success=created", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to create OAuth2 app: %s", exc)
        return RedirectResponse(
            url="/admin/integrations/apps?error=creation_failed", status_code=303
        )


@router.get("/b2b", response_class=HTMLResponse)
def b2b_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List B2B OAuth2 clients (Service Accounts)."""
    if not has_page_access("/admin/integrations/b2b", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    clients = oauth2_service.get_all_clients(tenant_id, client_type="b2b")

    # Check for pending credentials in session (one-time read)
    pending_credentials = request.session.pop("pending_credentials", None)

    context = get_template_context(
        request,
        tenant_id,
        clients=clients,
        pending_credentials=pending_credentials,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("integrations_b2b.html", context)


@router.post("/b2b/create", response_class=HTMLResponse)
def b2b_create(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: str = Form(""),
    role: str = Form(""),
    description: str = Form(""),
):
    """Create a new B2B OAuth2 client (Service Account)."""
    if not has_page_access("/admin/integrations/b2b", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not name.strip():
        return RedirectResponse(url="/admin/integrations/b2b?error=name_required", status_code=303)

    if role not in ("member", "admin", "super_admin"):
        return RedirectResponse(url="/admin/integrations/b2b?error=invalid_role", status_code=303)

    try:
        client = oauth2_service.create_b2b_client(
            tenant_id=tenant_id,
            name=name.strip(),
            role=role,
            created_by=str(user["id"]),
            description=description.strip() or None,
        )

        # Store credentials in session for one-time display
        request.session["pending_credentials"] = {
            "client_id": client["client_id"],
            "client_secret": client["client_secret"],
            "name": client["name"],
        }

        return RedirectResponse(url="/admin/integrations/b2b?success=created", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to create B2B client: %s", exc)
        return RedirectResponse(
            url="/admin/integrations/b2b?error=creation_failed", status_code=303
        )
