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
from pages import get_first_accessible_child, has_page_access
from services import oauth2 as oauth2_service
from services.exceptions import ServiceError
from utils.template_context import get_template_context
from utils.templates import templates

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/integrations",
    tags=["integrations"],
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)


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
    return templates.TemplateResponse(request, "integrations_apps.html", context)


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
    return templates.TemplateResponse(request, "integrations_b2b.html", context)


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


# =============================================================================
# App Detail / Edit / Actions
# =============================================================================


@router.get("/apps/{client_id}", response_class=HTMLResponse)
def app_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """View/edit details for a normal OAuth2 client (App)."""
    if not has_page_access("/admin/integrations/apps", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "normal":
        return RedirectResponse(url="/admin/integrations/apps?error=not_found", status_code=303)

    # Check for pending credentials in session (one-time read after regenerate)
    pending_credentials = request.session.pop("pending_credentials", None)

    context = get_template_context(
        request,
        tenant_id,
        client=client,
        pending_credentials=pending_credentials,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "integrations_app_detail.html", context)


@router.post("/apps/{client_id}/edit", response_class=HTMLResponse)
def app_edit(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    name: str = Form(""),
    redirect_uris: str = Form(""),
    description: str = Form(""),
):
    """Update a normal OAuth2 client (App)."""
    if not has_page_access("/admin/integrations/apps", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/admin/integrations/apps/{client_id}"

    if not name.strip():
        return RedirectResponse(url=f"{redirect_url}?error=name_required", status_code=303)

    # Parse redirect URIs from textarea (one per line)
    uri_list = [uri.strip() for uri in redirect_uris.strip().splitlines() if uri.strip()]

    if not uri_list:
        return RedirectResponse(url=f"{redirect_url}?error=redirect_uris_required", status_code=303)

    try:
        client = oauth2_service.update_client(
            tenant_id=tenant_id,
            client_id=client_id,
            actor_user_id=str(user["id"]),
            name=name.strip(),
            description=description.strip() or None,
            redirect_uris=uri_list,
        )

        if not client:
            return RedirectResponse(url="/admin/integrations/apps?error=not_found", status_code=303)

        return RedirectResponse(url=f"{redirect_url}?success=updated", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to update OAuth2 app: %s", exc)
        return RedirectResponse(url=f"{redirect_url}?error=update_failed", status_code=303)


@router.post("/apps/{client_id}/regenerate-secret", response_class=HTMLResponse)
def app_regenerate_secret(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Regenerate the client secret for an App."""
    if not has_page_access("/admin/integrations/apps", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/admin/integrations/apps/{client_id}"

    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "normal":
        return RedirectResponse(url="/admin/integrations/apps?error=not_found", status_code=303)

    new_secret = oauth2_service.regenerate_client_secret(tenant_id, client_id, str(user["id"]))

    # Store credentials in session for one-time display
    request.session["pending_credentials"] = {
        "client_id": client["client_id"],
        "client_secret": new_secret,
        "name": client["name"],
    }

    return RedirectResponse(url=f"{redirect_url}?success=secret_regenerated", status_code=303)


@router.post("/apps/{client_id}/deactivate", response_class=HTMLResponse)
def app_deactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Deactivate an App (soft delete)."""
    if not has_page_access("/admin/integrations/apps", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/admin/integrations/apps/{client_id}"

    client = oauth2_service.deactivate_client(tenant_id, client_id, str(user["id"]))
    if not client:
        return RedirectResponse(url="/admin/integrations/apps?error=not_found", status_code=303)

    return RedirectResponse(url=f"{redirect_url}?success=deactivated", status_code=303)


@router.post("/apps/{client_id}/reactivate", response_class=HTMLResponse)
def app_reactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Reactivate a deactivated App."""
    if not has_page_access("/admin/integrations/apps", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/admin/integrations/apps/{client_id}"

    client = oauth2_service.reactivate_client(tenant_id, client_id, str(user["id"]))
    if not client:
        return RedirectResponse(url="/admin/integrations/apps?error=not_found", status_code=303)

    return RedirectResponse(url=f"{redirect_url}?success=reactivated", status_code=303)


# =============================================================================
# B2B Detail / Edit / Actions
# =============================================================================


@router.get("/b2b/{client_id}", response_class=HTMLResponse)
def b2b_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """View/edit details for a B2B OAuth2 client."""
    if not has_page_access("/admin/integrations/b2b", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "b2b":
        return RedirectResponse(url="/admin/integrations/b2b?error=not_found", status_code=303)

    # Check for pending credentials in session (one-time read after regenerate)
    pending_credentials = request.session.pop("pending_credentials", None)

    context = get_template_context(
        request,
        tenant_id,
        client=client,
        pending_credentials=pending_credentials,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "integrations_b2b_detail.html", context)


@router.post("/b2b/{client_id}/edit", response_class=HTMLResponse)
def b2b_edit(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    name: str = Form(""),
    description: str = Form(""),
):
    """Update a B2B OAuth2 client name/description."""
    if not has_page_access("/admin/integrations/b2b", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/admin/integrations/b2b/{client_id}"

    if not name.strip():
        return RedirectResponse(url=f"{redirect_url}?error=name_required", status_code=303)

    try:
        client = oauth2_service.update_client(
            tenant_id=tenant_id,
            client_id=client_id,
            actor_user_id=str(user["id"]),
            name=name.strip(),
            description=description.strip() or None,
        )

        if not client:
            return RedirectResponse(url="/admin/integrations/b2b?error=not_found", status_code=303)

        return RedirectResponse(url=f"{redirect_url}?success=updated", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to update B2B client: %s", exc)
        return RedirectResponse(url=f"{redirect_url}?error=update_failed", status_code=303)


@router.post("/b2b/{client_id}/role", response_class=HTMLResponse)
def b2b_change_role(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    role: str = Form(""),
):
    """Change the service user role for a B2B client."""
    if not has_page_access("/admin/integrations/b2b", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/admin/integrations/b2b/{client_id}"

    if role not in ("member", "admin", "super_admin"):
        return RedirectResponse(url=f"{redirect_url}?error=invalid_role", status_code=303)

    try:
        client = oauth2_service.update_b2b_client_role(
            tenant_id=tenant_id,
            client_id=client_id,
            role=role,
            actor_user_id=str(user["id"]),
        )

        if not client:
            return RedirectResponse(url="/admin/integrations/b2b?error=not_found", status_code=303)

        return RedirectResponse(url=f"{redirect_url}?success=role_changed", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to change B2B client role: %s", exc)
        return RedirectResponse(url=f"{redirect_url}?error=role_change_failed", status_code=303)


@router.post("/b2b/{client_id}/regenerate-secret", response_class=HTMLResponse)
def b2b_regenerate_secret(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Regenerate the client secret for a B2B client."""
    if not has_page_access("/admin/integrations/b2b", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/admin/integrations/b2b/{client_id}"

    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "b2b":
        return RedirectResponse(url="/admin/integrations/b2b?error=not_found", status_code=303)

    new_secret = oauth2_service.regenerate_client_secret(tenant_id, client_id, str(user["id"]))

    # Store credentials in session for one-time display
    request.session["pending_credentials"] = {
        "client_id": client["client_id"],
        "client_secret": new_secret,
        "name": client["name"],
    }

    return RedirectResponse(url=f"{redirect_url}?success=secret_regenerated", status_code=303)


@router.post("/b2b/{client_id}/deactivate", response_class=HTMLResponse)
def b2b_deactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Deactivate a B2B client (soft delete)."""
    if not has_page_access("/admin/integrations/b2b", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/admin/integrations/b2b/{client_id}"

    client = oauth2_service.deactivate_client(tenant_id, client_id, str(user["id"]))
    if not client:
        return RedirectResponse(url="/admin/integrations/b2b?error=not_found", status_code=303)

    return RedirectResponse(url=f"{redirect_url}?success=deactivated", status_code=303)


@router.post("/b2b/{client_id}/reactivate", response_class=HTMLResponse)
def b2b_reactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Reactivate a deactivated B2B client."""
    if not has_page_access("/admin/integrations/b2b", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/admin/integrations/b2b/{client_id}"

    client = oauth2_service.reactivate_client(tenant_id, client_id, str(user["id"]))
    if not client:
        return RedirectResponse(url="/admin/integrations/b2b?error=not_found", status_code=303)

    return RedirectResponse(url=f"{redirect_url}?success=reactivated", status_code=303)
