"""Applications routes: index redirects, OAuth2/OIDC apps, B2B service accounts.

Named ``integrations.py`` for historical reasons -- this module covered
``/admin/integrations`` before the nav restructure (see
``.claude/ITERATION_nav_restructure.md``). Apps moved to
``/applications/oauth`` (renamed "OAuth2 / OIDC") and B2B clients moved to
``/applications/service-accounts`` (renamed "Service Accounts"); the old
``/admin/integrations`` container no longer exists. SAML service providers
live in ``routers.saml_idp.admin``; forward-auth (protected domains + proxy
apps, tabbed as "Domains" / "Apps" under Applications > Forward Auth) lives
in ``routers.protected_domains`` / ``routers.proxy_apps``. This module also
owns the ``/applications`` and ``/applications/forward-auth`` index
redirects since it is the closest thing the Applications section has to a
"home" module.
"""

import logging
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import get_first_accessible_child, has_page_access
from services import oauth2 as oauth2_service
from services.exceptions import ServiceError
from services.oidc import clients as oidc_client_service
from utils.redirects import safe_redirect
from utils.template_context import get_template_context
from utils.templates import templates
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

top_router = APIRouter(
    prefix="/applications",
    tags=["applications"],
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)

apps_router = APIRouter(
    prefix="/applications/oauth",
    tags=["applications-oauth"],
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)

b2b_router = APIRouter(
    prefix="/applications/service-accounts",
    tags=["applications-service-accounts"],
    dependencies=[Depends(require_admin)],
    include_in_schema=False,
)


@top_router.get("/", response_class=HTMLResponse)
def applications_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible Applications sub-page."""
    first_child = get_first_accessible_child("/applications", user.get("role"))
    return safe_redirect(first_child, default="/dashboard")


@top_router.get("/forward-auth/", response_class=HTMLResponse)
@top_router.get("/forward-auth", response_class=HTMLResponse)
def forward_auth_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible Forward Auth tab (Domains or Apps)."""
    first_child = get_first_accessible_child("/applications/forward-auth", user.get("role"))
    return safe_redirect(first_child, default="/dashboard")


@apps_router.get("", response_class=HTMLResponse)
def apps_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List normal OAuth2 clients (Apps)."""
    if not has_page_access("/applications/oauth", user.get("role")):
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


@apps_router.post("/create", response_class=HTMLResponse)
def apps_create(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: str = Form("", max_length=255),
    redirect_uris: str = Form("", max_length=20000),
    description: str = Form("", max_length=2000),
):
    """Create a new normal OAuth2 client (App)."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not name.strip():
        return RedirectResponse(url="/applications/oauth?error=name_required", status_code=303)

    # Parse redirect URIs from textarea (one per line)
    uri_list = [uri.strip() for uri in redirect_uris.strip().splitlines() if uri.strip()]

    if not uri_list:
        return RedirectResponse(
            url="/applications/oauth?error=redirect_uris_required", status_code=303
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

        return RedirectResponse(url="/applications/oauth?success=created", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to create OAuth2 app: %s", exc)
        return RedirectResponse(url="/applications/oauth?error=creation_failed", status_code=303)


@b2b_router.get("", response_class=HTMLResponse)
def b2b_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List B2B OAuth2 clients (Service Accounts)."""
    if not has_page_access("/applications/service-accounts", user.get("role")):
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


@b2b_router.post("/create", response_class=HTMLResponse)
def b2b_create(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: str = Form("", max_length=255),
    role: str = Form("", max_length=50),
    description: str = Form("", max_length=2000),
):
    """Create a new B2B OAuth2 client (Service Account)."""
    if not has_page_access("/applications/service-accounts", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not name.strip():
        return RedirectResponse(
            url="/applications/service-accounts?error=name_required", status_code=303
        )

    if role not in ("member", "admin", "super_admin"):
        return RedirectResponse(
            url="/applications/service-accounts?error=invalid_role", status_code=303
        )

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

        return RedirectResponse(
            url="/applications/service-accounts?success=created", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to create B2B client: %s", exc)
        return RedirectResponse(
            url="/applications/service-accounts?error=creation_failed", status_code=303
        )


# =============================================================================
# App Detail / Edit / Actions
# =============================================================================


@apps_router.get("/{client_id}", response_class=HTMLResponse)
def app_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """View/edit details for a normal OAuth2 client (App)."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "normal":
        return RedirectResponse(url="/applications/oauth?error=not_found", status_code=303)

    # Check for pending credentials in session (one-time read after regenerate)
    pending_credentials = request.session.pop("pending_credentials", None)

    # OIDC management context: discovery URLs and group access assignments.
    requesting_user = build_requesting_user(user, tenant_id, request)
    oidc_urls = oidc_client_service.get_client_discovery_info(
        requesting_user, client_id, tenant_base_url(request)
    )
    assigned_groups = oidc_client_service.list_client_group_assignments(
        requesting_user, client_id
    ).items
    available_groups = oidc_client_service.list_available_groups_for_client(
        requesting_user, client_id
    )

    context = get_template_context(
        request,
        tenant_id,
        client=client,
        oidc_urls=oidc_urls,
        assigned_groups=assigned_groups,
        available_groups=available_groups,
        pending_credentials=pending_credentials,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "integrations_app_detail.html", context)


@apps_router.post("/{client_id}/edit", response_class=HTMLResponse)
def app_edit(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    name: str = Form("", max_length=255),
    redirect_uris: str = Form("", max_length=20000),
    description: str = Form("", max_length=2000),
):
    """Update a normal OAuth2 client (App)."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/oauth/{client_id}"

    if not name.strip():
        return safe_redirect(f"{redirect_url}?error=name_required")

    # Parse redirect URIs from textarea (one per line)
    uri_list = [uri.strip() for uri in redirect_uris.strip().splitlines() if uri.strip()]

    if not uri_list:
        return safe_redirect(f"{redirect_url}?error=redirect_uris_required")

    existing = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not existing or existing["client_type"] != "normal":
        return RedirectResponse(url="/applications/oauth?error=not_found", status_code=303)

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
            return RedirectResponse(url="/applications/oauth?error=not_found", status_code=303)

        return safe_redirect(f"{redirect_url}?success=updated")
    except ServiceError as exc:
        logger.warning("Failed to update OAuth2 app: %s", exc)
        return safe_redirect(f"{redirect_url}?error=update_failed")


@apps_router.post("/{client_id}/regenerate-secret", response_class=HTMLResponse)
def app_regenerate_secret(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Regenerate the client secret for an App."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/oauth/{client_id}"

    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "normal":
        return RedirectResponse(url="/applications/oauth?error=not_found", status_code=303)

    new_secret = oauth2_service.regenerate_client_secret(tenant_id, client_id, str(user["id"]))

    # Store credentials in session for one-time display
    request.session["pending_credentials"] = {
        "client_id": client["client_id"],
        "client_secret": new_secret,
        "name": client["name"],
    }

    return safe_redirect(f"{redirect_url}?success=secret_regenerated")


@apps_router.post("/{client_id}/deactivate", response_class=HTMLResponse)
def app_deactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Deactivate an App (soft delete)."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/oauth/{client_id}"

    existing = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not existing or existing["client_type"] != "normal":
        return RedirectResponse(url="/applications/oauth?error=not_found", status_code=303)

    client = oauth2_service.deactivate_client(tenant_id, client_id, str(user["id"]))
    if not client:
        return RedirectResponse(url="/applications/oauth?error=not_found", status_code=303)

    return safe_redirect(f"{redirect_url}?success=deactivated")


@apps_router.post("/{client_id}/reactivate", response_class=HTMLResponse)
def app_reactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Reactivate a deactivated App."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/oauth/{client_id}"

    existing = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not existing or existing["client_type"] != "normal":
        return RedirectResponse(url="/applications/oauth?error=not_found", status_code=303)

    client = oauth2_service.reactivate_client(tenant_id, client_id, str(user["id"]))
    if not client:
        return RedirectResponse(url="/applications/oauth?error=not_found", status_code=303)

    return safe_redirect(f"{redirect_url}?success=reactivated")


# =============================================================================
# App OIDC settings and group access control
# =============================================================================


@apps_router.post("/{client_id}/oidc/toggle", response_class=HTMLResponse)
def app_toggle_oidc(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    oidc_enabled: Annotated[str, Form(max_length=50)] = "false",
):
    """Enable or disable OIDC (OpenID Provider) for an App."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/oauth/{client_id}"
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_client_service.set_oidc_settings(
            requesting_user, client_id, oidc_enabled=oidc_enabled == "true"
        )
        return safe_redirect(f"{redirect_url}?success=oidc_updated")
    except ServiceError as exc:
        logger.warning("Failed to toggle OIDC: %s", exc)
        return safe_redirect(f"{redirect_url}?error=oidc_update_failed")


@apps_router.post("/{client_id}/oidc/toggle-available-to-all", response_class=HTMLResponse)
def app_toggle_available_to_all(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    available_to_all: Annotated[str, Form(max_length=50)] = "false",
):
    """Toggle the 'available to all users' access mode for an OIDC App."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/oauth/{client_id}"
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_client_service.set_oidc_settings(
            requesting_user, client_id, available_to_all=available_to_all == "true"
        )
        return safe_redirect(f"{redirect_url}?success=oidc_updated")
    except ServiceError as exc:
        logger.warning("Failed to toggle available_to_all: %s", exc)
        return safe_redirect(f"{redirect_url}?error=oidc_update_failed")


@apps_router.post("/{client_id}/oidc/groups/add", response_class=HTMLResponse)
def app_add_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    group_id: Annotated[str, Form(max_length=50)] = "",
):
    """Assign a group to an OIDC App."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/oauth/{client_id}"

    if not group_id.strip():
        return safe_redirect(f"{redirect_url}?error=group_required")

    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_client_service.assign_client_to_group(requesting_user, client_id, group_id.strip())
        return safe_redirect(f"{redirect_url}?success=group_assigned")
    except ServiceError as exc:
        logger.warning("Failed to assign group to App: %s", exc)
        return safe_redirect(f"{redirect_url}?error=group_assign_failed")


@apps_router.post("/{client_id}/oidc/groups/{group_id}/remove", response_class=HTMLResponse)
def app_remove_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    group_id: str,
):
    """Remove a group assignment from an OIDC App."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/oauth/{client_id}"
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_client_service.remove_client_group_assignment(requesting_user, client_id, group_id)
        return safe_redirect(f"{redirect_url}?success=group_removed")
    except ServiceError as exc:
        logger.warning("Failed to remove group from App: %s", exc)
        return safe_redirect(f"{redirect_url}?error=group_remove_failed")


# =============================================================================
# B2B Detail / Edit / Actions
# =============================================================================


@b2b_router.get("/{client_id}", response_class=HTMLResponse)
def b2b_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """View/edit details for a B2B OAuth2 client."""
    if not has_page_access("/applications/service-accounts", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "b2b":
        return RedirectResponse(
            url="/applications/service-accounts?error=not_found", status_code=303
        )

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


@b2b_router.post("/{client_id}/edit", response_class=HTMLResponse)
def b2b_edit(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    name: str = Form("", max_length=255),
    description: str = Form("", max_length=2000),
):
    """Update a B2B OAuth2 client name/description."""
    if not has_page_access("/applications/service-accounts", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/service-accounts/{client_id}"

    if not name.strip():
        return safe_redirect(f"{redirect_url}?error=name_required")

    try:
        client = oauth2_service.update_client(
            tenant_id=tenant_id,
            client_id=client_id,
            actor_user_id=str(user["id"]),
            name=name.strip(),
            description=description.strip() or None,
        )

        if not client:
            return RedirectResponse(
                url="/applications/service-accounts?error=not_found", status_code=303
            )

        return safe_redirect(f"{redirect_url}?success=updated")
    except ServiceError as exc:
        logger.warning("Failed to update B2B client: %s", exc)
        return safe_redirect(f"{redirect_url}?error=update_failed")


@b2b_router.post("/{client_id}/role", response_class=HTMLResponse)
def b2b_change_role(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    role: str = Form("", max_length=50),
):
    """Change the service user role for a B2B client."""
    if not has_page_access("/applications/service-accounts", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/service-accounts/{client_id}"

    if role not in ("member", "admin", "super_admin"):
        return safe_redirect(f"{redirect_url}?error=invalid_role")

    try:
        client = oauth2_service.update_b2b_client_role(
            tenant_id=tenant_id,
            client_id=client_id,
            role=role,
            actor_user_id=str(user["id"]),
        )

        if not client:
            return RedirectResponse(
                url="/applications/service-accounts?error=not_found", status_code=303
            )

        return safe_redirect(f"{redirect_url}?success=role_changed")
    except ServiceError as exc:
        logger.warning("Failed to change B2B client role: %s", exc)
        return safe_redirect(f"{redirect_url}?error=role_change_failed")


@b2b_router.post("/{client_id}/regenerate-secret", response_class=HTMLResponse)
def b2b_regenerate_secret(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Regenerate the client secret for a B2B client."""
    if not has_page_access("/applications/service-accounts", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/service-accounts/{client_id}"

    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "b2b":
        return RedirectResponse(
            url="/applications/service-accounts?error=not_found", status_code=303
        )

    new_secret = oauth2_service.regenerate_client_secret(tenant_id, client_id, str(user["id"]))

    # Store credentials in session for one-time display
    request.session["pending_credentials"] = {
        "client_id": client["client_id"],
        "client_secret": new_secret,
        "name": client["name"],
    }

    return safe_redirect(f"{redirect_url}?success=secret_regenerated")


@b2b_router.post("/{client_id}/deactivate", response_class=HTMLResponse)
def b2b_deactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Deactivate a B2B client (soft delete)."""
    if not has_page_access("/applications/service-accounts", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/service-accounts/{client_id}"

    client = oauth2_service.deactivate_client(tenant_id, client_id, str(user["id"]))
    if not client:
        return RedirectResponse(
            url="/applications/service-accounts?error=not_found", status_code=303
        )

    return safe_redirect(f"{redirect_url}?success=deactivated")


@b2b_router.post("/{client_id}/reactivate", response_class=HTMLResponse)
def b2b_reactivate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
):
    """Reactivate a deactivated B2B client."""
    if not has_page_access("/applications/service-accounts", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/service-accounts/{client_id}"

    client = oauth2_service.reactivate_client(tenant_id, client_id, str(user["id"]))
    if not client:
        return RedirectResponse(
            url="/applications/service-accounts?error=not_found", status_code=303
        )

    return safe_redirect(f"{redirect_url}?success=reactivated")


# =============================================================================
# Combined router (mounted once in main.py)
# =============================================================================

router = APIRouter()
router.include_router(top_router)
router.include_router(apps_router)
router.include_router(b2b_router)
