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
from schemas.oauth2 import InitialAccessTokenCreate, RegistrationSettingsUpdate
from services import oauth2 as oauth2_service
from services import oauth2_registration as registration_service
from services import oauth2_tokens as oauth2_tokens_service
from services.exceptions import ServiceError
from services.oidc import backchannel as backchannel_service
from services.oidc import clients as oidc_client_service
from services.oidc import consent as consent_service
from services.oidc.discovery import build_discovery_metadata
from utils.redirects import safe_redirect
from utils.template_context import get_template_context
from utils.templates import templates
from utils.urls import tenant_base_url

logger = logging.getLogger(__name__)

# Most recent back-channel logout deliveries listed on the App detail page
# (the API pages through the rest).
BACKCHANNEL_DELIVERIES_SHOWN = 20

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

registration_router = APIRouter(
    prefix="/applications/client-registration",
    tags=["applications-client-registration"],
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
@top_router.get("", response_class=HTMLResponse)
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
    consent_grants = consent_service.list_client_grants(requesting_user, client_id)
    backchannel_deliveries = backchannel_service.list_backchannel_logout_deliveries(
        requesting_user, client_id, limit=BACKCHANNEL_DELIVERIES_SHOWN
    )

    context = get_template_context(
        request,
        tenant_id,
        client=client,
        oidc_urls=oidc_urls,
        introspection_endpoint=oidc_urls.introspection_endpoint,
        assigned_groups=assigned_groups,
        available_groups=available_groups,
        consent_grants=consent_grants,
        backchannel_deliveries=backchannel_deliveries,
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
    post_logout_redirect_uris: str = Form("", max_length=20000),
    frontchannel_logout_uri: str = Form("", max_length=2048),
    frontchannel_logout_session_required: str = Form("", max_length=10),
    backchannel_logout_uri: str = Form("", max_length=2048),
    backchannel_logout_session_required: str = Form("", max_length=10),
    initiate_login_uri: str = Form("", max_length=2048),
    device_grant_enabled: str = Form("", max_length=10),
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
            post_logout_redirect_uris=post_logout_redirect_uris.splitlines(),
            frontchannel_logout_uri=frontchannel_logout_uri.strip(),
            frontchannel_logout_session_required=frontchannel_logout_session_required == "true",
            backchannel_logout_uri=backchannel_logout_uri.strip(),
            backchannel_logout_session_required=backchannel_logout_session_required == "true",
            initiate_login_uri=initiate_login_uri.strip(),
            device_grant_enabled=device_grant_enabled == "true",
        )

        if not client:
            return RedirectResponse(url="/applications/oauth?error=not_found", status_code=303)

        return safe_redirect(f"{redirect_url}?success=updated")
    except ServiceError as exc:
        if exc.code == "invalid_post_logout_redirect_uri":
            return safe_redirect(f"{redirect_url}?error=invalid_post_logout_redirect_uri")
        if exc.code == "invalid_frontchannel_logout_uri":
            return safe_redirect(f"{redirect_url}?error=invalid_frontchannel_logout_uri")
        if exc.code == "invalid_backchannel_logout_uri":
            return safe_redirect(f"{redirect_url}?error=invalid_backchannel_logout_uri")
        if exc.code == "invalid_initiate_login_uri":
            return safe_redirect(f"{redirect_url}?error=invalid_initiate_login_uri")
        logger.warning("Failed to update OAuth2 app: %s", exc)
        return safe_redirect(f"{redirect_url}?error=update_failed")


def _set_introspection(
    request: Request,
    tenant_id: str,
    user: dict,
    client_id: str,
    enabled: str,
    redirect_url: str,
) -> RedirectResponse:
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        oauth2_tokens_service.set_tenant_introspection(
            requesting_user, client_id, enabled == "true"
        )
        return safe_redirect(f"{redirect_url}?success=introspection_updated")
    except ServiceError as exc:
        logger.warning("Failed to update token introspection: %s", exc)
        return safe_redirect(f"{redirect_url}?error=introspection_update_failed")


@apps_router.post("/{client_id}/introspection", response_class=HTMLResponse)
def app_set_introspection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    enabled: Annotated[str, Form(max_length=10)] = "false",
):
    """Allow or stop an App introspecting every token in the tenant."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    return _set_introspection(
        request, tenant_id, user, client_id, enabled, f"/applications/oauth/{client_id}"
    )


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


@apps_router.post("/{client_id}/consents/{grant_id}/revoke", response_class=HTMLResponse)
def app_revoke_consent(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    grant_id: str,
):
    """Revoke one user's remembered consent for an App."""
    if not has_page_access("/applications/oauth", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    redirect_url = f"/applications/oauth/{client_id}"
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        consent_service.revoke_client_grant(requesting_user, client_id, grant_id)
        return safe_redirect(f"{redirect_url}?success=consent_revoked")
    except ServiceError as exc:
        logger.warning("Failed to revoke consent for App: %s", exc)
        return safe_redirect(f"{redirect_url}?error=consent_revoke_failed")


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
        introspection_endpoint=build_discovery_metadata(
            tenant_base_url(request)
        ).introspection_endpoint,
        pending_credentials=pending_credentials,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "integrations_b2b_detail.html", context)


@b2b_router.post("/{client_id}/introspection", response_class=HTMLResponse)
def b2b_set_introspection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    client_id: str,
    enabled: Annotated[str, Form(max_length=10)] = "false",
):
    """Allow or stop a B2B client introspecting every token in the tenant."""
    if not has_page_access("/applications/service-accounts", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    return _set_introspection(
        request, tenant_id, user, client_id, enabled, f"/applications/service-accounts/{client_id}"
    )


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
# Client Registration (RFC 7591 policy and initial access tokens)
# =============================================================================

_REGISTRATION_PAGE = "/applications/client-registration"


@registration_router.get("", response_class=HTMLResponse)
def client_registration_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Dynamic client registration settings and initial access tokens."""
    if not has_page_access(_REGISTRATION_PAGE, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    settings = registration_service.get_registration_settings(
        requesting_user, tenant_base_url(request)
    )
    tokens = registration_service.list_initial_access_tokens(requesting_user)

    context = get_template_context(
        request,
        tenant_id,
        settings=settings,
        tokens=tokens,
        registration_endpoint=registration_service.registration_endpoint_url(
            tenant_base_url(request)
        ),
        pending_token=request.session.pop("pending_initial_access_token", None),
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "integrations_client_registration.html", context)


@registration_router.post("/settings", response_class=HTMLResponse)
def client_registration_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    policy: str = Form("", max_length=50),
    default_access: str = Form("", max_length=50),
):
    """Save the registration policy and default access for registered clients."""
    if not has_page_access(_REGISTRATION_PAGE, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        update = RegistrationSettingsUpdate(policy=policy, default_access=default_access)
    except ValueError:
        return RedirectResponse(
            url="/applications/client-registration?error=invalid_settings", status_code=303
        )

    registration_service.update_registration_settings(
        build_requesting_user(user, tenant_id, request), update, tenant_base_url(request)
    )
    return RedirectResponse(
        url="/applications/client-registration?success=settings_saved", status_code=303
    )


@registration_router.post("/tokens", response_class=HTMLResponse)
def client_registration_create_token(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: str = Form("", max_length=255),
    expires_in_days: str = Form("", max_length=10),
):
    """Issue an initial access token and show its value once."""
    if not has_page_access(_REGISTRATION_PAGE, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not name.strip():
        return RedirectResponse(
            url="/applications/client-registration?error=name_required", status_code=303
        )
    try:
        data = InitialAccessTokenCreate(
            name=name.strip(),
            expires_in_days=int(expires_in_days) if expires_in_days.strip() else None,
        )
    except ValueError:
        return RedirectResponse(
            url="/applications/client-registration?error=invalid_expiry", status_code=303
        )

    created = registration_service.create_initial_access_token(
        build_requesting_user(user, tenant_id, request), data
    )
    request.session["pending_initial_access_token"] = {"name": created.name, "token": created.token}
    return RedirectResponse(
        url="/applications/client-registration?success=token_created", status_code=303
    )


@registration_router.post("/tokens/{token_id}/revoke", response_class=HTMLResponse)
def client_registration_revoke_token(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    token_id: str,
):
    """Revoke an initial access token."""
    if not has_page_access(_REGISTRATION_PAGE, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        registration_service.revoke_initial_access_token(
            build_requesting_user(user, tenant_id, request), token_id
        )
    except ServiceError:
        return RedirectResponse(
            url="/applications/client-registration?error=token_not_found", status_code=303
        )
    return RedirectResponse(
        url="/applications/client-registration?success=token_revoked", status_code=303
    )


# =============================================================================
# Combined router (mounted once in main.py)
# =============================================================================

router = APIRouter()
router.include_router(top_router)
router.include_router(apps_router)
router.include_router(b2b_router)
router.include_router(registration_router)
