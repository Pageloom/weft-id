"""Identity Providers routes: index redirect and Domain Routing.

Domain Routing (formerly Privileged Domains) manages which email domains
route new users through the platform's own auth vs. federate to a specific
SAML IdP or OIDC connection. Moved here from
``/admin/settings/privileged-domains`` as part of the nav restructure (see
``.claude/ITERATION_nav_restructure.md``); the SAML and OIDC identity
provider CRUD routes themselves stay in ``routers.saml.admin`` and
``routers.oidc_upstream.admin`` (only their paths moved to
``/identity-providers/saml*`` and ``/identity-providers/oidc*``).
"""

from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import get_first_accessible_child
from schemas.settings import DomainGroupLinkCreate, PrivilegedDomainCreate
from services import groups as groups_service
from services import oidc_upstream as oidc_service
from services import saml as saml_service
from services import settings as settings_service
from services.exceptions import ServiceError
from utils.redirects import safe_redirect
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/identity-providers",
    tags=["identity-providers"],
    dependencies=[Depends(require_admin)],  # Baseline: every route requires admin role
    include_in_schema=False,
)


@router.get("/", response_class=HTMLResponse)
@router.get("", response_class=HTMLResponse)
def identity_providers_index(
    request: Request,
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible identity providers page."""
    first_child = get_first_accessible_child("/identity-providers", user.get("role"))

    return safe_redirect(first_child, default="/dashboard")


# =============================================================================
# Domain Routing (formerly Privileged Domains)
# =============================================================================


@router.get("/domain-routing", response_class=HTMLResponse)
def privileged_domains(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display and manage privileged domains for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        domains = settings_service.list_privileged_domains(requesting_user)
        # Get IdPs for binding dropdown (super_admin only). Both SAML IdPs and
        # OIDC connections are binding targets; the template groups them by
        # protocol.
        idps = []
        oidc_connections = []
        if user.get("role") == "super_admin":
            idps = saml_service.list_identity_providers(requesting_user).items
            oidc_connections = oidc_service.list_connections(requesting_user).items
        # Get WeftID groups for link dropdown
        weftid_groups = groups_service.list_groups(
            requesting_user, group_type="weftid", page_size=500
        ).items
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    error = request.query_params.get("error")
    success = request.query_params.get("success")

    return templates.TemplateResponse(
        request,
        "settings_privileged_domains.html",
        get_template_context(
            request,
            tenant_id,
            domains=domains,
            idps=idps,
            oidc_connections=oidc_connections,
            weftid_groups=weftid_groups,
            error=error,
            success=success,
        ),
    )


@router.post("/domain-routing/add")
def add_privileged_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain: Annotated[str, Form(max_length=253)],
):
    """Add a new privileged domain."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    domain_data = PrivilegedDomainCreate(domain=domain)

    try:
        settings_service.add_privileged_domain(requesting_user, domain_data)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/identity-providers/domain-routing", status_code=303)


@router.post("/domain-routing/delete/{domain_id}")
def delete_privileged_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
):
    """Delete a privileged domain."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        settings_service.delete_privileged_domain(requesting_user, domain_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/identity-providers/domain-routing", status_code=303)


@router.post("/domain-routing/{domain_id}/link-group")
def link_group_to_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
    group_id: Annotated[str, Form(max_length=50)],
):
    """Link a group to a privileged domain for auto-assignment."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    link_data = DomainGroupLinkCreate(group_id=group_id)

    try:
        settings_service.add_domain_group_link(requesting_user, domain_id, link_data)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/identity-providers/domain-routing?success=group_linked",
        status_code=303,
    )


@router.post("/domain-routing/{domain_id}/unlink-group/{link_id}")
def unlink_group_from_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
    link_id: str,
):
    """Unlink a group from a privileged domain."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        settings_service.delete_domain_group_link(requesting_user, domain_id, link_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/identity-providers/domain-routing?success=group_unlinked",
        status_code=303,
    )


@router.post(
    "/domain-routing/{domain_id}/bind",
    dependencies=[Depends(require_super_admin)],
)
def bind_domain_to_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
    idp_id: Annotated[str, Form(max_length=50)],
):
    """Bind a privileged domain to an IdP (super_admin only)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.bind_domain_to_idp(
            requesting_user=requesting_user,
            idp_id=idp_id,
            domain_id=domain_id,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/identity-providers/domain-routing?success=domain_bound",
        status_code=303,
    )


@router.post(
    "/domain-routing/{domain_id}/unbind",
    dependencies=[Depends(require_super_admin)],
)
def unbind_domain_from_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
):
    """Unbind a privileged domain from its IdP (super_admin only)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.unbind_domain_from_idp(
            requesting_user=requesting_user,
            domain_id=domain_id,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/identity-providers/domain-routing?success=domain_unbound",
        status_code=303,
    )


@router.post(
    "/domain-routing/{domain_id}/bind-oidc",
    dependencies=[Depends(require_super_admin)],
)
def bind_domain_to_oidc_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
    connection_id: Annotated[str, Form(max_length=50)],
):
    """Bind a privileged domain to an OIDC connection (super_admin only)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_service.bind_domain_to_connection(
            requesting_user=requesting_user,
            connection_id=connection_id,
            domain_id=domain_id,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/identity-providers/domain-routing?success=domain_bound_oidc",
        status_code=303,
    )


@router.post(
    "/domain-routing/{domain_id}/unbind-oidc",
    dependencies=[Depends(require_super_admin)],
)
def unbind_domain_from_oidc_connection(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
):
    """Unbind a privileged domain from its OIDC connection (super_admin only)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        oidc_service.unbind_domain_from_connection(
            requesting_user=requesting_user,
            domain_id=domain_id,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/identity-providers/domain-routing?success=domain_unbound",
        status_code=303,
    )
