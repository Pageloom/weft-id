"""Admin UI routes for proxy-app (forward-auth) management.

Lives under the Service Providers section. Lets a super admin create proxy apps
under verified protected domains, edit their config (public paths, forwarded
headers), manage group grants, and view a reverse-proxy config snippet.
"""

import logging
from typing import Annotated

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import has_page_access
from schemas.proxy_apps import (
    SUPPORTED_HEADER_KEYS,
    ProxyAppCreate,
    ProxyAppUpdate,
)
from services import protected_domains as protected_domains_service
from services import proxy_apps as proxy_apps_service
from services.exceptions import ServiceError
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/settings/proxy-apps",
    tags=["proxy-apps"],
    dependencies=[Depends(require_super_admin)],
    include_in_schema=False,
)

LIST_URL = "/admin/settings/proxy-apps"


def _parse_public_paths(raw: str) -> list[str]:
    """Split a newline/comma-separated textarea value into a list of paths."""
    parts: list[str] = []
    for line in raw.replace(",", "\n").splitlines():
        item = line.strip()
        if item:
            parts.append(item)
    return parts


def _parse_header_config(form: dict) -> dict[str, bool]:
    """Build a header_config dict from checkbox form fields header_<key>."""
    config: dict[str, bool] = {}
    for key in sorted(SUPPORTED_HEADER_KEYS):
        config[key] = form.get(f"header_{key}") == "on"
    return config


@router.get("", response_class=HTMLResponse)
def proxy_apps_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List proxy apps and the create form."""
    if not has_page_access(LIST_URL, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        apps = proxy_apps_service.list_proxy_apps(requesting_user).items
        domains = protected_domains_service.list_protected_domains(requesting_user).items
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    verified_domains = [d for d in domains if d.verification_status == "verified" and d.enabled]

    context = get_template_context(
        request,
        tenant_id,
        apps=apps,
        verified_domains=verified_domains,
        has_unverified=any(d.verification_status != "verified" for d in domains),
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "proxy_apps_list.html", context)


@router.get("/detail/{proxy_app_id}", response_class=HTMLResponse)
def proxy_app_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    proxy_app_id: str,
):
    """Show a proxy app: edit form, grants, and reverse-proxy snippet."""
    if not has_page_access(LIST_URL + "/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        app = proxy_apps_service.get_proxy_app(requesting_user, proxy_app_id)
        grants = proxy_apps_service.list_proxy_app_grants(requesting_user, proxy_app_id).items
        available_groups = proxy_apps_service.list_available_groups_for_proxy_app(
            requesting_user, proxy_app_id
        )
        domain = protected_domains_service.get_protected_domain(
            requesting_user, app.protected_domain_id
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    context = get_template_context(
        request,
        tenant_id,
        app=app,
        grants=grants,
        available_groups=available_groups,
        portal_host=domain.portal_host,
        header_keys=sorted(SUPPORTED_HEADER_KEYS),
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "proxy_apps_detail.html", context)


@router.post("/add")
async def add_proxy_app(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    protected_domain_id: Annotated[str, Form(max_length=50)],
    name: Annotated[str, Form(max_length=255)],
    external_url: Annotated[str, Form(max_length=2048)],
    description: Annotated[str, Form(max_length=2000)] = "",
    public_paths: Annotated[str, Form(max_length=8192)] = "",
    available_to_all: Annotated[str, Form(max_length=10)] = "",
):
    """Create a new proxy app."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    form = dict(await request.form())
    data = ProxyAppCreate(
        protected_domain_id=protected_domain_id,
        name=name,
        external_url=external_url,
        description=description or None,
        public_paths=_parse_public_paths(public_paths),
        header_config=_parse_header_config(form),
        available_to_all=available_to_all == "on",
    )
    try:
        created = proxy_apps_service.create_proxy_app(requesting_user, data)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"{LIST_URL}/detail/{created.id}?success=created", status_code=303)


@router.post("/detail/{proxy_app_id}/edit")
async def edit_proxy_app(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    proxy_app_id: str,
    name: Annotated[str, Form(max_length=255)],
    external_url: Annotated[str, Form(max_length=2048)],
    description: Annotated[str, Form(max_length=2000)] = "",
    public_paths: Annotated[str, Form(max_length=8192)] = "",
    available_to_all: Annotated[str, Form(max_length=10)] = "",
    enabled: Annotated[str, Form(max_length=10)] = "",
):
    """Update a proxy app's configuration."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    form = dict(await request.form())
    data = ProxyAppUpdate(
        name=name,
        external_url=external_url,
        description=description or "",
        public_paths=_parse_public_paths(public_paths),
        header_config=_parse_header_config(form),
        available_to_all=available_to_all == "on",
        enabled=enabled == "on",
    )
    try:
        proxy_apps_service.update_proxy_app(requesting_user, proxy_app_id, data)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"{LIST_URL}/detail/{proxy_app_id}?success=updated", status_code=303
    )


@router.post("/delete/{proxy_app_id}")
def delete_proxy_app(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    proxy_app_id: str,
):
    """Delete a proxy app."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        proxy_apps_service.delete_proxy_app(requesting_user, proxy_app_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"{LIST_URL}?success=deleted", status_code=303)


@router.post("/detail/{proxy_app_id}/grants/add")
def add_proxy_app_grant(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    proxy_app_id: str,
    group_id: Annotated[str, Form(max_length=50)],
):
    """Grant a group access to a proxy app."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        proxy_apps_service.add_proxy_app_grant(requesting_user, proxy_app_id, group_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"{LIST_URL}/detail/{proxy_app_id}?success=grant_added", status_code=303
    )


@router.post("/detail/{proxy_app_id}/grants/{group_id}/remove")
def remove_proxy_app_grant(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    proxy_app_id: str,
    group_id: str,
):
    """Remove a group grant from a proxy app."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        proxy_apps_service.remove_proxy_app_grant(requesting_user, proxy_app_id, group_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"{LIST_URL}/detail/{proxy_app_id}?success=grant_removed", status_code=303
    )
