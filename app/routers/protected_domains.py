"""Admin UI routes for protected-domain (forward-auth) management.

Lives under the Service Providers section. Lets an admin register a domain to
protect with forward auth, see the DNS-TXT setup instructions and portal-host
requirement, re-run verification, and delete a domain.
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
from schemas.protected_domains import ProtectedDomainCreate
from services import protected_domains as protected_domains_service
from services.exceptions import ServiceError
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/settings/protected-domains",
    tags=["protected-domains"],
    dependencies=[Depends(require_super_admin)],
    include_in_schema=False,
)

LIST_URL = "/admin/settings/protected-domains"


@router.get("", response_class=HTMLResponse)
def protected_domains_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List registered protected domains and the add form."""
    if not has_page_access(LIST_URL, user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        domains = protected_domains_service.list_protected_domains(requesting_user).items
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    context = get_template_context(
        request,
        tenant_id,
        domains=domains,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "protected_domains_list.html", context)


@router.get("/detail/{domain_id}", response_class=HTMLResponse)
def protected_domain_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
):
    """Show a single protected domain with DNS-TXT + portal-host setup steps."""
    if not has_page_access(LIST_URL + "/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        domain = protected_domains_service.get_protected_domain(requesting_user, domain_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    context = get_template_context(
        request,
        tenant_id,
        domain=domain,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "protected_domains_detail.html", context)


@router.post("/add")
def add_protected_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain: Annotated[str, Form(max_length=253)],
    portal_host: Annotated[str, Form(max_length=253)],
):
    """Register a new protected domain."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    data = ProtectedDomainCreate(domain=domain, portal_host=portal_host)
    try:
        created = protected_domains_service.register_protected_domain(requesting_user, data)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url=f"{LIST_URL}/detail/{created.id}?success=registered", status_code=303
    )


@router.post("/detail/{domain_id}/verify")
def verify_protected_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
):
    """Re-run the DNS-TXT verification for a protected domain."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        result = protected_domains_service.verify_protected_domain(requesting_user, domain_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    flag = "verified" if result.verified else "verify_failed"
    return RedirectResponse(url=f"{LIST_URL}/detail/{domain_id}?success={flag}", status_code=303)


@router.post("/delete/{domain_id}")
def delete_protected_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
):
    """Delete a protected domain."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    try:
        protected_domains_service.delete_protected_domain(requesting_user, domain_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url=f"{LIST_URL}?success=deleted", status_code=303)
