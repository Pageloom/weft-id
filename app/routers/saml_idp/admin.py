"""Admin UI routes for SAML IdP Service Provider management."""

import logging
from typing import Annotated

from dependencies import (
    get_current_user,
    get_tenant_id_from_request,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import has_page_access
from services import service_providers as sp_service
from services.exceptions import ServiceError
from services.types import RequestingUser
from utils.template_context import get_template_context

from ._helpers import get_base_url

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/integrations/service-providers",
    tags=["saml-idp"],
    dependencies=[Depends(require_super_admin)],
    include_in_schema=False,
)
templates = Jinja2Templates(directory="templates")

SP_LIST_URL = "/admin/integrations/service-providers"


def _build_requesting_user(user: dict, tenant_id: str) -> RequestingUser:
    """Build a RequestingUser from user dict and tenant ID."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=user.get("role", "user"),
    )


@router.get("/", response_class=HTMLResponse)
def sp_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List all registered service providers."""
    if not has_page_access("/admin/integrations/service-providers", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        result = sp_service.list_service_providers(requesting_user)
        service_providers = result.items
    except ServiceError as exc:
        logger.warning("Failed to list service providers: %s", exc)
        service_providers = []

    base_url = get_base_url(request)
    idp_metadata_url = f"{base_url}/saml/idp/metadata" if service_providers else None

    context = get_template_context(
        request,
        tenant_id,
        service_providers=service_providers,
        idp_metadata_url=idp_metadata_url,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("saml_idp_sp_list.html", context)


@router.get("/new", response_class=HTMLResponse)
def sp_new(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Show the SP registration form."""
    if not has_page_access("/admin/integrations/service-providers/new", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    context = get_template_context(
        request,
        tenant_id,
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("saml_idp_sp_new.html", context)


@router.post("/create", response_class=HTMLResponse)
def sp_create_manual(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: str = Form(""),
    entity_id: str = Form(""),
    acs_url: str = Form(""),
):
    """Create an SP from manual entry."""
    if not has_page_access("/admin/integrations/service-providers", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not name.strip():
        return RedirectResponse(url=f"{SP_LIST_URL}/new?error=Name is required", status_code=303)
    if not entity_id.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/new?error=Entity ID is required", status_code=303
        )
    if not acs_url.strip():
        return RedirectResponse(url=f"{SP_LIST_URL}/new?error=ACS URL is required", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        from schemas.service_providers import SPCreate

        data = SPCreate(name=name.strip(), entity_id=entity_id.strip(), acs_url=acs_url.strip())
        sp_service.create_service_provider(requesting_user, data)
        return RedirectResponse(url=f"{SP_LIST_URL}?success=created", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to create SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}/new?error={exc.message}", status_code=303)


@router.post("/import-metadata-xml", response_class=HTMLResponse)
def sp_import_xml(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: str = Form(""),
    metadata_xml: str = Form(""),
):
    """Create an SP from pasted metadata XML."""
    if not has_page_access("/admin/integrations/service-providers", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not name.strip():
        return RedirectResponse(url=f"{SP_LIST_URL}/new?error=Name is required", status_code=303)
    if not metadata_xml.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/new?error=Metadata XML is required", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.import_sp_from_metadata_xml(
            requesting_user, name=name.strip(), metadata_xml=metadata_xml.strip()
        )
        return RedirectResponse(url=f"{SP_LIST_URL}?success=created", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to import SP from XML: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}/new?error={exc.message}", status_code=303)


@router.post("/import-metadata-url", response_class=HTMLResponse)
def sp_import_url(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: str = Form(""),
    metadata_url: str = Form(""),
):
    """Create an SP from a metadata URL."""
    if not has_page_access("/admin/integrations/service-providers", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not name.strip():
        return RedirectResponse(url=f"{SP_LIST_URL}/new?error=Name is required", status_code=303)
    if not metadata_url.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/new?error=Metadata URL is required", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.import_sp_from_metadata_url(
            requesting_user, name=name.strip(), metadata_url=metadata_url.strip()
        )
        return RedirectResponse(url=f"{SP_LIST_URL}?success=created", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to import SP from URL: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}/new?error={exc.message}", status_code=303)


@router.get("/{sp_id}", response_class=HTMLResponse)
def sp_detail(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Show SP detail page with cert status and per-SP metadata URL."""
    if not has_page_access("/admin/integrations/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_config = sp_service.get_service_provider(requesting_user, sp_id)
    except ServiceError as exc:
        logger.warning("Failed to get SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)

    # Get signing cert info
    signing_cert = None
    try:
        signing_cert = sp_service.get_sp_signing_certificate(requesting_user, sp_id)
    except ServiceError:
        pass

    base_url = get_base_url(request)
    sp_metadata_url = f"{base_url}/saml/idp/metadata/{sp_id}"

    context = get_template_context(
        request,
        tenant_id,
        sp=sp_config,
        signing_cert=signing_cert,
        sp_metadata_url=sp_metadata_url,
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("saml_idp_sp_detail.html", context)


@router.post("/{sp_id}/rotate-certificate", response_class=HTMLResponse)
def sp_rotate_certificate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Rotate the signing certificate for an SP."""
    if not has_page_access("/admin/integrations/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.rotate_sp_signing_certificate(requesting_user, sp_id)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}?success=certificate_rotated", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to rotate SP certificate: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}/{sp_id}?error={exc.message}", status_code=303)


@router.post("/{sp_id}/delete", response_class=HTMLResponse)
def sp_delete(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Delete a service provider."""
    if not has_page_access("/admin/integrations/service-providers", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.delete_service_provider(requesting_user, sp_id)
        return RedirectResponse(url=f"{SP_LIST_URL}?success=deleted", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to delete SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)
