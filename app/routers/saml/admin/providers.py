"""Admin endpoints for IdP management (CRUD operations and certificate rotation)."""

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
from fastapi.templating import Jinja2Templates
from pages import has_page_access
from routers.saml._helpers import get_base_url
from schemas.saml import IdPCreate, IdPUpdate
from services import saml as saml_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.saml import extract_idp_advertised_attributes
from utils.template_context import get_template_context

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

IDP_LIST_URL = "/admin/settings/identity-providers"


def _load_idp_common(request: Request, tenant_id: str, user: dict, idp_id: str):
    """Load IdP config for the tab bar. Returns (idp, requesting_user)."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    idp = saml_service.get_identity_provider(requesting_user, idp_id)
    return idp, requesting_user


# =============================================================================
# IdP List, New, Create, Import
# =============================================================================


@router.get(
    "/admin/settings/identity-providers",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def list_idps(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List identity providers for admin management."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        idp_list = saml_service.list_identity_providers(requesting_user)
    except ServiceError as e:
        return templates.TemplateResponse(
            request,
            "saml_error.html",
            get_template_context(
                request, tenant_id, error_type="configuration_error", error_detail=str(e)
            ),
        )

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "saml_idp_list.html",
        get_template_context(
            request,
            tenant_id,
            idps=idp_list.items,
            success=success,
            error=error,
        ),
    )


@router.get(
    "/admin/settings/identity-providers/new",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def new_idp_form(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display form to create a new identity provider."""
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "saml_idp_form.html",
        get_template_context(request, tenant_id, error=error),
    )


@router.post(
    "/admin/settings/identity-providers/new",
    dependencies=[Depends(require_super_admin)],
)
def create_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    name: Annotated[str, Form()],
    provider_type: Annotated[str, Form()],
):
    """Create a new identity provider (name-only, two-step creation)."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = get_base_url(request)

    data = IdPCreate(
        name=name,
        provider_type=provider_type,
    )

    try:
        idp = saml_service.create_identity_provider(requesting_user, data, base_url)
    except ValidationError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/new?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/new?error={str(e)}",
            status_code=303,
        )

    # Redirect to detail page so admin can establish trust
    return RedirectResponse(url=f"{IDP_LIST_URL}/{idp.id}/details?success=created", status_code=303)


@router.post(
    "/admin/settings/identity-providers/import-metadata",
    dependencies=[Depends(require_super_admin)],
)
def import_from_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    metadata_url: Annotated[str, Form()],
    provider_type: Annotated[str, Form()],
    name: Annotated[str, Form()],
):
    """Import an IdP configuration from a metadata URL."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = get_base_url(request)

    try:
        saml_service.import_idp_from_metadata_url(
            requesting_user, name, provider_type, metadata_url, base_url
        )
    except ValidationError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/new?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/new?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url=f"{IDP_LIST_URL}?success=created", status_code=303)


@router.post(
    "/admin/settings/identity-providers/import-metadata-xml",
    dependencies=[Depends(require_super_admin)],
)
def import_from_metadata_xml(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    metadata_xml: Annotated[str, Form()],
    provider_type: Annotated[str, Form()],
    name: Annotated[str, Form()],
):
    """Import an IdP configuration from raw metadata XML."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = get_base_url(request)

    try:
        saml_service.import_idp_from_metadata_xml(
            requesting_user, name, provider_type, metadata_xml, base_url
        )
    except ValidationError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/new?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/new?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url=f"{IDP_LIST_URL}?success=created", status_code=303)


# NOTE: Literal routes must be defined BEFORE parameterized routes like {idp_id}
# to ensure FastAPI matches them correctly (routes are matched in definition order)


# =============================================================================
# Trust Establishment Routes (must be before {idp_id} catch-all)
# =============================================================================


# =============================================================================
# IdP Detail - Redirect + Tab Routes
# =============================================================================


@router.get(
    "/admin/settings/identity-providers/{idp_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def idp_detail_redirect(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Redirect to the Details tab."""
    if not has_page_access("/admin/settings/identity-providers/idp", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    return RedirectResponse(url=f"{IDP_LIST_URL}/{idp_id}/details", status_code=303)


@router.get(
    "/admin/settings/identity-providers/{idp_id}/details",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def idp_tab_details(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Details tab: name, provider type, entity ID, SSO/SLO URLs, settings, connection test."""
    if not has_page_access("/admin/settings/identity-providers/idp/details", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        idp, requesting_user = _load_idp_common(request, tenant_id, user, idp_id)
        domain_bindings = saml_service.list_domain_bindings(requesting_user, idp_id)
        unbound_domains = saml_service.get_unbound_domains(requesting_user)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to get IdP: %s", exc)
        return RedirectResponse(url=f"{IDP_LIST_URL}?error={exc.message}", status_code=303)

    # Get per-IdP SP certificate for display
    sp_certificate = saml_service.get_idp_sp_certificate_for_display(requesting_user, idp_id)

    context = get_template_context(
        request,
        tenant_id,
        idp=idp,
        sp_certificate=sp_certificate,
        domain_bindings=domain_bindings.items,
        unbound_domains=unbound_domains,
        base_url=get_base_url(request),
        active_tab="details",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "saml_idp_tab_details.html", context)


@router.get(
    "/admin/settings/identity-providers/{idp_id}/certificates",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def idp_tab_certificates(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Certificates tab: IdP certificates with management, SP certificate info."""
    if not has_page_access("/admin/settings/identity-providers/idp/certificates", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        idp, requesting_user = _load_idp_common(request, tenant_id, user, idp_id)
        idp_certificates = saml_service.list_idp_certificates(requesting_user, idp_id)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to get IdP: %s", exc)
        return RedirectResponse(url=f"{IDP_LIST_URL}?error={exc.message}", status_code=303)

    sp_certificate = None
    try:
        sp_certificate = saml_service.get_idp_sp_certificate_for_display(requesting_user, idp_id)
    except ServiceError:
        pass

    import datetime

    cert_expiry_threshold = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30)

    context = get_template_context(
        request,
        tenant_id,
        idp=idp,
        idp_certificates=idp_certificates,
        sp_certificate=sp_certificate,
        cert_expiry_threshold=cert_expiry_threshold,
        active_tab="certificates",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "saml_idp_tab_certificates.html", context)


@router.get(
    "/admin/settings/identity-providers/{idp_id}/attributes",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def idp_tab_attributes(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Attributes tab: attribute mapping table with presets."""
    if not has_page_access("/admin/settings/identity-providers/idp/attributes", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        idp, requesting_user = _load_idp_common(request, tenant_id, user, idp_id)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to get IdP: %s", exc)
        return RedirectResponse(url=f"{IDP_LIST_URL}?error={exc.message}", status_code=303)

    advertised_attributes: list[dict[str, str]] = []
    if idp.metadata_xml:
        advertised_attributes = extract_idp_advertised_attributes(idp.metadata_xml)

    context = get_template_context(
        request,
        tenant_id,
        idp=idp,
        advertised_attributes=advertised_attributes,
        active_tab="attributes",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "saml_idp_tab_attributes.html", context)


@router.get(
    "/admin/settings/identity-providers/{idp_id}/metadata",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def idp_tab_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Metadata tab: re-import from URL or XML, last sync status."""
    if not has_page_access("/admin/settings/identity-providers/idp/metadata", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        idp, requesting_user = _load_idp_common(request, tenant_id, user, idp_id)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to get IdP: %s", exc)
        return RedirectResponse(url=f"{IDP_LIST_URL}?error={exc.message}", status_code=303)

    context = get_template_context(
        request,
        tenant_id,
        idp=idp,
        active_tab="metadata",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "saml_idp_tab_metadata.html", context)


@router.get(
    "/admin/settings/identity-providers/{idp_id}/danger",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def idp_tab_danger(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Danger tab: enable/disable toggle, set default, delete."""
    if not has_page_access("/admin/settings/identity-providers/idp/danger", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        idp, requesting_user = _load_idp_common(request, tenant_id, user, idp_id)
        domain_bindings = saml_service.list_domain_bindings(requesting_user, idp_id)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to get IdP: %s", exc)
        return RedirectResponse(url=f"{IDP_LIST_URL}?error={exc.message}", status_code=303)

    context = get_template_context(
        request,
        tenant_id,
        idp=idp,
        domain_count=len(domain_bindings.items),
        active_tab="danger",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse(request, "saml_idp_tab_danger.html", context)


# =============================================================================
# IdP Detail - POST Handlers
# =============================================================================


@router.post(
    "/admin/settings/identity-providers/{idp_id}/edit",
    dependencies=[Depends(require_super_admin)],
)
def edit_idp_name(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    name: Annotated[str, Form()],
):
    """Update IdP name (inline edit from details tab)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.update_identity_provider(requesting_user, idp_id, IdPUpdate(name=name))
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/details?error={str(e)}", status_code=303
        )

    return RedirectResponse(url=f"{IDP_LIST_URL}/{idp_id}/details?success=updated", status_code=303)


@router.post(
    "/admin/settings/identity-providers/{idp_id}/edit-settings",
    dependencies=[Depends(require_super_admin)],
)
def edit_idp_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    is_enabled: Annotated[bool, Form()] = False,
    is_default: Annotated[bool, Form()] = False,
    require_platform_mfa: Annotated[bool, Form()] = False,
    jit_provisioning: Annotated[bool, Form()] = False,
):
    """Update IdP settings (enabled, default, MFA, JIT provisioning)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        idp = saml_service.get_identity_provider(requesting_user, idp_id)

        # Toggle enabled state if changed
        if is_enabled != idp.is_enabled:
            saml_service.set_idp_enabled(requesting_user, idp_id, is_enabled)

        # Set as default if toggled on (un-defaulting requires picking another)
        if is_default and not idp.is_default:
            saml_service.set_idp_default(requesting_user, idp_id)

        # Update MFA/JIT settings
        saml_service.update_identity_provider(
            requesting_user,
            idp_id,
            IdPUpdate(
                require_platform_mfa=require_platform_mfa,
                jit_provisioning=jit_provisioning,
            ),
        )
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/details?error={str(e)}", status_code=303
        )

    return RedirectResponse(
        url=f"{IDP_LIST_URL}/{idp_id}/details?success=settings_updated", status_code=303
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}/edit-attributes",
    dependencies=[Depends(require_super_admin)],
)
def edit_idp_attributes(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    attr_email: Annotated[str, Form()] = "email",
    attr_first_name: Annotated[str, Form()] = "firstName",
    attr_last_name: Annotated[str, Form()] = "lastName",
    attr_groups: Annotated[str, Form()] = "groups",
):
    """Update IdP attribute mapping."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.update_identity_provider(
            requesting_user,
            idp_id,
            IdPUpdate(
                attribute_mapping={
                    "email": attr_email,
                    "first_name": attr_first_name,
                    "last_name": attr_last_name,
                    "groups": attr_groups,
                }
            ),
        )
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/attributes?error={str(e)}", status_code=303
        )

    return RedirectResponse(
        url=f"{IDP_LIST_URL}/{idp_id}/attributes?success=attributes_updated", status_code=303
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}/reimport-metadata",
    dependencies=[Depends(require_super_admin)],
)
def reimport_idp_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    metadata_xml: Annotated[str, Form()],
):
    """Re-import IdP metadata from pasted XML."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        # Verify IdP exists before parsing
        saml_service.get_identity_provider(requesting_user, idp_id)
        # Parse the new XML and update
        parsed = saml_service.parse_idp_metadata_xml_to_schema(metadata_xml)
        saml_service.update_identity_provider(
            requesting_user,
            idp_id,
            IdPUpdate(
                sso_url=parsed.sso_url,
                slo_url=parsed.slo_url,
                certificate_pem=parsed.certificate_pem,
            ),
        )
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ValidationError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/metadata?error={e.message}", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/metadata?error={str(e)}", status_code=303
        )

    return RedirectResponse(
        url=f"{IDP_LIST_URL}/{idp_id}/metadata?success=refreshed", status_code=303
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}/toggle",
    dependencies=[Depends(require_super_admin)],
)
def toggle_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Toggle an IdP's enabled status."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        idp = saml_service.get_identity_provider(requesting_user, idp_id)
        saml_service.set_idp_enabled(requesting_user, idp_id, not idp.is_enabled)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}?error={str(e)}",
            status_code=303,
        )

    success = "enabled" if not idp.is_enabled else "disabled"
    return RedirectResponse(
        url=f"{IDP_LIST_URL}/{idp_id}/details?success={success}", status_code=303
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}/set-default",
    dependencies=[Depends(require_super_admin)],
)
def set_default_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Set an IdP as the default for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.set_idp_default(requesting_user, idp_id)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url=f"{IDP_LIST_URL}/{idp_id}/details?success=updated", status_code=303)


@router.post(
    "/admin/settings/identity-providers/{idp_id}/refresh-metadata",
    dependencies=[Depends(require_super_admin)],
)
def refresh_idp_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Manually refresh an IdP's metadata from its URL."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.refresh_idp_from_metadata(requesting_user, idp_id)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ValidationError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/metadata?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/metadata?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url=f"{IDP_LIST_URL}/{idp_id}/metadata?success=refreshed", status_code=303
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}/delete",
    dependencies=[Depends(require_super_admin)],
)
def delete_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Delete an identity provider."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.delete_identity_provider(requesting_user, idp_id)
    except NotFoundError:
        return RedirectResponse(url=f"{IDP_LIST_URL}?error=not_found", status_code=303)
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(url=f"{IDP_LIST_URL}?success=deleted", status_code=303)


# =============================================================================
# Trust Establishment & Per-IdP Certificate Rotation
# =============================================================================


@router.post(
    "/admin/settings/identity-providers/{idp_id}/establish-trust-url",
    dependencies=[Depends(require_super_admin)],
)
def establish_trust_url(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    metadata_url: Annotated[str, Form()],
):
    """Establish trust on a pending IdP via metadata URL."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = get_base_url(request)

    try:
        saml_service.import_idp_from_metadata_url(
            requesting_user,
            name="",  # Not used when idp_id is provided
            provider_type="",
            metadata_url=metadata_url,
            base_url=base_url,
            idp_id=idp_id,
        )
    except ValidationError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/details?error={e.message}", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/details?error={str(e)}", status_code=303
        )

    return RedirectResponse(
        url=f"{IDP_LIST_URL}/{idp_id}/details?success=trust_established", status_code=303
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}/establish-trust-xml",
    dependencies=[Depends(require_super_admin)],
)
def establish_trust_xml(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    metadata_xml: Annotated[str, Form()],
):
    """Establish trust on a pending IdP via metadata XML paste."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = get_base_url(request)

    try:
        saml_service.import_idp_from_metadata_xml(
            requesting_user,
            name="",
            provider_type="",
            metadata_xml=metadata_xml,
            base_url=base_url,
            idp_id=idp_id,
        )
    except ValidationError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/details?error={e.message}", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/details?error={str(e)}", status_code=303
        )

    return RedirectResponse(
        url=f"{IDP_LIST_URL}/{idp_id}/details?success=trust_established", status_code=303
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}/establish-trust-manual",
    dependencies=[Depends(require_super_admin)],
)
def establish_trust_manual(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    entity_id: Annotated[str, Form()],
    sso_url: Annotated[str, Form()],
    certificate_pem: Annotated[str, Form()],
    slo_url: Annotated[str, Form()] = "",
):
    """Establish trust on a pending IdP via manual configuration."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.establish_idp_trust(
            requesting_user,
            idp_id=idp_id,
            entity_id=entity_id,
            sso_url=sso_url,
            certificate_pem=certificate_pem,
            slo_url=slo_url or None,
        )
    except ValidationError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/details?error={e.message}", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/details?error={str(e)}", status_code=303
        )

    return RedirectResponse(
        url=f"{IDP_LIST_URL}/{idp_id}/details?success=trust_established", status_code=303
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}/rotate-sp-certificate",
    dependencies=[Depends(require_super_admin)],
)
def rotate_idp_sp_certificate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Rotate the per-IdP SP certificate with a 7-day grace period."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.rotate_idp_sp_certificate(requesting_user, idp_id, grace_period_days=7)
    except NotFoundError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/certificates?error={e.message}", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"{IDP_LIST_URL}/{idp_id}/certificates?error={str(e)}", status_code=303
        )

    return RedirectResponse(
        url=f"{IDP_LIST_URL}/{idp_id}/certificates?success=rotated", status_code=303
    )
