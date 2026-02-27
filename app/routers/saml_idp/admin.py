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
from pages import has_page_access
from services import service_providers as sp_service
from services.exceptions import ServiceError
from services.types import RequestingUser
from utils.saml_assertion import SAML_ATTRIBUTE_URIS
from utils.template_context import get_template_context
from utils.templates import templates

from ._helpers import get_base_url

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/settings/service-providers",
    tags=["saml-idp"],
    dependencies=[Depends(require_super_admin)],
    include_in_schema=False,
)

SP_LIST_URL = "/admin/settings/service-providers"


def _build_requesting_user(user: dict, tenant_id: str) -> RequestingUser:
    """Build a RequestingUser from user dict and tenant ID."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=user.get("role", "user"),
    )


def _load_sp_common(
    request: Request,
    tenant_id: str,
    user: dict,
    sp_id: str,
):
    """Load SP config and group count for the tab bar.

    Returns (sp_config, group_count, requesting_user) or redirects on error.
    """
    requesting_user = _build_requesting_user(user, tenant_id)
    sp_config = sp_service.get_service_provider(requesting_user, sp_id)
    group_count = sp_service.count_sp_group_assignments(requesting_user, sp_id)
    return sp_config, group_count, requesting_user


# =============================================================================
# SP List, New, Create, Import
# =============================================================================


@router.get("/", response_class=HTMLResponse)
def sp_list(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """List all registered service providers."""
    if not has_page_access("/admin/settings/service-providers", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        result = sp_service.list_service_providers(requesting_user)
        service_providers = result.items
    except ServiceError as exc:
        logger.warning("Failed to list service providers: %s", exc)
        service_providers = []

    context = get_template_context(
        request,
        tenant_id,
        service_providers=service_providers,
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
    if not has_page_access("/admin/settings/service-providers/new", user.get("role")):
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
):
    """Create an SP with just a name (step 1 of trust establishment flow)."""
    if not has_page_access("/admin/settings/service-providers", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not name.strip():
        return RedirectResponse(url=f"{SP_LIST_URL}/new?error=Name is required", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        from schemas.service_providers import SPCreate

        data = SPCreate(name=name.strip())
        sp = sp_service.create_service_provider(requesting_user, data)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp.id}/details?success=created", status_code=303
        )
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
    if not has_page_access("/admin/settings/service-providers", user.get("role")):
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
    if not has_page_access("/admin/settings/service-providers", user.get("role")):
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


# =============================================================================
# SP Detail - Redirect + Tab Routes
# =============================================================================


@router.get("/{sp_id}", response_class=HTMLResponse)
def sp_detail_redirect(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Redirect to the Details tab."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    return RedirectResponse(url=f"{SP_LIST_URL}/{sp_id}/details", status_code=303)


@router.get("/{sp_id}/details", response_class=HTMLResponse)
def sp_tab_details(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Details tab: name, description, entity ID, ACS URL, SLO URL, metadata URL."""
    if not has_page_access("/admin/settings/service-providers/detail/details", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        sp_config, group_count, requesting_user = _load_sp_common(request, tenant_id, user, sp_id)
    except ServiceError as exc:
        logger.warning("Failed to get SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)

    base_url = get_base_url(request)
    sp_metadata_url = f"{base_url}/saml/idp/metadata/{sp_id}"

    context = get_template_context(
        request,
        tenant_id,
        sp=sp_config,
        group_count=group_count,
        sp_metadata_url=sp_metadata_url,
        active_tab="details",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("saml_idp_sp_tab_details.html", context)


@router.get("/{sp_id}/attributes", response_class=HTMLResponse)
def sp_tab_attributes(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Attributes tab: attribute mapping and include_group_claims toggle."""
    if not has_page_access("/admin/settings/service-providers/detail/attributes", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        sp_config, group_count, requesting_user = _load_sp_common(request, tenant_id, user, sp_id)
    except ServiceError as exc:
        logger.warning("Failed to get SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)

    # Compute expected mapping from SP metadata for display
    from utils.saml_idp import auto_detect_attribute_mapping

    expected_mapping = {}
    if sp_config.sp_requested_attributes:
        expected_mapping = auto_detect_attribute_mapping(sp_config.sp_requested_attributes)

    context = get_template_context(
        request,
        tenant_id,
        sp=sp_config,
        group_count=group_count,
        saml_attributes=SAML_ATTRIBUTE_URIS,
        expected_mapping=expected_mapping,
        active_tab="attributes",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("saml_idp_sp_tab_attributes.html", context)


@router.get("/{sp_id}/groups", response_class=HTMLResponse)
def sp_tab_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Groups tab: assigned groups with add/remove controls."""
    if not has_page_access("/admin/settings/service-providers/detail/groups", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        sp_config, group_count, requesting_user = _load_sp_common(request, tenant_id, user, sp_id)
    except ServiceError as exc:
        logger.warning("Failed to get SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)

    assigned_groups = []
    available_groups = []
    try:
        result = sp_service.list_sp_group_assignments(requesting_user, sp_id)
        assigned_groups = result.items
        available_groups = sp_service.list_available_groups_for_sp(requesting_user, sp_id)
    except ServiceError:
        pass

    context = get_template_context(
        request,
        tenant_id,
        sp=sp_config,
        group_count=group_count,
        assigned_groups=assigned_groups,
        available_groups=available_groups,
        active_tab="groups",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("saml_idp_sp_tab_groups.html", context)


@router.get("/{sp_id}/certificates", response_class=HTMLResponse)
def sp_tab_certificates(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Certificates tab: signing certificate status and rotation."""
    if not has_page_access(
        "/admin/settings/service-providers/detail/certificates", user.get("role")
    ):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        sp_config, group_count, requesting_user = _load_sp_common(request, tenant_id, user, sp_id)
    except ServiceError as exc:
        logger.warning("Failed to get SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)

    signing_cert = None
    try:
        signing_cert = sp_service.get_sp_signing_certificate(requesting_user, sp_id)
    except ServiceError:
        pass

    context = get_template_context(
        request,
        tenant_id,
        sp=sp_config,
        group_count=group_count,
        signing_cert=signing_cert,
        active_tab="certificates",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("saml_idp_sp_tab_certificates.html", context)


@router.get("/{sp_id}/metadata", response_class=HTMLResponse)
def sp_tab_metadata(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Metadata tab: stored XML viewer, refresh/reimport controls."""
    if not has_page_access("/admin/settings/service-providers/detail/metadata", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        sp_config, group_count, requesting_user = _load_sp_common(request, tenant_id, user, sp_id)
    except ServiceError as exc:
        logger.warning("Failed to get SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)

    context = get_template_context(
        request,
        tenant_id,
        sp=sp_config,
        group_count=group_count,
        active_tab="metadata",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("saml_idp_sp_tab_metadata.html", context)


@router.get("/{sp_id}/danger", response_class=HTMLResponse)
def sp_tab_danger(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Danger tab: enable/disable toggle and delete."""
    if not has_page_access("/admin/settings/service-providers/detail/danger", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    try:
        sp_config, group_count, requesting_user = _load_sp_common(request, tenant_id, user, sp_id)
    except ServiceError as exc:
        logger.warning("Failed to get SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)

    context = get_template_context(
        request,
        tenant_id,
        sp=sp_config,
        group_count=group_count,
        assigned_group_count=group_count,
        active_tab="danger",
        success=request.query_params.get("success"),
        error=request.query_params.get("error"),
    )
    return templates.TemplateResponse("saml_idp_sp_tab_danger.html", context)


# =============================================================================
# POST Handlers
# =============================================================================


@router.post("/{sp_id}/edit", response_class=HTMLResponse)
def sp_edit(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    name: str = Form(""),
    description: str = Form(""),
    acs_url: str = Form(""),
    slo_url: str = Form(""),
):
    """Update an SP's name, description, and optionally ACS/SLO URLs (manual SPs)."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    from schemas.service_providers import SPUpdate

    update_fields: dict = {}
    if name.strip():
        update_fields["name"] = name.strip()
    if description.strip():
        update_fields["description"] = description.strip()
    if acs_url.strip():
        update_fields["acs_url"] = acs_url.strip()
    if slo_url.strip():
        update_fields["slo_url"] = slo_url.strip()

    if not update_fields:
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error=No changes provided", status_code=303
        )

    try:
        data = SPUpdate(**update_fields)
        sp_service.update_service_provider(requesting_user, sp_id, data)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?success=updated", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to update SP: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/edit-nameid-format", response_class=HTMLResponse)
def sp_edit_nameid_format(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    nameid_format: str = Form(""),
):
    """Update an SP's NameID format."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    valid_formats = {"emailAddress", "persistent", "transient", "unspecified"}
    if nameid_format not in valid_formats:
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error=Invalid NameID format", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    from schemas.service_providers import SPUpdate

    try:
        data = SPUpdate(nameid_format=nameid_format)  # type: ignore[arg-type]
        sp_service.update_service_provider(requesting_user, sp_id, data)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?success=nameid_format_updated", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to update NameID format: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/edit-attributes", response_class=HTMLResponse)
def sp_edit_attributes(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    include_group_claims: str | None = Form(None),
    attr_map_email: str = Form(""),
    attr_map_firstName: str = Form(""),  # noqa: N803
    attr_map_lastName: str = Form(""),  # noqa: N803
    attr_map_groups: str = Form(""),
):
    """Update an SP's attribute mapping and include_group_claims setting."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    from schemas.service_providers import SPUpdate

    update_fields: dict = {}
    update_fields["include_group_claims"] = include_group_claims == "true"

    attr_mapping: dict[str, str] = {}
    if attr_map_email.strip():
        attr_mapping["email"] = attr_map_email.strip()
    if attr_map_firstName.strip():
        attr_mapping["firstName"] = attr_map_firstName.strip()
    if attr_map_lastName.strip():
        attr_mapping["lastName"] = attr_map_lastName.strip()
    if attr_map_groups.strip():
        attr_mapping["groups"] = attr_map_groups.strip()
    if attr_mapping:
        update_fields["attribute_mapping"] = attr_mapping

    try:
        data = SPUpdate(**update_fields)
        sp_service.update_service_provider(requesting_user, sp_id, data)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/attributes?success=attributes_updated", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to update SP attributes: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/attributes?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/refresh-metadata-preview", response_class=HTMLResponse)
def sp_refresh_metadata_preview(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Preview changes from refreshing metadata from the stored URL."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        preview = sp_service.preview_sp_metadata_refresh(requesting_user, sp_id)
    except ServiceError as exc:
        logger.warning("Failed to preview metadata refresh: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/metadata?error={exc.message}", status_code=303
        )

    context = get_template_context(
        request,
        tenant_id,
        preview=preview,
        metadata_xml=None,
    )
    return templates.TemplateResponse("saml_idp_sp_metadata_preview.html", context)


@router.post("/{sp_id}/refresh-metadata-apply", response_class=HTMLResponse)
def sp_refresh_metadata_apply(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Apply metadata refresh from the stored URL."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.apply_sp_metadata_refresh(requesting_user, sp_id)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/metadata?success=metadata_refreshed", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to apply metadata refresh: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/metadata?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/reimport-metadata-preview", response_class=HTMLResponse)
def sp_reimport_metadata_preview(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    metadata_xml: str = Form(""),
):
    """Preview changes from re-importing metadata from provided XML."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not metadata_xml.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/metadata?error=Metadata XML is required", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        preview = sp_service.preview_sp_metadata_reimport(
            requesting_user, sp_id, metadata_xml.strip()
        )
    except ServiceError as exc:
        logger.warning("Failed to preview metadata reimport: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/metadata?error={exc.message}", status_code=303
        )

    context = get_template_context(
        request,
        tenant_id,
        preview=preview,
        metadata_xml=metadata_xml.strip(),
    )
    return templates.TemplateResponse("saml_idp_sp_metadata_preview.html", context)


@router.post("/{sp_id}/reimport-metadata-apply", response_class=HTMLResponse)
def sp_reimport_metadata_apply(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    metadata_xml: str = Form(""),
):
    """Apply metadata reimport from provided XML."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not metadata_xml.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/metadata?error=Metadata XML is required", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.apply_sp_metadata_reimport(requesting_user, sp_id, metadata_xml.strip())
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/metadata?success=metadata_reimported", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to apply metadata reimport: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/metadata?error={exc.message}", status_code=303
        )


# =============================================================================
# Trust Establishment POST Handlers
# =============================================================================


@router.post("/{sp_id}/establish-trust-url", response_class=HTMLResponse)
def sp_establish_trust_url(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    metadata_url: str = Form(""),
):
    """Establish trust with an SP by fetching its metadata URL."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not metadata_url.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error=Metadata URL is required", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.establish_trust_from_metadata_url(requesting_user, sp_id, metadata_url.strip())
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?success=trust_established", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to establish trust via URL: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/establish-trust-xml", response_class=HTMLResponse)
def sp_establish_trust_xml(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    metadata_xml: str = Form(""),
):
    """Establish trust with an SP by providing metadata XML."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not metadata_xml.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error=Metadata XML is required", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.establish_trust_from_metadata_xml(requesting_user, sp_id, metadata_xml.strip())
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?success=trust_established", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to establish trust via XML: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/establish-trust-manual", response_class=HTMLResponse)
def sp_establish_trust_manual(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    entity_id: str = Form(""),
    acs_url: str = Form(""),
    slo_url: str = Form(""),
):
    """Establish trust with an SP by manually providing entity_id and acs_url."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not entity_id.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error=Entity ID is required", status_code=303
        )
    if not acs_url.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error=ACS URL is required", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.establish_trust_manually(
            requesting_user,
            sp_id,
            entity_id=entity_id.strip(),
            acs_url=acs_url.strip(),
            slo_url=slo_url.strip() or None,
        )
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?success=trust_established", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to establish trust manually: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/details?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/rotate-certificate", response_class=HTMLResponse)
def sp_rotate_certificate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Rotate the signing certificate for an SP."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.rotate_sp_signing_certificate(requesting_user, sp_id)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/certificates?success=certificate_rotated", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to rotate SP certificate: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/certificates?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/groups/add", response_class=HTMLResponse)
def sp_add_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    group_id: str = Form(""),
):
    """Assign a group to a service provider."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not group_id.strip():
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/groups?error=Please select a group", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.assign_sp_to_group(requesting_user, sp_id, group_id.strip())
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/groups?success=group_assigned", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to assign group to SP: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/groups?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/groups/bulk", response_class=HTMLResponse)
def sp_bulk_add_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    group_ids: list[str] = Form(default=[]),
):
    """Bulk-assign groups to a service provider."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    if not group_ids:
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/groups?error=Please select groups", status_code=303
        )

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.bulk_assign_sp_to_groups(requesting_user, sp_id, group_ids)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/groups?success=groups_assigned", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to bulk assign groups to SP: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/groups?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/groups/{group_id}/remove", response_class=HTMLResponse)
def sp_remove_group(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
    group_id: str,
):
    """Remove a group assignment from a service provider."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.remove_sp_group_assignment(requesting_user, sp_id, group_id)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/groups?success=group_removed", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to remove group from SP: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/groups?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/enable", response_class=HTMLResponse)
def sp_enable(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Enable a disabled service provider."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.enable_service_provider(requesting_user, sp_id)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/danger?success=enabled", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to enable SP: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/danger?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/disable", response_class=HTMLResponse)
def sp_disable(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Disable a service provider. SSO will stop working immediately."""
    if not has_page_access("/admin/settings/service-providers/detail", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.disable_service_provider(requesting_user, sp_id)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/danger?success=disabled", status_code=303
        )
    except ServiceError as exc:
        logger.warning("Failed to disable SP: %s", exc)
        return RedirectResponse(
            url=f"{SP_LIST_URL}/{sp_id}/danger?error={exc.message}", status_code=303
        )


@router.post("/{sp_id}/delete", response_class=HTMLResponse)
def sp_delete(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    sp_id: str,
):
    """Delete a service provider."""
    if not has_page_access("/admin/settings/service-providers", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    requesting_user = _build_requesting_user(user, tenant_id)

    try:
        sp_service.delete_service_provider(requesting_user, sp_id)
        return RedirectResponse(url=f"{SP_LIST_URL}?success=deleted", status_code=303)
    except ServiceError as exc:
        logger.warning("Failed to delete SP: %s", exc)
        return RedirectResponse(url=f"{SP_LIST_URL}?error={exc.message}", status_code=303)
