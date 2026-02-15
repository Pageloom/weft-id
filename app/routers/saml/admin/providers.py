"""Admin endpoints for IdP management (CRUD operations and certificate rotation)."""

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
from routers.saml._helpers import get_base_url
from schemas.saml import IdPCreate, IdPUpdate
from services import saml as saml_service
from services.exceptions import NotFoundError, ServiceError, ValidationError
from utils.saml import extract_idp_advertised_attributes
from utils.template_context import get_template_context

router = APIRouter()
templates = Jinja2Templates(directory="templates")


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
        get_template_context(request, tenant_id, idp=None, error=error),
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
    entity_id: Annotated[str, Form()],
    sso_url: Annotated[str, Form()],
    certificate_pem: Annotated[str, Form()],
    slo_url: Annotated[str, Form()] = "",
    metadata_url: Annotated[str, Form()] = "",
    attr_email: Annotated[str, Form()] = "email",
    attr_first_name: Annotated[str, Form()] = "firstName",
    attr_last_name: Annotated[str, Form()] = "lastName",
    attr_groups: Annotated[str, Form()] = "groups",
    is_enabled: Annotated[bool, Form()] = False,
    is_default: Annotated[bool, Form()] = False,
    require_platform_mfa: Annotated[bool, Form()] = False,
    jit_provisioning: Annotated[bool, Form()] = False,
):
    """Create a new identity provider."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = get_base_url(request)

    data = IdPCreate(
        name=name,
        provider_type=provider_type,
        entity_id=entity_id,
        sso_url=sso_url,
        slo_url=slo_url or None,
        certificate_pem=certificate_pem,
        metadata_url=metadata_url or None,
        attribute_mapping={
            "email": attr_email,
            "first_name": attr_first_name,
            "last_name": attr_last_name,
            "groups": attr_groups,
        },
        is_enabled=is_enabled,
        is_default=is_default,
        require_platform_mfa=require_platform_mfa,
        jit_provisioning=jit_provisioning,
    )

    try:
        saml_service.create_identity_provider(requesting_user, data, base_url)
    except ValidationError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/new?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/new?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url="/admin/settings/identity-providers?success=created", status_code=303
    )


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
            url=f"/admin/settings/identity-providers/new?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/new?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url="/admin/settings/identity-providers?success=created", status_code=303
    )


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
            url=f"/admin/settings/identity-providers/new?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/new?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url="/admin/settings/identity-providers?success=created", status_code=303
    )


# NOTE: Literal routes must be defined BEFORE parameterized routes like {idp_id}
# to ensure FastAPI matches them correctly (routes are matched in definition order)


@router.post(
    "/admin/settings/identity-providers/rotate-certificate",
    dependencies=[Depends(require_super_admin)],
)
def rotate_certificate(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Rotate the SP certificate with a 7-day grace period."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        saml_service.rotate_sp_certificate(requesting_user, grace_period_days=7)
    except NotFoundError:
        return RedirectResponse(
            url="/admin/settings/identity-providers?error=No+SP+certificate+exists+to+rotate",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url="/admin/settings/identity-providers?success=rotated", status_code=303
    )


@router.get(
    "/admin/settings/identity-providers/{idp_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def edit_idp_form(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
):
    """Display form to edit an identity provider."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    base_url = get_base_url(request)

    try:
        idp = saml_service.get_identity_provider(requesting_user, idp_id)
        sp_metadata = saml_service.get_sp_metadata(requesting_user, base_url)

        # Get domain bindings for this IdP and unbound domains for binding
        domain_bindings = saml_service.list_domain_bindings(requesting_user, idp_id)
        unbound_domains = saml_service.get_unbound_domains(requesting_user)

    except NotFoundError:
        return RedirectResponse(
            url="/admin/settings/identity-providers?error=not_found", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers?error={str(e)}",
            status_code=303,
        )

    # Extract advertised attributes from stored metadata XML
    advertised_attributes: list[dict[str, str]] = []
    if idp.metadata_xml:
        advertised_attributes = extract_idp_advertised_attributes(idp.metadata_xml)

    error = request.query_params.get("error")
    success = request.query_params.get("success")

    return templates.TemplateResponse(
        request,
        "saml_idp_form.html",
        get_template_context(
            request,
            tenant_id,
            idp=idp,
            sp_metadata=sp_metadata,
            advertised_attributes=advertised_attributes,
            domain_bindings=domain_bindings.items,
            unbound_domains=unbound_domains,
            error=error,
            success=success,
        ),
    )


@router.post(
    "/admin/settings/identity-providers/{idp_id}",
    dependencies=[Depends(require_super_admin)],
)
def update_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    idp_id: str,
    name: Annotated[str, Form()],
    sso_url: Annotated[str, Form()],
    certificate_pem: Annotated[str, Form()],
    slo_url: Annotated[str, Form()] = "",
    metadata_url: Annotated[str, Form()] = "",
    attr_email: Annotated[str, Form()] = "email",
    attr_first_name: Annotated[str, Form()] = "firstName",
    attr_last_name: Annotated[str, Form()] = "lastName",
    attr_groups: Annotated[str, Form()] = "groups",
    is_enabled: Annotated[bool, Form()] = False,
    is_default: Annotated[bool, Form()] = False,
    require_platform_mfa: Annotated[bool, Form()] = False,
    jit_provisioning: Annotated[bool, Form()] = False,
):
    """Update an identity provider."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    data = IdPUpdate(
        name=name,
        sso_url=sso_url,
        slo_url=slo_url or None,
        certificate_pem=certificate_pem,
        metadata_url=metadata_url or None,
        attribute_mapping={
            "email": attr_email,
            "first_name": attr_first_name,
            "last_name": attr_last_name,
            "groups": attr_groups,
        },
        require_platform_mfa=require_platform_mfa,
        jit_provisioning=jit_provisioning,
    )

    try:
        saml_service.update_identity_provider(requesting_user, idp_id, data)

        # Handle enable/disable and default separately
        idp = saml_service.get_identity_provider(requesting_user, idp_id)
        if idp.is_enabled != is_enabled:
            saml_service.set_idp_enabled(requesting_user, idp_id, is_enabled)
        if is_default and not idp.is_default:
            saml_service.set_idp_default(requesting_user, idp_id)

    except NotFoundError:
        return RedirectResponse(
            url="/admin/settings/identity-providers?error=not_found", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url=f"/admin/settings/identity-providers/{idp_id}?success=updated", status_code=303
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
        return RedirectResponse(
            url="/admin/settings/identity-providers?error=not_found", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers?error={str(e)}",
            status_code=303,
        )

    success = "enabled" if not idp.is_enabled else "disabled"
    return RedirectResponse(
        url=f"/admin/settings/identity-providers?success={success}", status_code=303
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
        return RedirectResponse(
            url="/admin/settings/identity-providers?error=not_found", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url="/admin/settings/identity-providers?success=set_default", status_code=303
    )


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
        return RedirectResponse(
            url="/admin/settings/identity-providers?error=not_found", status_code=303
        )
    except ValidationError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/{idp_id}?error={e.message}",
            status_code=303,
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers/{idp_id}?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url="/admin/settings/identity-providers?success=refreshed", status_code=303
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
        return RedirectResponse(
            url="/admin/settings/identity-providers?error=not_found", status_code=303
        )
    except ServiceError as e:
        return RedirectResponse(
            url=f"/admin/settings/identity-providers?error={str(e)}",
            status_code=303,
        )

    return RedirectResponse(
        url="/admin/settings/identity-providers?success=deleted", status_code=303
    )
