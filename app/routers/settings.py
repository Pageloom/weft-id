"""Settings routes (privileged domains, branding, security, about)."""

from typing import Annotated, Literal

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_admin,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import get_first_accessible_child
from pydantic import ValidationError as PydanticValidationError
from schemas.branding import BrandingSettingsUpdate, LogoMode, LogoSlot
from schemas.settings import (
    DomainGroupLinkCreate,
    PrivilegedDomainCreate,
    TenantSecuritySettingsUpdate,
)
from services import branding as branding_service
from services import groups as groups_service
from services import saml as saml_service
from services import settings as settings_service
from services.activity import track_activity
from services.exceptions import ServiceError, ValidationError
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates
from version import __version__

router = APIRouter(
    prefix="/admin/settings",
    tags=["admin-settings"],
    dependencies=[Depends(require_admin)],  # All routes require admin role
    include_in_schema=False,
)


@router.get("/", response_class=HTMLResponse)
def admin_settings_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible settings page."""
    # Get first accessible child page
    first_child = get_first_accessible_child("/admin/settings", user.get("role"))

    if first_child:
        return RedirectResponse(url=first_child, status_code=303)

    # Fallback if no accessible children (shouldn't happen)
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/privileged-domains", response_class=HTMLResponse)
def privileged_domains(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display and manage privileged domains for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        domains = settings_service.list_privileged_domains(requesting_user)
        # Get IdPs for binding dropdown (super_admin only)
        idps = []
        if user.get("role") == "super_admin":
            idps = saml_service.list_identity_providers(requesting_user).items
        # Get WeftId groups for link dropdown
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
            weftid_groups=weftid_groups,
            error=error,
            success=success,
        ),
    )


@router.post("/privileged-domains/add")
def add_privileged_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain: Annotated[str, Form()],
):
    """Add a new privileged domain."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    domain_data = PrivilegedDomainCreate(domain=domain)

    try:
        settings_service.add_privileged_domain(requesting_user, domain_data)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/admin/settings/privileged-domains", status_code=303)


@router.post("/privileged-domains/delete/{domain_id}")
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

    return RedirectResponse(url="/admin/settings/privileged-domains", status_code=303)


@router.post("/privileged-domains/{domain_id}/link-group")
def link_group_to_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
    group_id: Annotated[str, Form()],
):
    """Link a group to a privileged domain for auto-assignment."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    link_data = DomainGroupLinkCreate(group_id=group_id)

    try:
        settings_service.add_domain_group_link(requesting_user, domain_id, link_data)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/privileged-domains?success=group_linked",
        status_code=303,
    )


@router.post("/privileged-domains/{domain_id}/unlink-group/{link_id}")
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
        url="/admin/settings/privileged-domains?success=group_unlinked",
        status_code=303,
    )


@router.post(
    "/privileged-domains/{domain_id}/bind",
    dependencies=[Depends(require_super_admin)],
)
def bind_domain_to_idp(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    domain_id: str,
    idp_id: Annotated[str, Form()],
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
        url="/admin/settings/privileged-domains?success=domain_bound",
        status_code=303,
    )


@router.post(
    "/privileged-domains/{domain_id}/unbind",
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
        url="/admin/settings/privileged-domains?success=domain_unbound",
        status_code=303,
    )


@router.get("/about", response_class=HTMLResponse)
def admin_about(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display the About Weft ID page with version and documentation links."""
    requesting_user = build_requesting_user(user, tenant_id, request)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    return templates.TemplateResponse(
        request,
        "settings_about.html",
        get_template_context(request, tenant_id, version=__version__),
    )


@router.get("/security", response_class=HTMLResponse, dependencies=[Depends(require_super_admin)])
def admin_security_redirect(
    request: Request,
):
    """Redirect to security sessions tab."""
    return RedirectResponse(url="/admin/settings/security/sessions", status_code=303)


def _get_security_template_context(
    request: Request,
    tenant_id: str,
    user: dict,
    template_name: str,
):
    """Shared helper to load security settings and render a tab template."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        settings = settings_service.get_security_settings(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        template_name,
        get_template_context(
            request,
            tenant_id,
            current_timeout=settings.session_timeout_seconds,
            persistent_sessions=settings.persistent_sessions,
            allow_users_edit_profile=settings.allow_users_edit_profile,
            allow_users_add_emails=settings.allow_users_add_emails,
            inactivity_threshold_days=settings.inactivity_threshold_days,
            max_certificate_lifetime_years=settings.max_certificate_lifetime_years,
            certificate_rotation_window_days=settings.certificate_rotation_window_days,
            minimum_password_length=settings.minimum_password_length,
            minimum_zxcvbn_score=settings.minimum_zxcvbn_score,
            success=success,
            error=error,
        ),
    )


@router.get(
    "/security/sessions", response_class=HTMLResponse, dependencies=[Depends(require_super_admin)]
)
def admin_security_sessions(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display sessions security settings tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_sessions.html"
    )


@router.get(
    "/security/certificates",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def admin_security_certificates(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display certificates security settings tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_certificates.html"
    )


@router.get(
    "/security/passwords",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def admin_security_passwords(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display passwords security settings tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_passwords.html"
    )


@router.get(
    "/security/permissions",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def admin_security_permissions(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display permissions security settings tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_permissions.html"
    )


@router.post("/security/sessions/update", dependencies=[Depends(require_super_admin)])
def update_admin_security_sessions(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    session_timeout: Annotated[str, Form()] = "",
    persistent_sessions: Annotated[str, Form()] = "",
    inactivity_threshold: Annotated[str, Form()] = "",
):
    """Update session security settings for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Parse session timeout (empty string means indefinite/NULL)
    timeout_seconds: int | None = None
    if session_timeout:
        try:
            timeout_seconds = int(session_timeout)
            if timeout_seconds <= 0:
                exc = ValidationError(
                    message="Session timeout must be positive",
                    code="invalid_timeout",
                    field="session_timeout_seconds",
                )
                return render_error_page(request, tenant_id, exc)
        except ValueError:
            exc = ValidationError(
                message="Session timeout must be a number",
                code="invalid_timeout",
                field="session_timeout_seconds",
            )
            return render_error_page(request, tenant_id, exc)

    # Parse inactivity threshold (empty string means disabled/NULL)
    inactivity_days: int | None = None
    if inactivity_threshold:
        try:
            inactivity_days = int(inactivity_threshold)
            if inactivity_days <= 0:
                exc = ValidationError(
                    message="Inactivity threshold must be positive",
                    code="invalid_threshold",
                    field="inactivity_threshold_days",
                )
                return render_error_page(request, tenant_id, exc)
        except ValueError:
            exc = ValidationError(
                message="Inactivity threshold must be a number",
                code="invalid_threshold",
                field="inactivity_threshold_days",
            )
            return render_error_page(request, tenant_id, exc)

    try:
        settings_update = TenantSecuritySettingsUpdate(
            session_timeout_seconds=timeout_seconds,
            persistent_sessions=persistent_sessions == "true",
            inactivity_threshold_days=inactivity_days,
        )
    except PydanticValidationError as e:
        exc = ValidationError(
            message=str(e.errors()[0]["msg"]) if e.errors() else "Invalid input",
            code="validation_error",
        )
        return render_error_page(request, tenant_id, exc)

    try:
        settings_service.update_security_settings(requesting_user, settings_update)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/admin/settings/security/sessions?success=1", status_code=303)


@router.post("/security/passwords/update", dependencies=[Depends(require_super_admin)])
def update_admin_security_passwords(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    minimum_password_length: Annotated[str, Form()] = "",
    minimum_zxcvbn_score: Annotated[str, Form()] = "",
):
    """Update password policy security settings for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Parse minimum password length
    pw_length: Literal[8, 10, 12, 14, 16, 18, 20] | None = None
    if minimum_password_length:
        try:
            parsed_length = int(minimum_password_length)
            if parsed_length not in (8, 10, 12, 14, 16, 18, 20):
                raise ValueError("Invalid length value")
            pw_length = parsed_length  # type: ignore[assignment]
        except ValueError:
            exc = ValidationError(
                message="Minimum password length must be 8, 10, 12, 14, 16, 18, or 20",
                code="invalid_password_length",
                field="minimum_password_length",
            )
            return render_error_page(request, tenant_id, exc)

    # Parse minimum zxcvbn score
    zxcvbn_score: Literal[3, 4] | None = None
    if minimum_zxcvbn_score:
        try:
            parsed_score = int(minimum_zxcvbn_score)
            if parsed_score not in (3, 4):
                raise ValueError("Invalid score value")
            zxcvbn_score = parsed_score  # type: ignore[assignment]
        except ValueError:
            exc = ValidationError(
                message="Minimum strength score must be 3 or 4",
                code="invalid_zxcvbn_score",
                field="minimum_zxcvbn_score",
            )
            return render_error_page(request, tenant_id, exc)

    try:
        settings_update = TenantSecuritySettingsUpdate(
            minimum_password_length=pw_length,
            minimum_zxcvbn_score=zxcvbn_score,
        )
    except PydanticValidationError as e:
        exc = ValidationError(
            message=str(e.errors()[0]["msg"]) if e.errors() else "Invalid input",
            code="validation_error",
        )
        return render_error_page(request, tenant_id, exc)

    try:
        settings_service.update_security_settings(requesting_user, settings_update)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/admin/settings/security/passwords?success=1", status_code=303)


@router.post("/security/certificates/update", dependencies=[Depends(require_super_admin)])
def update_admin_security_certificates(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    certificate_lifetime: Annotated[str, Form()] = "",
    rotation_window: Annotated[str, Form()] = "",
):
    """Update certificate security settings for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Parse certificate lifetime (empty string means keep current)
    cert_lifetime_years: Literal[1, 2, 3, 5, 10] | None = None
    if certificate_lifetime:
        try:
            parsed_lifetime = int(certificate_lifetime)
            if parsed_lifetime not in (1, 2, 3, 5, 10):
                raise ValueError("Invalid lifetime value")
            cert_lifetime_years = parsed_lifetime  # type: ignore[assignment]
        except ValueError:
            exc = ValidationError(
                message="Certificate lifetime must be 1, 2, 3, 5, or 10 years",
                code="invalid_certificate_lifetime",
                field="max_certificate_lifetime_years",
            )
            return render_error_page(request, tenant_id, exc)

    # Parse rotation window (empty string means keep current)
    rotation_window_days: Literal[14, 30, 60, 90] | None = None
    if rotation_window:
        try:
            parsed_window = int(rotation_window)
            if parsed_window not in (14, 30, 60, 90):
                raise ValueError("Invalid rotation window value")
            rotation_window_days = parsed_window  # type: ignore[assignment]
        except ValueError:
            exc = ValidationError(
                message="Certificate rotation window must be 14, 30, 60, or 90 days",
                code="invalid_rotation_window",
                field="certificate_rotation_window_days",
            )
            return render_error_page(request, tenant_id, exc)

    try:
        settings_update = TenantSecuritySettingsUpdate(
            max_certificate_lifetime_years=cert_lifetime_years,
            certificate_rotation_window_days=rotation_window_days,
        )
    except PydanticValidationError as e:
        exc = ValidationError(
            message=str(e.errors()[0]["msg"]) if e.errors() else "Invalid input",
            code="validation_error",
        )
        return render_error_page(request, tenant_id, exc)

    try:
        settings_service.update_security_settings(requesting_user, settings_update)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/admin/settings/security/certificates?success=1", status_code=303)


@router.post("/security/permissions/update", dependencies=[Depends(require_super_admin)])
def update_admin_security_permissions(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    allow_users_edit_profile: Annotated[str, Form()] = "",
    allow_users_add_emails: Annotated[str, Form()] = "",
):
    """Update permission security settings for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        settings_update = TenantSecuritySettingsUpdate(
            allow_users_edit_profile=allow_users_edit_profile == "true",
            allow_users_add_emails=allow_users_add_emails == "true",
        )
    except PydanticValidationError as e:
        exc = ValidationError(
            message=str(e.errors()[0]["msg"]) if e.errors() else "Invalid input",
            code="validation_error",
        )
        return render_error_page(request, tenant_id, exc)

    try:
        settings_service.update_security_settings(requesting_user, settings_update)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/admin/settings/security/permissions?success=1", status_code=303)


# =============================================================================
# Branding
# =============================================================================


@router.get("/branding", response_class=HTMLResponse)
def admin_branding_redirect(
    request: Request,
):
    """Redirect to branding global tab."""
    return RedirectResponse(url="/admin/settings/branding/global", status_code=303)


@router.get("/branding/global", response_class=HTMLResponse)
def admin_branding_global(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display global branding settings (logos, site title, display mode)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        settings = branding_service.get_branding_settings(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "settings_branding_global.html",
        get_template_context(
            request,
            tenant_id,
            branding_settings=settings,
            success=success,
            error=error,
        ),
    )


@router.get("/branding/groups", response_class=HTMLResponse)
def admin_branding_groups(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display group branding settings (avatar style, per-group logos)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        branding_settings = branding_service.get_branding_settings(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        request,
        "settings_branding_groups.html",
        get_template_context(
            request,
            tenant_id,
            branding_settings=branding_settings,
            success=success,
            error=error,
        ),
    )


@router.post("/branding/global/upload/{slot}")
async def upload_branding_logo(
    request: Request,
    slot: LogoSlot,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    file: UploadFile,
):
    """Upload a logo image for a slot (light or dark)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        data = await file.read()
        branding_service.upload_logo(
            requesting_user,
            slot=slot,
            data=data,
            filename=file.filename,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/global?success=logo_uploaded",
        status_code=303,
    )


@router.post("/branding/global/delete/{slot}")
def delete_branding_logo(
    request: Request,
    slot: LogoSlot,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Delete a logo image for a slot."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        branding_service.delete_logo(requesting_user, slot=slot)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/global?success=logo_deleted",
        status_code=303,
    )


@router.post("/branding/global/settings")
def update_branding_settings(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    logo_mode: Annotated[str, Form()],
    use_logo_as_favicon: Annotated[str, Form()] = "",
    site_title: Annotated[str, Form()] = "",
    show_title_in_nav: Annotated[str, Form()] = "",
):
    """Update global branding display settings (logo mode, favicon, title)."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Retrieve current group_avatar_style to preserve it
    try:
        current = branding_service.get_branding_settings(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    try:
        settings_data = BrandingSettingsUpdate(
            logo_mode=LogoMode(logo_mode),
            use_logo_as_favicon=use_logo_as_favicon == "true",
            site_title=site_title or None,
            show_title_in_nav=show_title_in_nav == "true",
            group_avatar_style=current.group_avatar_style,
        )
    except (ValueError, PydanticValidationError):
        return render_error_page(
            request,
            tenant_id,
            ValidationError(message="Invalid branding settings", code="validation_error"),
        )

    try:
        branding_service.update_branding_settings(requesting_user, settings_data)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/global?success=settings_updated",
        status_code=303,
    )


@router.post("/branding/groups/upload/{group_id}")
async def upload_group_logo_form(
    request: Request,
    group_id: str,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    file: UploadFile,
):
    """Upload a custom logo for a specific group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        data = await file.read()
        branding_service.upload_group_logo(
            requesting_user,
            group_id=group_id,
            data=data,
            filename=file.filename,
        )
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/groups?success=logo_uploaded",
        status_code=303,
    )


@router.post("/branding/groups/delete/{group_id}")
def delete_group_logo_form(
    request: Request,
    group_id: str,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Remove a custom logo from a group."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        branding_service.delete_group_logo(requesting_user, group_id=group_id)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(
        url="/admin/settings/branding/groups?success=logo_deleted",
        status_code=303,
    )
