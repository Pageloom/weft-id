"""Settings routes (privileged domains, security, about)."""

from typing import Annotated, Literal

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
from pydantic import ValidationError as PydanticValidationError
from schemas.settings import (
    DomainGroupLinkCreate,
    PrivilegedDomainCreate,
    TenantSecuritySettingsUpdate,
)
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
    domain: Annotated[str, Form(max_length=253)],
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
    """Display the About WeftID page with version and documentation links."""
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
            inactivity_threshold_days=settings.inactivity_threshold_days,
            max_certificate_lifetime_years=settings.max_certificate_lifetime_years,
            certificate_rotation_window_days=settings.certificate_rotation_window_days,
            minimum_password_length=settings.minimum_password_length,
            minimum_zxcvbn_score=settings.minimum_zxcvbn_score,
            group_assertion_scope=settings.group_assertion_scope,
            require_email_verification_for_login=settings.require_email_verification_for_login,
            required_auth_strength=settings.required_auth_strength,
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


@router.get(
    "/security/authentication",
    response_class=HTMLResponse,
    dependencies=[Depends(require_super_admin)],
)
def admin_security_authentication(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display authentication strength policy tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_authentication.html"
    )


@router.post("/security/authentication/update", dependencies=[Depends(require_super_admin)])
def update_admin_security_authentication(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    required_auth_strength: Annotated[str, Form(max_length=20)] = "baseline",
):
    """Update the tenant authentication strength policy."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    strength: Literal["baseline", "enhanced"]
    if required_auth_strength == "enhanced":
        strength = "enhanced"
    elif required_auth_strength == "baseline":
        strength = "baseline"
    else:
        exc = ValidationError(
            message="Authentication strength must be 'baseline' or 'enhanced'",
            code="invalid_auth_strength",
            field="required_auth_strength",
        )
        return render_error_page(request, tenant_id, exc)

    try:
        settings_update = TenantSecuritySettingsUpdate(required_auth_strength=strength)
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

    return RedirectResponse(
        url="/admin/settings/security/authentication?success=1", status_code=303
    )


@router.post("/security/sessions/update", dependencies=[Depends(require_super_admin)])
def update_admin_security_sessions(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    session_timeout: Annotated[str, Form(max_length=20)] = "",
    persistent_sessions: Annotated[str, Form(max_length=10)] = "",
    inactivity_threshold: Annotated[str, Form(max_length=20)] = "",
    require_email_verification_for_login: Annotated[str, Form(max_length=10)] = "",
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
            require_email_verification_for_login=(require_email_verification_for_login == "true"),
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
    minimum_password_length: Annotated[str, Form(max_length=10)] = "",
    minimum_zxcvbn_score: Annotated[str, Form(max_length=10)] = "",
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
    certificate_lifetime: Annotated[str, Form(max_length=20)] = "",
    rotation_window: Annotated[str, Form(max_length=20)] = "",
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
    allow_users_edit_profile: Annotated[str, Form(max_length=10)] = "",
    group_assertion_scope: Annotated[str, Form(max_length=50)] = "access_relevant",
):
    """Update permission security settings for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Validate scope value; Pydantic will reject invalid values, but
    # we sanitize here to avoid a validation error page for bad form data
    valid_scopes = {"all", "trunk", "access_relevant"}
    scope_value = (
        group_assertion_scope if group_assertion_scope in valid_scopes else "access_relevant"
    )

    try:
        settings_update = TenantSecuritySettingsUpdate(
            allow_users_edit_profile=allow_users_edit_profile == "true",
            group_assertion_scope=scope_value,  # type: ignore[arg-type]
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
