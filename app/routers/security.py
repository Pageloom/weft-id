"""Security settings routes (sessions, certificates, passwords, permissions, authentication).

Promoted to top-level ``/security`` from ``/admin/settings/security`` as part
of the nav restructure (see ``.claude/ITERATION_nav_restructure.md``). Every
route here is ``super_admin``-only, so the router-level dependency enforces
that directly instead of layering a per-route override on top of a
looser router baseline (as the old ``/admin/settings``-prefixed router did).
"""

from typing import Annotated, Literal

from dependencies import (
    build_requesting_user,
    get_current_user,
    get_tenant_id_from_request,
    require_super_admin,
)
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pages import get_first_accessible_child
from pydantic import ValidationError as PydanticValidationError
from schemas.settings import TenantSecuritySettingsUpdate
from services import settings as settings_service
from services.exceptions import ServiceError, ValidationError
from utils.redirects import safe_redirect
from utils.service_errors import render_error_page
from utils.template_context import get_template_context
from utils.templates import templates

router = APIRouter(
    prefix="/security",
    tags=["security"],
    dependencies=[Depends(require_super_admin)],  # Every route requires super_admin role
    include_in_schema=False,
)


@router.get("/", response_class=HTMLResponse)
@router.get("", response_class=HTMLResponse)
def security_index(
    request: Request,
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible security page."""
    first_child = get_first_accessible_child("/security", user.get("role"))

    return safe_redirect(first_child, default="/dashboard")


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


@router.get("/sessions", response_class=HTMLResponse)
def security_sessions(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display sessions security settings tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_sessions.html"
    )


@router.get("/certificates", response_class=HTMLResponse)
def security_certificates(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display certificates security settings tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_certificates.html"
    )


@router.get("/passwords", response_class=HTMLResponse)
def security_passwords(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display passwords security settings tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_passwords.html"
    )


@router.get("/permissions", response_class=HTMLResponse)
def security_permissions(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display permissions security settings tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_permissions.html"
    )


@router.get("/authentication", response_class=HTMLResponse)
def security_authentication(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display authentication strength policy tab."""
    return _get_security_template_context(
        request, tenant_id, user, "settings_security_tab_authentication.html"
    )


@router.post("/authentication/update")
def update_security_authentication(
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

    return RedirectResponse(url="/security/authentication?success=1", status_code=303)


@router.post("/sessions/update")
def update_security_sessions(
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

    return RedirectResponse(url="/security/sessions?success=1", status_code=303)


@router.post("/passwords/update")
def update_security_passwords(
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

    return RedirectResponse(url="/security/passwords?success=1", status_code=303)


@router.post("/certificates/update")
def update_security_certificates(
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

    return RedirectResponse(url="/security/certificates?success=1", status_code=303)


@router.post("/permissions/update")
def update_security_permissions(
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

    return RedirectResponse(url="/security/permissions?success=1", status_code=303)
