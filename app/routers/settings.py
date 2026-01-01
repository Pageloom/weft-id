"""Settings routes (privileged domains)."""

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
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child
from pydantic import ValidationError as PydanticValidationError
from schemas.settings import PrivilegedDomainCreate, TenantSecuritySettingsUpdate
from services import settings as settings_service
from services.exceptions import ServiceError, ValidationError
from utils.service_errors import render_error_page
from utils.template_context import get_template_context

router = APIRouter(
    prefix="/admin",
    tags=["admin-settings"],
    dependencies=[Depends(require_admin)],  # All routes require admin role
    include_in_schema=False,
)
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
def admin_settings_index(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Redirect to the first accessible admin page."""
    # Get first accessible child page
    first_child = get_first_accessible_child("/admin", user.get("role"))

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
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "settings_privileged_domains.html",
        get_template_context(request, tenant_id, domains=domains, error=error),
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

    return RedirectResponse(url="/admin/privileged-domains", status_code=303)


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

    return RedirectResponse(url="/admin/privileged-domains", status_code=303)


@router.get("/security", response_class=HTMLResponse, dependencies=[Depends(require_super_admin)])
def admin_security(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
):
    """Display security settings for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    try:
        settings = settings_service.get_security_settings(requesting_user)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "settings_tenant_security.html",
        get_template_context(
            request,
            tenant_id,
            current_timeout=settings.session_timeout_seconds,
            persistent_sessions=settings.persistent_sessions,
            allow_users_edit_profile=settings.allow_users_edit_profile,
            allow_users_add_emails=settings.allow_users_add_emails,
            success=success,
            error=error,
        ),
    )


@router.post("/security/update", dependencies=[Depends(require_super_admin)])
def update_admin_security(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(get_current_user)],
    session_timeout: Annotated[str, Form()] = "",
    persistent_sessions: Annotated[str, Form()] = "",
    allow_users_edit_profile: Annotated[str, Form()] = "",
    allow_users_add_emails: Annotated[str, Form()] = "",
):
    """Update security settings for the tenant."""
    requesting_user = build_requesting_user(user, tenant_id, request)

    # Parse session timeout (empty string means indefinite/NULL)
    timeout_seconds: int | None = None
    if session_timeout:
        try:
            timeout_seconds = int(session_timeout)
            if timeout_seconds <= 0:
                # Invalid timeout - show error page
                exc = ValidationError(
                    message="Session timeout must be positive",
                    code="invalid_timeout",
                    field="session_timeout_seconds",
                )
                return render_error_page(request, tenant_id, exc)
        except ValueError:
            # Non-numeric value - show error page
            exc = ValidationError(
                message="Session timeout must be a number",
                code="invalid_timeout",
                field="session_timeout_seconds",
            )
            return render_error_page(request, tenant_id, exc)

    # Parse checkboxes (checked = "true", unchecked = "")
    try:
        settings_update = TenantSecuritySettingsUpdate(
            session_timeout_seconds=timeout_seconds,
            persistent_sessions=persistent_sessions == "true",
            allow_users_edit_profile=allow_users_edit_profile == "true",
            allow_users_add_emails=allow_users_add_emails == "true",
        )
    except PydanticValidationError as e:
        # Convert Pydantic validation error to service error
        exc = ValidationError(
            message=str(e.errors()[0]["msg"]) if e.errors() else "Invalid input",
            code="validation_error",
        )
        return render_error_page(request, tenant_id, exc)

    try:
        settings_service.update_security_settings(requesting_user, settings_update)
    except ServiceError as exc:
        return render_error_page(request, tenant_id, exc)

    return RedirectResponse(url="/admin/security?success=1", status_code=303)
