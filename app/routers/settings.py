"""Settings routes (privileged domains)."""

from typing import Annotated

import database
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pages import get_first_accessible_child, has_page_access
from utils.auth import get_current_user
from utils.template_context import get_template_context

router = APIRouter(prefix="/settings", tags=["settings"])
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
def settings_index(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Redirect to the first accessible settings page."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if user has permission to access settings
    if not has_page_access("/settings", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Get first accessible child page
    first_child = get_first_accessible_child("/settings", user.get("role"))

    if first_child:
        return RedirectResponse(url=first_child, status_code=303)

    # Fallback if no accessible children (shouldn't happen)
    return RedirectResponse(url="/dashboard", status_code=303)


@router.get("/privileged-domains", response_class=HTMLResponse)
def privileged_domains(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Display and manage privileged domains for the tenant."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if user has permission to access this page
    if not has_page_access("/settings/privileged-domains", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Fetch all privileged domains for this tenant
    domains = database.fetchall(
        tenant_id,
        """
        select pd.id, pd.domain, pd.created_at, u.first_name, u.last_name
        from tenant_privileged_domains pd
        left join users u on pd.created_by = u.id
        order by pd.created_at desc
        """,
    )

    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "settings_privileged_domains.html",
        get_template_context(request, tenant_id, domains=domains, error=error),
    )


@router.post("/privileged-domains/add")
def add_privileged_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    domain: Annotated[str, Form()],
):
    """Add a new privileged domain."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if user has permission to manage privileged domains
    if not has_page_access("/settings/privileged-domains", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Clean and validate domain
    domain_clean = domain.strip().lower()

    # Remove @ prefix if present
    if domain_clean.startswith("@"):
        domain_clean = domain_clean[1:]

    # Basic validation: must contain a dot, no spaces, reasonable length
    if (
        not domain_clean
        or " " in domain_clean
        or "." not in domain_clean
        or len(domain_clean) > 253
        or len(domain_clean) < 3
    ):
        return RedirectResponse(
            url="/settings/privileged-domains?error=invalid_domain", status_code=303
        )

    # Check if domain already exists for this tenant
    existing = database.fetchone(
        tenant_id,
        "select id from tenant_privileged_domains where domain = :domain",
        {"domain": domain_clean},
    )

    if existing:
        return RedirectResponse(
            url="/settings/privileged-domains?error=domain_exists", status_code=303
        )

    # Insert the new privileged domain
    database.execute(
        tenant_id,
        """
        insert into tenant_privileged_domains (tenant_id, domain, created_by)
        values (:tenant_id, :domain, :created_by)
        """,
        {"tenant_id": tenant_id, "domain": domain_clean, "created_by": user["id"]},
    )

    return RedirectResponse(url="/settings/privileged-domains", status_code=303)


@router.post("/privileged-domains/delete/{domain_id}")
def delete_privileged_domain(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    domain_id: str,
):
    """Delete a privileged domain."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if user has permission to manage privileged domains
    if not has_page_access("/settings/privileged-domains", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Delete the domain (RLS ensures it belongs to this tenant)
    database.execute(
        tenant_id,
        "delete from tenant_privileged_domains where id = :domain_id",
        {"domain_id": domain_id},
    )

    return RedirectResponse(url="/settings/privileged-domains", status_code=303)


@router.get("/tenant-security", response_class=HTMLResponse)
def tenant_security(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Display security settings for the tenant."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if user has permission to access this page (super_admin only)
    if not has_page_access("/settings/tenant-security", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Fetch current security settings for this tenant
    settings_row = database.fetchone(
        tenant_id,
        """
        select session_timeout_seconds, persistent_sessions,
               allow_users_edit_profile, allow_users_add_emails
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )

    current_timeout = settings_row["session_timeout_seconds"] if settings_row else None
    persistent_sessions = settings_row["persistent_sessions"] if settings_row else True
    allow_users_edit_profile = settings_row["allow_users_edit_profile"] if settings_row else True
    allow_users_add_emails = settings_row["allow_users_add_emails"] if settings_row else True
    success = request.query_params.get("success")
    error = request.query_params.get("error")

    return templates.TemplateResponse(
        "settings_tenant_security.html",
        get_template_context(
            request,
            tenant_id,
            current_timeout=current_timeout,
            persistent_sessions=persistent_sessions,
            allow_users_edit_profile=allow_users_edit_profile,
            allow_users_add_emails=allow_users_add_emails,
            success=success,
            error=error,
        ),
    )


@router.post("/tenant-security/update")
def update_tenant_security(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    session_timeout: Annotated[str, Form()] = "",
    persistent_sessions: Annotated[str, Form()] = "",
    allow_users_edit_profile: Annotated[str, Form()] = "",
    allow_users_add_emails: Annotated[str, Form()] = "",
):
    """Update security settings for the tenant."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Check if user has permission to manage security settings (super_admin only)
    if not has_page_access("/settings/tenant-security", user.get("role")):
        return RedirectResponse(url="/dashboard", status_code=303)

    # Parse session timeout (empty string means indefinite/NULL)
    timeout_seconds = None
    if session_timeout:
        try:
            timeout_seconds = int(session_timeout)
            if timeout_seconds <= 0:
                return RedirectResponse(
                    url="/settings/tenant-security?error=invalid_timeout", status_code=303
                )
        except ValueError:
            return RedirectResponse(
                url="/settings/tenant-security?error=invalid_timeout", status_code=303
            )

    # Parse persistent_sessions checkbox (checked = "true", unchecked = "")
    persistent = persistent_sessions == "true"

    # Parse user permission checkboxes (checked = "true", unchecked = "")
    allow_edit_profile = allow_users_edit_profile == "true"
    allow_add_emails = allow_users_add_emails == "true"

    # Upsert the security settings
    database.execute(
        tenant_id,
        """
        insert into tenant_security_settings (
            tenant_id, session_timeout_seconds, persistent_sessions,
            allow_users_edit_profile, allow_users_add_emails, updated_by
        )
        values (
            :tenant_id, :timeout_seconds, :persistent_sessions,
            :allow_users_edit_profile, :allow_users_add_emails, :updated_by
        )
        on conflict (tenant_id)
        do update set
            session_timeout_seconds = :timeout_seconds,
            persistent_sessions = :persistent_sessions,
            allow_users_edit_profile = :allow_users_edit_profile,
            allow_users_add_emails = :allow_users_add_emails,
            updated_at = now(),
            updated_by = :updated_by
        """,
        {
            "tenant_id": tenant_id,
            "timeout_seconds": timeout_seconds,
            "persistent_sessions": persistent,
            "allow_users_edit_profile": allow_edit_profile,
            "allow_users_add_emails": allow_add_emails,
            "updated_by": user["id"],
        },
    )

    return RedirectResponse(url="/settings/tenant-security?success=1", status_code=303)
