"""Settings routes (privileged domains - super admin only)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import database
from dependencies import get_tenant_id_from_request
from pages import get_first_accessible_child
from utils.auth import get_current_user
from utils.template_context import get_template_context

router = APIRouter(prefix="/settings", tags=["settings"])
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
def settings_index(
    request: Request, tenant_id: Annotated[str, Depends(get_tenant_id_from_request)]
):
    """Redirect to first accessible settings page."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Only super admins can access settings
    if user.get("role") != "super_admin":
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
    """Display and manage privileged domains for the tenant (super admin only)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Only super admins can access this page
    if user.get("role") != "super_admin":
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
    """Add a new privileged domain (super admin only)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Only super admins can manage privileged domains
    if user.get("role") != "super_admin":
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
    """Delete a privileged domain (super admin only)."""
    user = get_current_user(request, tenant_id)

    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # Only super admins can manage privileged domains
    if user.get("role") != "super_admin":
        return RedirectResponse(url="/dashboard", status_code=303)

    # Delete the domain (RLS ensures it belongs to this tenant)
    database.execute(
        tenant_id,
        "delete from tenant_privileged_domains where id = :domain_id",
        {"domain_id": domain_id},
    )

    return RedirectResponse(url="/settings/privileged-domains", status_code=303)
