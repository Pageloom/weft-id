"""Settings API endpoints."""

from typing import Annotated

import database
from api_dependencies import require_admin_api, require_super_admin_api
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, HTTPException
from schemas.settings import (
    PrivilegedDomain,
    PrivilegedDomainCreate,
    TenantSecuritySettings,
    TenantSecuritySettingsUpdate,
)

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


# =============================================================================
# Privileged Domains (Admin access)
# =============================================================================


def _domain_to_response(domain: dict) -> PrivilegedDomain:
    """Convert database domain dict to PrivilegedDomain schema."""
    created_by_name = None
    if domain.get("first_name") or domain.get("last_name"):
        created_by_name = f"{domain.get('first_name', '')} {domain.get('last_name', '')}".strip()

    return PrivilegedDomain(
        id=str(domain["id"]),
        domain=domain["domain"],
        created_at=domain["created_at"],
        created_by_name=created_by_name,
    )


@router.get("/privileged-domains", response_model=list[PrivilegedDomain])
def list_privileged_domains(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """
    List all privileged domains for the tenant.

    Requires admin role.

    Returns:
        List of privileged domains with metadata
    """
    domains = database.settings.list_privileged_domains(tenant_id)
    return [_domain_to_response(d) for d in domains]


@router.post("/privileged-domains", response_model=PrivilegedDomain, status_code=201)
def add_privileged_domain(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    domain_data: PrivilegedDomainCreate,
):
    """
    Add a new privileged domain.

    Requires admin role.

    Request Body:
        domain: Domain to add (e.g., 'company.com')

    Returns:
        The created privileged domain
    """
    # Clean and validate domain
    domain_clean = domain_data.domain.strip().lower()

    # Remove @ prefix if present
    if domain_clean.startswith("@"):
        domain_clean = domain_clean[1:]

    # Validate domain format
    if not domain_clean or " " in domain_clean or "." not in domain_clean:
        raise HTTPException(status_code=400, detail="Invalid domain format")

    if len(domain_clean) < 3 or len(domain_clean) > 253:
        raise HTTPException(status_code=400, detail="Domain must be 3-253 characters")

    # Check if domain already exists
    if database.settings.privileged_domain_exists(tenant_id, domain_clean):
        raise HTTPException(status_code=409, detail="Domain already exists")

    # Add the domain
    database.settings.add_privileged_domain(
        tenant_id=tenant_id,
        domain=domain_clean,
        created_by=str(admin["id"]),
        tenant_id_value=tenant_id,
    )

    # Fetch the created domain to return it
    domains = database.settings.list_privileged_domains(tenant_id)
    for d in domains:
        if d["domain"] == domain_clean:
            return _domain_to_response(d)

    raise HTTPException(status_code=500, detail="Failed to retrieve created domain")


@router.delete("/privileged-domains/{domain_id}", status_code=204)
def delete_privileged_domain(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    domain_id: str,
):
    """
    Delete a privileged domain.

    Requires admin role.

    Path Parameters:
        domain_id: Domain UUID

    Returns:
        204 No Content on success
    """
    # Check if domain exists first
    domains = database.settings.list_privileged_domains(tenant_id)
    domain_exists = any(str(d["id"]) == domain_id for d in domains)

    if not domain_exists:
        raise HTTPException(status_code=404, detail="Domain not found")

    database.settings.delete_privileged_domain(tenant_id, domain_id)

    return None


# =============================================================================
# Tenant Security Settings (Super-admin only)
# =============================================================================


@router.get("/tenant-security", response_model=TenantSecuritySettings)
def get_tenant_security(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    super_admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """
    Get current tenant security settings.

    Requires super_admin role.

    Returns:
        Current security settings
    """
    settings = database.security.get_security_settings(tenant_id)

    if not settings:
        # Return defaults if no settings exist
        return TenantSecuritySettings()

    return TenantSecuritySettings(
        session_timeout_seconds=settings.get("session_timeout_seconds"),
        persistent_sessions=settings.get("persistent_sessions", True),
        allow_users_edit_profile=settings.get("allow_users_edit_profile", True),
        allow_users_add_emails=settings.get("allow_users_add_emails", True),
    )


@router.patch("/tenant-security", response_model=TenantSecuritySettings)
def update_tenant_security(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    super_admin: Annotated[dict, Depends(require_super_admin_api)],
    settings_update: TenantSecuritySettingsUpdate,
):
    """
    Update tenant security settings.

    Requires super_admin role.

    Request Body:
        session_timeout_seconds: Session timeout in seconds (null = indefinite)
        persistent_sessions: Whether sessions persist after browser close
        allow_users_edit_profile: Whether users can edit their own profile
        allow_users_add_emails: Whether users can add alternative email addresses

    Returns:
        Updated security settings
    """
    # Get current settings to merge with updates
    current = database.security.get_security_settings(tenant_id) or {}

    # Merge updates with current values
    timeout = (
        settings_update.session_timeout_seconds
        if settings_update.session_timeout_seconds is not None
        else current.get("session_timeout_seconds")
    )
    persistent = (
        settings_update.persistent_sessions
        if settings_update.persistent_sessions is not None
        else current.get("persistent_sessions", True)
    )
    allow_edit = (
        settings_update.allow_users_edit_profile
        if settings_update.allow_users_edit_profile is not None
        else current.get("allow_users_edit_profile", True)
    )
    allow_emails = (
        settings_update.allow_users_add_emails
        if settings_update.allow_users_add_emails is not None
        else current.get("allow_users_add_emails", True)
    )

    # Update settings
    database.security.update_security_settings(
        tenant_id=tenant_id,
        timeout_seconds=timeout,
        persistent_sessions=persistent,
        allow_users_edit_profile=allow_edit,
        allow_users_add_emails=allow_emails,
        updated_by=str(super_admin["id"]),
        tenant_id_value=tenant_id,
    )

    # Return updated settings
    return TenantSecuritySettings(
        session_timeout_seconds=timeout,
        persistent_sessions=persistent,
        allow_users_edit_profile=allow_edit,
        allow_users_add_emails=allow_emails,
    )
