"""Settings API endpoints."""

from typing import Annotated

from api_dependencies import require_admin_api, require_super_admin_api
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends
from schemas.settings import (
    PrivilegedDomain,
    PrivilegedDomainCreate,
    TenantSecuritySettings,
    TenantSecuritySettingsUpdate,
)
from services import settings as settings_service
from services.exceptions import ServiceError
from services.types import RequestingUser
from utils.service_errors import translate_to_http_exception

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


def _to_requesting_user(user: dict, tenant_id: str) -> RequestingUser:
    """Convert route user dict to RequestingUser for service layer."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=user.get("role", "user"),
    )


# =============================================================================
# Privileged Domains (Admin access)
# =============================================================================


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
    requesting_user = _to_requesting_user(admin, tenant_id)

    try:
        return settings_service.list_privileged_domains(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    requesting_user = _to_requesting_user(admin, tenant_id)

    try:
        return settings_service.add_privileged_domain(requesting_user, domain_data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    requesting_user = _to_requesting_user(admin, tenant_id)

    try:
        settings_service.delete_privileged_domain(requesting_user, domain_id)
        return None
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    requesting_user = _to_requesting_user(super_admin, tenant_id)

    try:
        return settings_service.get_security_settings(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


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
    requesting_user = _to_requesting_user(super_admin, tenant_id)

    try:
        return settings_service.update_security_settings(requesting_user, settings_update)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)
