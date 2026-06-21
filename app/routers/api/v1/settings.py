"""Settings API endpoints."""

from typing import Annotated

from api_dependencies import require_admin_api, require_super_admin_api
from dependencies import build_requesting_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends
from schemas.settings import (
    DomainGroupLink,
    DomainGroupLinkCreate,
    PrivilegedDomain,
    PrivilegedDomainCreate,
    TenantAttributeConfigRow,
    TenantAttributeConfigUpdate,
    TenantSecuritySettings,
    TenantSecuritySettingsUpdate,
    VersionInfo,
)
from services import settings as settings_service
from services.exceptions import ServiceError
from utils.service_errors import translate_to_http_exception
from version import __version__

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


# =============================================================================
# Version Info (Admin access)
# =============================================================================


@router.get("/version", response_model=VersionInfo)
def get_version(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
):
    """
    Get the current WeftID version.

    Requires admin role.

    Returns:
        Version information
    """
    return VersionInfo(version=__version__)


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
    requesting_user = build_requesting_user(admin, tenant_id, None)

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
    requesting_user = build_requesting_user(admin, tenant_id, None)

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
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        settings_service.delete_privileged_domain(requesting_user, domain_id)
        return None
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Domain-Group Links (Admin access)
# =============================================================================


@router.get(
    "/privileged-domains/{domain_id}/group-links",
    response_model=list[DomainGroupLink],
)
def list_domain_group_links(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    domain_id: str,
):
    """
    List groups linked to a privileged domain for auto-assignment.

    Requires admin role.

    Path Parameters:
        domain_id: Privileged domain UUID

    Returns:
        List of domain-group links with group names
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        return settings_service.list_domain_group_links(requesting_user, domain_id)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.post(
    "/privileged-domains/{domain_id}/group-links",
    response_model=DomainGroupLink,
    status_code=201,
)
def add_domain_group_link(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    domain_id: str,
    link_data: DomainGroupLinkCreate,
):
    """
    Link a group to a privileged domain for auto-assignment.

    When created, existing users with verified emails matching the domain
    are retroactively added to the group.

    Requires admin role.

    Path Parameters:
        domain_id: Privileged domain UUID

    Request Body:
        group_id: UUID of the WeftID group to link

    Returns:
        The created domain-group link
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        return settings_service.add_domain_group_link(requesting_user, domain_id, link_data)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


@router.delete(
    "/privileged-domains/{domain_id}/group-links/{link_id}",
    status_code=204,
)
def delete_domain_group_link(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    admin: Annotated[dict, Depends(require_admin_api)],
    domain_id: str,
    link_id: str,
):
    """
    Remove a group link from a privileged domain.

    Does not remove existing group memberships.

    Requires admin role.

    Path Parameters:
        domain_id: Privileged domain UUID
        link_id: Domain-group link UUID

    Returns:
        204 No Content on success
    """
    requesting_user = build_requesting_user(admin, tenant_id, None)

    try:
        settings_service.delete_domain_group_link(requesting_user, domain_id, link_id)
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
    requesting_user = build_requesting_user(super_admin, tenant_id, None)

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

    Request Body (all fields optional):
        session_timeout_seconds: Session timeout in seconds (null = indefinite)
        persistent_sessions: Whether sessions persist after browser close
        allow_users_edit_profile: Whether users can edit their own profile
        inactivity_threshold_days: Days of inactivity before auto-inactivation (null = disabled)
        max_certificate_lifetime_years: Lifetime for new signing certs (1, 2, 3, 5, or 10)
        certificate_rotation_window_days: Days before expiry for auto-rotation (14, 30, 60, or 90)
        minimum_password_length: Minimum password length (8, 10, 12, 14, 16, 18, or 20)
        minimum_zxcvbn_score: Minimum zxcvbn strength score (3 or 4)
        group_assertion_scope: Group scope for SAML assertions
        require_email_verification_for_login: Require email verification before login routing
        required_auth_strength: Required sign-in strength ('baseline' or 'enhanced')

    Returns:
        Updated security settings
    """
    requesting_user = build_requesting_user(super_admin, tenant_id, None)

    try:
        return settings_service.update_security_settings(requesting_user, settings_update)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)


# =============================================================================
# Tenant Attribute Configuration (Super-admin only)
# =============================================================================
#
# Mounted under /api/v1/tenant via a separate router so the URL path matches
# the iteration spec while reusing this module's service-layer wiring.


tenant_router = APIRouter(prefix="/api/v1/tenant", tags=["Tenant"])


@tenant_router.get("/attribute-config", response_model=list[TenantAttributeConfigRow])
def list_attribute_config(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    super_admin: Annotated[dict, Depends(require_super_admin_api)],
):
    """
    List the tenant's standard user attribute configuration.

    Returns one row per registered standard attribute (14 total) with all
    five per-attribute toggles. Rows are ordered by category, then by key.

    Requires super_admin role.

    Returns:
        List of attribute config rows
    """
    requesting_user = build_requesting_user(super_admin, tenant_id, None)

    try:
        rows = settings_service.list_tenant_attribute_config(requesting_user)
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    return [
        TenantAttributeConfigRow(
            attribute_key=row["attribute_key"],
            category=row["category"],
            enabled=bool(row["enabled"]),
            required=bool(row["required"]),
            mirror_from_idp=bool(row["mirror_from_idp"]),
            locked_for_users=bool(row["locked_for_users"]),
            send_to_sps_default=bool(row["send_to_sps_default"]),
            allow_self_sourced_to_sp=bool(row["allow_self_sourced_to_sp"]),
            updated_at=row["updated_at"],
        )
        for row in rows
    ]


@tenant_router.put(
    "/attribute-config/{attribute_key}",
    response_model=TenantAttributeConfigRow,
)
def update_attribute_config(
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    super_admin: Annotated[dict, Depends(require_super_admin_api)],
    attribute_key: str,
    payload: TenantAttributeConfigUpdate,
):
    """
    Update one tenant attribute config row.

    Authorization: super_admin only.

    Path Parameters:
        attribute_key: One of the 14 standard attribute keys (e.g., 'job_title').

    Request Body:
        enabled: Attribute is in use by this tenant.
        required: Profile is incomplete without this value.
        mirror_from_idp: When an IdP sends this attribute, copy it into the
            user's profile. Otherwise, the IdP value is shown only as
            read-only info.
        locked_for_users: Only admins can edit this. Users see it read-only.
        send_to_sps_default: Include this attribute in assertions to
            newly-added SPs.
        allow_self_sourced_to_sp: Allow user-edited (self-sourced) values to
            be sent to service providers. Defaults to false; when false, only
            admin- or IdP-sourced values are emitted into signed assertions.

    Returns:
        The updated attribute config row.
    """
    requesting_user = build_requesting_user(super_admin, tenant_id, None)

    try:
        updated = settings_service.update_tenant_attribute_config(
            requesting_user,
            attribute_key,
            enabled=payload.enabled,
            required=payload.required,
            mirror_from_idp=payload.mirror_from_idp,
            locked_for_users=payload.locked_for_users,
            send_to_sps_default=payload.send_to_sps_default,
            allow_self_sourced_to_sp=payload.allow_self_sourced_to_sp,
        )
    except ServiceError as exc:
        raise translate_to_http_exception(exc)

    return TenantAttributeConfigRow(
        attribute_key=updated["attribute_key"],
        category=updated["category"],
        enabled=bool(updated["enabled"]),
        required=bool(updated["required"]),
        mirror_from_idp=bool(updated["mirror_from_idp"]),
        locked_for_users=bool(updated["locked_for_users"]),
        send_to_sps_default=bool(updated["send_to_sps_default"]),
        allow_self_sourced_to_sp=bool(updated["allow_self_sourced_to_sp"]),
        updated_at=updated["updated_at"],
    )
