"""Settings service layer.

This module provides business logic for settings operations:
- Privileged domains management
- Tenant security settings

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/settings.py
- Raise ServiceError subclasses on failures
- Have no knowledge of HTTP concepts
"""

import database
from schemas.settings import (
    PrivilegedDomain,
    PrivilegedDomainCreate,
    TenantSecuritySettings,
    TenantSecuritySettingsUpdate,
)
from services.activity import track_activity
from services.event_log import log_event
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser

# =============================================================================
# Authorization Helpers (private)
# =============================================================================


def _require_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not admin or super_admin."""
    if user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )


def _require_super_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not super_admin."""
    if user["role"] != "super_admin":
        raise ForbiddenError(
            message="Super admin access required",
            code="super_admin_required",
            required_role="super_admin",
        )


# =============================================================================
# Domain Validation Helpers (private)
# =============================================================================


def _normalize_domain(domain: str) -> str:
    """Normalize domain input: strip, lowercase, remove @ prefix."""
    domain = domain.strip().lower()
    if domain.startswith("@"):
        domain = domain[1:]
    return domain


def _validate_domain_format(domain: str) -> None:
    """Validate domain format. Raises ValidationError if invalid."""
    if not domain:
        raise ValidationError(
            message="Domain cannot be empty",
            code="invalid_domain",
            field="domain",
        )
    if " " in domain:
        raise ValidationError(
            message="Domain cannot contain spaces",
            code="invalid_domain",
            field="domain",
        )
    if "." not in domain:
        raise ValidationError(
            message="Domain must contain at least one dot",
            code="invalid_domain",
            field="domain",
        )
    if len(domain) < 3 or len(domain) > 253:
        raise ValidationError(
            message="Domain must be 3-253 characters",
            code="invalid_domain_length",
            field="domain",
        )


def _domain_row_to_model(row: dict) -> PrivilegedDomain:
    """Convert database row to PrivilegedDomain model."""
    created_by_name = None
    if row.get("first_name") or row.get("last_name"):
        created_by_name = f"{row.get('first_name', '')} {row.get('last_name', '')}".strip()

    return PrivilegedDomain(
        id=str(row["id"]),
        domain=row["domain"],
        created_at=row["created_at"],
        created_by_name=created_by_name,
        bound_idp_id=str(row["bound_idp_id"]) if row.get("bound_idp_id") else None,
        bound_idp_name=row.get("bound_idp_name"),
    )


# =============================================================================
# Privileged Domains
# =============================================================================


def list_privileged_domains(
    requesting_user: RequestingUser,
) -> list[PrivilegedDomain]:
    """
    List all privileged domains for the tenant.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request

    Returns:
        List of PrivilegedDomain objects

    Raises:
        ForbiddenError: If user lacks admin permissions
    """
    _require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    rows = database.settings.list_privileged_domains(tenant_id)

    return [_domain_row_to_model(row) for row in rows]


def add_privileged_domain(
    requesting_user: RequestingUser,
    domain_data: PrivilegedDomainCreate,
) -> PrivilegedDomain:
    """
    Add a new privileged domain.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        domain_data: The domain to add

    Returns:
        The created PrivilegedDomain

    Raises:
        ForbiddenError: If user lacks admin permissions
        ValidationError: If domain format is invalid
        ConflictError: If domain already exists
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Normalize and validate
    domain_clean = _normalize_domain(domain_data.domain)
    _validate_domain_format(domain_clean)

    # Check for conflicts
    if database.settings.privileged_domain_exists(tenant_id, domain_clean):
        raise ConflictError(
            message=f"Domain '{domain_clean}' already exists",
            code="domain_exists",
            details={"domain": domain_clean},
        )

    # Create the domain
    database.settings.add_privileged_domain(
        tenant_id=tenant_id,
        domain=domain_clean,
        created_by=requesting_user["id"],
        tenant_id_value=tenant_id,
    )

    # Fetch and return the created domain
    rows = database.settings.list_privileged_domains(tenant_id)
    for row in rows:
        if row["domain"] == domain_clean:
            # Log the event
            log_event(
                tenant_id=tenant_id,
                actor_user_id=requesting_user["id"],
                artifact_type="privileged_domain",
                artifact_id=str(row["id"]),
                event_type="privileged_domain_added",
                metadata={"domain": domain_clean},
            )
            return _domain_row_to_model(row)

    # Should not happen, but handle gracefully
    raise ValidationError(
        message="Failed to retrieve created domain",
        code="domain_creation_failed",
    )


def delete_privileged_domain(
    requesting_user: RequestingUser,
    domain_id: str,
) -> None:
    """
    Delete a privileged domain.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        domain_id: UUID of the domain to delete

    Raises:
        ForbiddenError: If user lacks admin permissions
        NotFoundError: If domain does not exist
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify domain exists and capture info for logging
    rows = database.settings.list_privileged_domains(tenant_id)
    domain_row = None
    for row in rows:
        if str(row["id"]) == domain_id:
            domain_row = row
            break

    if not domain_row:
        raise NotFoundError(
            message="Domain not found",
            code="domain_not_found",
            details={"domain_id": domain_id},
        )

    database.settings.delete_privileged_domain(tenant_id, domain_id)

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="privileged_domain",
        artifact_id=domain_id,
        event_type="privileged_domain_deleted",
        metadata={"domain": domain_row["domain"]},
    )


# =============================================================================
# Tenant Security Settings
# =============================================================================


def get_security_settings(
    requesting_user: RequestingUser,
) -> TenantSecuritySettings:
    """
    Get current tenant security settings.

    Authorization: Requires super_admin role.

    Args:
        requesting_user: The authenticated user making the request

    Returns:
        TenantSecuritySettings with current values (or defaults)

    Raises:
        ForbiddenError: If user lacks super_admin permissions
    """
    _require_super_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    settings = database.security.get_security_settings(tenant_id)

    if not settings:
        # Return defaults when no settings exist
        return TenantSecuritySettings(
            session_timeout_seconds=None,
            persistent_sessions=True,
            allow_users_edit_profile=True,
            allow_users_add_emails=True,
            inactivity_threshold_days=None,
        )

    return TenantSecuritySettings(
        session_timeout_seconds=settings.get("session_timeout_seconds"),
        persistent_sessions=settings.get("persistent_sessions", True),
        allow_users_edit_profile=settings.get("allow_users_edit_profile", True),
        allow_users_add_emails=settings.get("allow_users_add_emails", True),
        inactivity_threshold_days=settings.get("inactivity_threshold_days"),
    )


def get_privileged_domains_list(tenant_id: str) -> list[str]:
    """
    Get list of privileged domain names for a tenant.

    This is a utility function that does not require authorization,
    intended for use by other services (e.g., when creating users).

    Args:
        tenant_id: The tenant ID

    Returns:
        List of domain strings (e.g., ["example.com", "corp.example.com"])
    """
    rows = database.settings.list_privileged_domains(tenant_id)
    return [row["domain"] for row in rows]


def is_privileged_domain(tenant_id: str, domain: str) -> bool:
    """
    Check if a domain is privileged for the tenant.

    This is a utility function that does not require authorization.

    Args:
        tenant_id: The tenant ID
        domain: Domain to check

    Returns:
        True if domain is privileged, False otherwise
    """
    return database.settings.privileged_domain_exists(tenant_id, domain.lower())


def can_users_add_emails(tenant_id: str) -> bool:
    """
    Check if users are allowed to add email addresses.

    This is a utility function that does not require authorization.

    Args:
        tenant_id: The tenant ID

    Returns:
        True if users can add emails, False otherwise
    """
    settings = database.security.get_security_settings(tenant_id)
    if not settings:
        return True  # Default to allowing
    return bool(settings.get("allow_users_add_emails", True))


def get_session_settings(tenant_id: str) -> dict | None:
    """
    Get session settings for a tenant.

    This is a utility function without authorization - used during
    login/MFA flows to configure session behavior.

    Args:
        tenant_id: Tenant ID

    Returns:
        Dict with session_timeout_seconds and persistent_sessions, or None
    """
    return database.security.get_session_settings(tenant_id)


def can_user_edit_profile(tenant_id: str) -> bool:
    """
    Check if users are allowed to edit their own profile.

    This is a utility function that does not require authorization.

    Args:
        tenant_id: The tenant ID

    Returns:
        True if users can edit profile, False otherwise
    """
    settings = database.security.get_security_settings(tenant_id)
    if not settings:
        return True  # Default to allowing
    return bool(settings.get("allow_users_edit_profile", True))


def get_inactivity_threshold(tenant_id: str) -> int | None:
    """
    Get the inactivity threshold in days for a tenant.

    This is a utility function that does not require authorization.

    Args:
        tenant_id: The tenant ID

    Returns:
        Number of days before auto-inactivation, or None if disabled
    """
    return database.security.get_inactivity_threshold(tenant_id)


def update_security_settings(
    requesting_user: RequestingUser,
    settings_update: TenantSecuritySettingsUpdate,
) -> TenantSecuritySettings:
    """
    Update tenant security settings.

    Authorization: Requires super_admin role.

    Args:
        requesting_user: The authenticated user making the request
        settings_update: Fields to update (None = keep existing)

    Returns:
        Updated TenantSecuritySettings

    Raises:
        ForbiddenError: If user lacks super_admin permissions
        ValidationError: If validation fails (e.g., negative timeout)
    """
    _require_super_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Validate timeout if provided
    if (
        settings_update.session_timeout_seconds is not None
        and settings_update.session_timeout_seconds <= 0
    ):
        raise ValidationError(
            message="Session timeout must be positive",
            code="invalid_timeout",
            field="session_timeout_seconds",
        )

    # Get current settings to merge
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
    inactivity_days = (
        settings_update.inactivity_threshold_days
        if settings_update.inactivity_threshold_days is not None
        else current.get("inactivity_threshold_days")
    )

    # Build changes metadata for logging
    changes: dict = {}
    if settings_update.session_timeout_seconds is not None:
        changes["session_timeout_seconds"] = {
            "old": current.get("session_timeout_seconds"),
            "new": timeout,
        }
    if settings_update.persistent_sessions is not None:
        changes["persistent_sessions"] = {
            "old": current.get("persistent_sessions", True),
            "new": persistent,
        }
    if settings_update.allow_users_edit_profile is not None:
        changes["allow_users_edit_profile"] = {
            "old": current.get("allow_users_edit_profile", True),
            "new": allow_edit,
        }
    if settings_update.allow_users_add_emails is not None:
        changes["allow_users_add_emails"] = {
            "old": current.get("allow_users_add_emails", True),
            "new": allow_emails,
        }
    if settings_update.inactivity_threshold_days is not None:
        changes["inactivity_threshold_days"] = {
            "old": current.get("inactivity_threshold_days"),
            "new": inactivity_days,
        }

    # Update in database
    database.security.update_security_settings(
        tenant_id=tenant_id,
        timeout_seconds=timeout,
        persistent_sessions=persistent,
        allow_users_edit_profile=allow_edit,
        allow_users_add_emails=allow_emails,
        inactivity_threshold_days=inactivity_days,
        updated_by=requesting_user["id"],
        tenant_id_value=tenant_id,
    )

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="tenant_settings",
        artifact_id=tenant_id,
        event_type="tenant_settings_updated",
        metadata={"changes": changes} if changes else None,
    )

    return TenantSecuritySettings(
        session_timeout_seconds=timeout,
        persistent_sessions=persistent,
        allow_users_edit_profile=allow_edit,
        allow_users_add_emails=allow_emails,
        inactivity_threshold_days=inactivity_days,
    )
