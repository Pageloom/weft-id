"""Tenant security settings management.

Handles reading, updating, and utility queries for tenant-level
security settings (sessions, passwords, certificates, permissions).
"""

from typing import Any

import database
from schemas.settings import (
    TenantSecuritySettings,
    TenantSecuritySettingsUpdate,
)
from services.activity import track_activity
from services.auth import require_super_admin
from services.event_log import log_event
from services.exceptions import ValidationError
from services.types import RequestingUser

# Field definitions for merge/changes logic.
# Each tuple: (update_attr, db_key, default_value)
_SETTINGS_FIELDS: list[tuple[str, str, Any]] = [
    ("session_timeout_seconds", "session_timeout_seconds", None),
    ("persistent_sessions", "persistent_sessions", True),
    ("allow_users_edit_profile", "allow_users_edit_profile", True),
    ("allow_users_add_emails", "allow_users_add_emails", True),
    ("inactivity_threshold_days", "inactivity_threshold_days", None),
    ("max_certificate_lifetime_years", "max_certificate_lifetime_years", 10),
    ("certificate_rotation_window_days", "certificate_rotation_window_days", 90),
    ("minimum_password_length", "minimum_password_length", 14),
    ("minimum_zxcvbn_score", "minimum_zxcvbn_score", 3),
    ("group_assertion_scope", "group_assertion_scope", "access_relevant"),
]


def _merge_security_update(
    current: dict,
    update: TenantSecuritySettingsUpdate,
) -> dict[str, Any]:
    """Merge an update into current settings, keeping existing values for unset fields.

    Returns a dict keyed by field name with the resolved values.
    """
    resolved: dict[str, Any] = {}
    for attr, db_key, default in _SETTINGS_FIELDS:
        update_value = getattr(update, attr)
        if update_value is not None:
            resolved[attr] = update_value
        else:
            resolved[attr] = current.get(db_key, default)
    return resolved


def _build_changes_metadata(
    current: dict,
    update: TenantSecuritySettingsUpdate,
    resolved: dict[str, Any],
) -> dict:
    """Build an old/new changes dict for fields that were explicitly set in the update."""
    changes: dict = {}
    for attr, db_key, default in _SETTINGS_FIELDS:
        if getattr(update, attr) is not None:
            changes[attr] = {
                "old": current.get(db_key, default),
                "new": resolved[attr],
            }
    return changes


# =============================================================================
# Read Operations
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
    require_super_admin(requesting_user)
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
            max_certificate_lifetime_years=10,
            certificate_rotation_window_days=90,
            minimum_password_length=14,
            minimum_zxcvbn_score=3,
            group_assertion_scope="access_relevant",
        )

    return TenantSecuritySettings(
        session_timeout_seconds=settings.get("session_timeout_seconds"),
        persistent_sessions=settings.get("persistent_sessions", True),
        allow_users_edit_profile=settings.get("allow_users_edit_profile", True),
        allow_users_add_emails=settings.get("allow_users_add_emails", True),
        inactivity_threshold_days=settings.get("inactivity_threshold_days"),
        max_certificate_lifetime_years=settings.get("max_certificate_lifetime_years", 10),
        certificate_rotation_window_days=settings.get("certificate_rotation_window_days", 90),
        minimum_password_length=settings.get("minimum_password_length", 14),
        minimum_zxcvbn_score=settings.get("minimum_zxcvbn_score", 3),
        group_assertion_scope=settings.get("group_assertion_scope", "access_relevant"),
    )


# =============================================================================
# Utility Queries (no authorization required)
# =============================================================================


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


def get_certificate_lifetime(tenant_id: str) -> int:
    """
    Get the certificate lifetime in years for a tenant.

    This is a utility function that does not require authorization,
    intended for use by certificate generation code.

    Args:
        tenant_id: The tenant ID

    Returns:
        Number of years for new certificate validity (default 10)
    """
    return database.security.get_certificate_lifetime(tenant_id)


def get_certificate_rotation_window(tenant_id: str) -> int:
    """
    Get the certificate rotation window in days for a tenant.

    This is a utility function that does not require authorization,
    intended for use by the background rotation job.

    Args:
        tenant_id: The tenant ID

    Returns:
        Number of days for rotation window (default 90)
    """
    return database.security.get_certificate_rotation_window(tenant_id)


def get_password_policy(tenant_id: str) -> dict:
    """
    Get password policy for a tenant.

    This is a utility function without authorization, intended for
    unauthenticated flows (onboarding, password reset).

    Args:
        tenant_id: The tenant ID

    Returns:
        Dict with minimum_password_length and minimum_zxcvbn_score
    """
    result = database.security.get_password_policy(tenant_id)
    if not result:
        return {"minimum_password_length": 14, "minimum_zxcvbn_score": 3}
    return {
        "minimum_password_length": result.get("minimum_password_length", 14),
        "minimum_zxcvbn_score": result.get("minimum_zxcvbn_score", 3),
    }


def get_group_assertion_scope(tenant_id: str) -> str:
    """
    Get the group assertion scope for a tenant.

    Utility function without authorization, intended for use by the SSO
    flow and SP attribute templates.

    Args:
        tenant_id: The tenant ID

    Returns:
        Scope string ('all', 'trunk', or 'access_relevant')
    """
    return database.security.get_group_assertion_scope(tenant_id)


# =============================================================================
# Update Operation
# =============================================================================


def _enforce_password_policy_compliance(
    tenant_id: str,
    actor_user_id: str,
    new_min_length: int,
    new_min_score: int,
) -> int:
    """Flag users whose passwords were set under a weaker policy.

    When an admin tightens the password policy, users whose stored
    password_policy_*_at_set values are weaker than the new policy
    are flagged for forced reset. Their OAuth2 tokens are also revoked.

    Args:
        tenant_id: Tenant ID
        actor_user_id: Admin who changed the policy
        new_min_length: New minimum password length
        new_min_score: New minimum zxcvbn score

    Returns:
        Number of users flagged
    """
    non_compliant = database.users.get_users_with_weak_policy(
        tenant_id, new_min_length, new_min_score
    )
    if not non_compliant:
        return 0

    user_ids = [str(u["id"]) for u in non_compliant]
    database.users.bulk_set_password_reset_required(tenant_id, user_ids)

    # Revoke OAuth2 tokens for all affected users
    for uid in user_ids:
        database.oauth2.revoke_all_user_tokens(tenant_id, uid)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        event_type="password_policy_compliance_enforced",
        artifact_type="tenant_settings",
        artifact_id=tenant_id,
        metadata={
            "affected_users": len(user_ids),
            "new_minimum_password_length": new_min_length,
            "new_minimum_zxcvbn_score": new_min_score,
        },
    )

    return len(user_ids)


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
    require_super_admin(requesting_user)

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

    # Get current settings and merge
    current = database.security.get_security_settings(tenant_id) or {}
    resolved = _merge_security_update(current, settings_update)
    changes = _build_changes_metadata(current, settings_update, resolved)

    # Update in database
    database.security.update_security_settings(
        tenant_id=tenant_id,
        timeout_seconds=resolved["session_timeout_seconds"],
        persistent_sessions=resolved["persistent_sessions"],
        allow_users_edit_profile=resolved["allow_users_edit_profile"],
        allow_users_add_emails=resolved["allow_users_add_emails"],
        inactivity_threshold_days=resolved["inactivity_threshold_days"],
        max_certificate_lifetime_years=resolved["max_certificate_lifetime_years"],
        certificate_rotation_window_days=resolved["certificate_rotation_window_days"],
        minimum_password_length=resolved["minimum_password_length"],
        minimum_zxcvbn_score=resolved["minimum_zxcvbn_score"],
        group_assertion_scope=resolved["group_assertion_scope"],
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

    # Log dedicated event when certificate lifetime changes
    if settings_update.max_certificate_lifetime_years is not None:
        old_lifetime = current.get("max_certificate_lifetime_years", 10)
        if old_lifetime != resolved["max_certificate_lifetime_years"]:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=requesting_user["id"],
                artifact_type="tenant_settings",
                artifact_id=tenant_id,
                event_type="tenant_certificate_lifetime_updated",
                metadata={
                    "old_years": old_lifetime,
                    "new_years": resolved["max_certificate_lifetime_years"],
                },
            )

    # Log dedicated event when rotation window changes
    if settings_update.certificate_rotation_window_days is not None:
        old_window = current.get("certificate_rotation_window_days", 90)
        if old_window != resolved["certificate_rotation_window_days"]:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=requesting_user["id"],
                artifact_type="tenant_settings",
                artifact_id=tenant_id,
                event_type="tenant_certificate_rotation_window_updated",
                metadata={
                    "old_days": old_window,
                    "new_days": resolved["certificate_rotation_window_days"],
                },
            )

    # Log dedicated event when password policy changes
    pw_policy_changed = False
    old_pw_length = current.get("minimum_password_length", 14)
    old_pw_score = current.get("minimum_zxcvbn_score", 3)
    if settings_update.minimum_password_length is not None:
        if old_pw_length != resolved["minimum_password_length"]:
            pw_policy_changed = True
    if settings_update.minimum_zxcvbn_score is not None:
        if old_pw_score != resolved["minimum_zxcvbn_score"]:
            pw_policy_changed = True
    if pw_policy_changed:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="tenant_settings",
            artifact_id=tenant_id,
            event_type="password_policy_updated",
            metadata={
                "minimum_password_length": resolved["minimum_password_length"],
                "minimum_zxcvbn_score": resolved["minimum_zxcvbn_score"],
            },
        )

        # Enforce policy compliance: flag users whose passwords were set
        # under a weaker policy and require them to reset.
        policy_tightened = (
            resolved["minimum_password_length"] > old_pw_length
            or resolved["minimum_zxcvbn_score"] > old_pw_score
        )
        if policy_tightened:
            _enforce_password_policy_compliance(
                tenant_id=tenant_id,
                actor_user_id=requesting_user["id"],
                new_min_length=resolved["minimum_password_length"],
                new_min_score=resolved["minimum_zxcvbn_score"],
            )

    # Log dedicated event when group assertion scope changes
    if settings_update.group_assertion_scope is not None:
        old_scope = current.get("group_assertion_scope", "access_relevant")
        if old_scope != resolved["group_assertion_scope"]:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=requesting_user["id"],
                artifact_type="tenant_settings",
                artifact_id=tenant_id,
                event_type="group_assertion_scope_updated",
                metadata={
                    "old_scope": old_scope,
                    "new_scope": resolved["group_assertion_scope"],
                },
            )

    return TenantSecuritySettings(
        session_timeout_seconds=resolved["session_timeout_seconds"],
        persistent_sessions=resolved["persistent_sessions"],
        allow_users_edit_profile=resolved["allow_users_edit_profile"],
        allow_users_add_emails=resolved["allow_users_add_emails"],
        inactivity_threshold_days=resolved["inactivity_threshold_days"],
        max_certificate_lifetime_years=resolved["max_certificate_lifetime_years"],
        certificate_rotation_window_days=resolved["certificate_rotation_window_days"],
        minimum_password_length=resolved["minimum_password_length"],
        minimum_zxcvbn_score=resolved["minimum_zxcvbn_score"],
        group_assertion_scope=resolved["group_assertion_scope"],
    )
