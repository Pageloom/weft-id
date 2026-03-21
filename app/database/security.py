"""Security settings database operations."""

from ._core import UNSCOPED, TenantArg, execute, fetchall, fetchone


def get_security_settings(tenant_id: TenantArg) -> dict | None:
    """
    Get security settings for a tenant.

    Returns:
        Dict with session_timeout_seconds, persistent_sessions,
        allow_users_edit_profile, allow_users_add_emails,
        inactivity_threshold_days fields, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select session_timeout_seconds, persistent_sessions,
               allow_users_edit_profile, allow_users_add_emails,
               inactivity_threshold_days, max_certificate_lifetime_years,
               certificate_rotation_window_days,
               minimum_password_length, minimum_zxcvbn_score,
               group_assertion_scope
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )


def get_session_settings(tenant_id: TenantArg) -> dict | None:
    """
    Get session-related security settings for a tenant.

    Returns:
        Dict with persistent_sessions and session_timeout_seconds fields,
        or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select persistent_sessions, session_timeout_seconds
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )


def get_session_timeout(tenant_id: TenantArg) -> dict | None:
    """
    Get just the session timeout setting for a tenant.

    Returns:
        Dict with session_timeout_seconds field, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select session_timeout_seconds
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )


def can_user_edit_profile(tenant_id: TenantArg) -> dict | None:
    """
    Check if users are allowed to edit their profile.

    Returns:
        Dict with allow_users_edit_profile field, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select allow_users_edit_profile
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )


def can_user_add_emails(tenant_id: TenantArg) -> dict | None:
    """
    Check if users are allowed to add email addresses.

    Returns:
        Dict with allow_users_add_emails field, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select allow_users_add_emails
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )


def update_security_settings(
    tenant_id: TenantArg,
    timeout_seconds: int | None,
    persistent_sessions: bool,
    allow_users_edit_profile: bool,
    allow_users_add_emails: bool,
    inactivity_threshold_days: int | None,
    max_certificate_lifetime_years: int,
    certificate_rotation_window_days: int,
    minimum_password_length: int,
    minimum_zxcvbn_score: int,
    group_assertion_scope: str,
    updated_by: str,
    tenant_id_value: str,
) -> int:
    """
    Update or insert security settings for a tenant.

    Args:
        tenant_id: Tenant ID for scoping
        timeout_seconds: Session timeout in seconds (None for no timeout)
        persistent_sessions: Whether to allow persistent sessions
        allow_users_edit_profile: Whether users can edit their own profile
        allow_users_add_emails: Whether users can add email addresses
        inactivity_threshold_days: Days before inactive users are auto-inactivated (None = disabled)
        max_certificate_lifetime_years: Lifetime in years for new signing certificates
        certificate_rotation_window_days: Days before expiry to trigger auto-rotation
        minimum_password_length: Minimum password length (8-20)
        minimum_zxcvbn_score: Minimum zxcvbn strength score (3 or 4)
        group_assertion_scope: Group scope for SAML assertions
        updated_by: User ID of the person making the update
        tenant_id_value: The actual tenant ID value to store in the record

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        insert into tenant_security_settings (
            tenant_id, session_timeout_seconds, persistent_sessions,
            allow_users_edit_profile, allow_users_add_emails,
            inactivity_threshold_days, max_certificate_lifetime_years,
            certificate_rotation_window_days, minimum_password_length,
            minimum_zxcvbn_score, group_assertion_scope, updated_by
        )
        values (
            :tenant_id, :timeout_seconds, :persistent_sessions,
            :allow_users_edit_profile, :allow_users_add_emails,
            :inactivity_threshold_days, :max_certificate_lifetime_years,
            :certificate_rotation_window_days, :minimum_password_length,
            :minimum_zxcvbn_score, :group_assertion_scope, :updated_by
        )
        on conflict (tenant_id)
        do update set
            session_timeout_seconds = :timeout_seconds,
            persistent_sessions = :persistent_sessions,
            allow_users_edit_profile = :allow_users_edit_profile,
            allow_users_add_emails = :allow_users_add_emails,
            inactivity_threshold_days = :inactivity_threshold_days,
            max_certificate_lifetime_years = :max_certificate_lifetime_years,
            certificate_rotation_window_days = :certificate_rotation_window_days,
            minimum_password_length = :minimum_password_length,
            minimum_zxcvbn_score = :minimum_zxcvbn_score,
            group_assertion_scope = :group_assertion_scope,
            updated_at = now(),
            updated_by = :updated_by
        """,
        {
            "tenant_id": tenant_id_value,
            "timeout_seconds": timeout_seconds,
            "persistent_sessions": persistent_sessions,
            "allow_users_edit_profile": allow_users_edit_profile,
            "allow_users_add_emails": allow_users_add_emails,
            "inactivity_threshold_days": inactivity_threshold_days,
            "max_certificate_lifetime_years": max_certificate_lifetime_years,
            "certificate_rotation_window_days": certificate_rotation_window_days,
            "minimum_password_length": minimum_password_length,
            "minimum_zxcvbn_score": minimum_zxcvbn_score,
            "group_assertion_scope": group_assertion_scope,
            "updated_by": updated_by,
        },
    )


def get_inactivity_threshold(tenant_id: TenantArg) -> int | None:
    """
    Get the inactivity threshold in days for a tenant.

    Returns:
        Number of days, or None if disabled
    """
    result = fetchone(
        tenant_id,
        """
        select inactivity_threshold_days
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )
    return result["inactivity_threshold_days"] if result else None


def get_certificate_lifetime(tenant_id: TenantArg) -> int:
    """
    Get the certificate lifetime in years for a tenant.

    Returns:
        Number of years, or 10 (default) if not configured
    """
    result = fetchone(
        tenant_id,
        """
        select max_certificate_lifetime_years
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )
    return result["max_certificate_lifetime_years"] if result else 10


def get_certificate_rotation_window(tenant_id: TenantArg) -> int:
    """
    Get the certificate rotation window in days for a tenant.

    Returns:
        Number of days, or 90 (default) if not configured
    """
    result = fetchone(
        tenant_id,
        """
        select certificate_rotation_window_days
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )
    return result["certificate_rotation_window_days"] if result else 90


def get_password_policy(tenant_id: TenantArg) -> dict | None:
    """
    Get password policy settings for a tenant.

    Lightweight getter for unauthenticated flows (onboarding, password reset).

    Returns:
        Dict with minimum_password_length and minimum_zxcvbn_score, or None
    """
    return fetchone(
        tenant_id,
        """
        select minimum_password_length, minimum_zxcvbn_score
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )


def get_all_tenants_with_inactivity_threshold() -> list[dict]:
    """
    Get all tenants that have inactivity threshold configured.

    This is a cross-tenant query used by the worker for auto-inactivation.
    Uses UNSCOPED to bypass RLS (system task).

    Returns:
        List of dicts with tenant_id and inactivity_threshold_days
    """
    return fetchall(
        UNSCOPED,
        """
        select tenant_id, inactivity_threshold_days
        from tenant_security_settings
        where inactivity_threshold_days is not null
        """,
    )


def get_group_assertion_scope(tenant_id: TenantArg) -> str:
    """
    Get the group assertion scope setting for a tenant.

    Lightweight getter for the SSO flow (no authorization required).

    Returns:
        Scope string ('all', 'trunk', or 'access_relevant'), default 'access_relevant'
    """
    result = fetchone(
        tenant_id,
        """
        select group_assertion_scope
        from tenant_security_settings
        where tenant_id = :tenant_id
        """,
        {"tenant_id": tenant_id},
    )
    return result["group_assertion_scope"] if result else "access_relevant"


def get_all_tenant_ids() -> list[dict]:
    """
    Get all tenant IDs.

    This is a cross-tenant query used by background jobs that need
    to iterate over all tenants. Uses UNSCOPED to bypass RLS.

    Returns:
        List of dicts with tenant_id
    """
    return fetchall(
        UNSCOPED,
        "select id as tenant_id from tenants",
    )
