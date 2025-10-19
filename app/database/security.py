"""Security settings database operations."""

from ._core import TenantArg, execute, fetchone


def get_security_settings(tenant_id: TenantArg) -> dict | None:
    """
    Get security settings for a tenant.

    Returns:
        Dict with session_timeout_seconds, persistent_sessions,
        allow_users_edit_profile, allow_users_add_emails fields,
        or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select session_timeout_seconds, persistent_sessions,
               allow_users_edit_profile, allow_users_add_emails
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
            "tenant_id": tenant_id_value,
            "timeout_seconds": timeout_seconds,
            "persistent_sessions": persistent_sessions,
            "allow_users_edit_profile": allow_users_edit_profile,
            "allow_users_add_emails": allow_users_add_emails,
            "updated_by": updated_by,
        },
    )
