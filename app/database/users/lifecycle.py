"""User account lifecycle database operations (inactivation, anonymization)."""

from database._core import TenantArg, execute, fetchall


def inactivate_user(tenant_id: TenantArg, user_id: str) -> int:
    """
    Inactivate a user account (soft-disable login).

    Inactivated users cannot sign in but retain all their data.
    This operation is reversible via reactivate_user().

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to inactivate

    Returns:
        Number of rows affected (0 if user not found or already inactivated)
    """
    return execute(
        tenant_id,
        """
        update users
        set is_inactivated = true, inactivated_at = now()
        where id = :user_id and is_inactivated = false
        """,
        {"user_id": user_id},
    )


def reactivate_user(tenant_id: TenantArg, user_id: str) -> int:
    """
    Reactivate an inactivated user account.

    Cannot reactivate anonymized users (anonymization is irreversible).

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to reactivate

    Returns:
        Number of rows affected (0 if user not found, not inactivated, or anonymized)
    """
    return execute(
        tenant_id,
        """
        update users
        set is_inactivated = false, inactivated_at = null
        where id = :user_id and is_inactivated = true and is_anonymized = false
        """,
        {"user_id": user_id},
    )


def anonymize_user(tenant_id: TenantArg, user_id: str) -> int:
    """
    Anonymize a user account (GDPR right to be forgotten).

    This is IRREVERSIBLE. Scrubs all PII from the user record:
    - first_name -> '[Anonymized]'
    - last_name -> 'User'
    - password_hash -> NULL
    - mfa_enabled -> false
    - mfa_method -> NULL
    - tz, locale, theme -> NULL

    The user is also inactivated. Related data (emails, MFA secrets) must be
    handled separately by the service layer.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to anonymize

    Returns:
        Number of rows affected (0 if user not found or already anonymized)
    """
    return execute(
        tenant_id,
        """
        update users
        set is_inactivated = true,
            is_anonymized = true,
            first_name = '[Anonymized]',
            last_name = 'User',
            inactivated_at = coalesce(inactivated_at, now()),
            anonymized_at = now(),
            password_hash = null,
            mfa_enabled = false,
            mfa_method = null,
            tz = null,
            locale = null,
            theme = null
        where id = :user_id and is_anonymized = false
        """,
        {"user_id": user_id},
    )


def set_reactivation_denied(tenant_id: TenantArg, user_id: str) -> int:
    """
    Mark a user as having been denied reactivation.

    This prevents them from submitting new reactivation requests.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to mark as denied

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update users
        set reactivation_denied_at = now()
        where id = :user_id
        """,
        {"user_id": user_id},
    )


def clear_reactivation_denied(tenant_id: TenantArg, user_id: str) -> int:
    """
    Clear the reactivation denied flag for a user.

    Called when a user is manually reactivated by an admin.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to clear denial for

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update users
        set reactivation_denied_at = null
        where id = :user_id
        """,
        {"user_id": user_id},
    )


def get_idle_users_for_tenant(
    tenant_id: TenantArg,
    threshold_days: int,
) -> list[dict]:
    """
    Get active users who have been idle beyond the threshold.

    This returns users who:
    - Are not inactivated or anonymized
    - Have last_activity_at older than threshold_days ago
    - Are not service users (no associated OAuth2 B2B client)

    Args:
        tenant_id: Tenant ID for scoping
        threshold_days: Number of days of inactivity before inclusion

    Returns:
        List of dicts with user_id, first_name, last_name, last_activity_at
    """
    return fetchall(
        tenant_id,
        """
        select u.id as user_id,
               u.first_name,
               u.last_name,
               ua.last_activity_at
        from users u
        left join user_activity ua on u.id = ua.user_id
        where u.is_inactivated = false
          and u.is_anonymized = false
          and (
              ua.last_activity_at < now() - make_interval(days => :threshold_days)
              or ua.last_activity_at is null
          )
          and not exists (
              select 1 from oauth2_clients oc
              where oc.service_user_id = u.id and oc.client_type = 'b2b'
          )
        """,
        {"threshold_days": threshold_days},
    )
