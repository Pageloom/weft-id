"""User authentication state database operations."""

from database._core import TenantArg, execute, fetchall, fetchone


def get_password_hash(tenant_id: TenantArg, user_id: str) -> str | None:
    """
    Get a user's password hash.

    Args:
        tenant_id: Tenant ID
        user_id: User ID

    Returns:
        The password hash string, or None if user not found or no password set.
    """
    row = fetchone(
        tenant_id,
        "select password_hash from users where id = :user_id",
        {"user_id": user_id},
    )
    return row["password_hash"] if row else None


def update_user_role(tenant_id: TenantArg, user_id: str, role: str) -> int:
    """
    Update a user's role (admin operation).

    Args:
        tenant_id: Tenant ID
        user_id: User ID to update
        role: New role ('member', 'admin', or 'super_admin')

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set role = :role where id = :user_id",
        {"role": role, "user_id": user_id},
    )


def update_password(
    tenant_id: TenantArg,
    user_id: str,
    password_hash: str,
    hibp_prefix: str | None = None,
    hibp_check_hmac: str | None = None,
    policy_length_at_set: int | None = None,
    policy_score_at_set: int | None = None,
) -> int:
    """
    Update a user's password hash and record the change timestamp.

    Also clears password_reset_required flag if set, and stores HIBP
    monitoring data and the password policy in effect at set time.

    Args:
        tenant_id: Tenant ID
        user_id: User ID to update
        password_hash: New hashed password
        hibp_prefix: First 5 hex chars of SHA-1 hash for HIBP monitoring
        hibp_check_hmac: HMAC-SHA256 of full SHA-1 for breach verification
        policy_length_at_set: Minimum password length policy when set
        policy_score_at_set: Minimum zxcvbn score policy when set

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """update users
           set password_hash = :password_hash,
               password_changed_at = now(),
               password_reset_required = false,
               hibp_prefix = :hibp_prefix,
               hibp_check_hmac = :hibp_check_hmac,
               password_policy_length_at_set = :policy_length_at_set,
               password_policy_score_at_set = :policy_score_at_set
           where id = :user_id""",
        {
            "password_hash": password_hash,
            "user_id": user_id,
            "hibp_prefix": hibp_prefix,
            "hibp_check_hmac": hibp_check_hmac,
            "policy_length_at_set": policy_length_at_set,
            "policy_score_at_set": policy_score_at_set,
        },
    )


def set_password_reset_required(tenant_id: TenantArg, user_id: str, required: bool) -> int:
    """
    Set or clear the password_reset_required flag on a user.

    Args:
        tenant_id: Tenant ID
        user_id: User ID to update
        required: Whether password reset is required

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set password_reset_required = :required where id = :user_id",
        {"required": required, "user_id": user_id},
    )


def update_mfa_status(tenant_id: TenantArg, user_id: str, enabled: bool) -> int:
    """
    Update a user's MFA enabled status.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to update
        enabled: Whether MFA is enabled

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set mfa_enabled = :enabled where id = :user_id",
        {"enabled": enabled, "user_id": user_id},
    )


def count_active_super_admins(tenant_id: TenantArg) -> int:
    """
    Count active (non-inactivated) super_admin users.

    Args:
        tenant_id: Tenant ID for scoping

    Returns:
        Number of active super_admin users
    """
    result = fetchone(
        tenant_id,
        """
        select count(*) as count from users
        where role = 'super_admin' and is_inactivated = false
        """,
        {},
    )
    return result["count"] if result else 0


def get_admin_emails(tenant_id: TenantArg) -> list[str]:
    """
    Get primary emails of all active admins and super_admins.

    Args:
        tenant_id: Tenant ID for scoping

    Returns:
        List of email addresses
    """
    rows = fetchall(
        tenant_id,
        """
        select ue.email
        from users u
        join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        where u.role in ('admin', 'super_admin')
          and u.is_inactivated = false
        """,
        {},
    )
    return [row["email"] for row in rows]


def get_users_with_hibp_prefix(tenant_id: TenantArg) -> list[dict]:
    """
    Get active password users who have HIBP monitoring data.

    Returns users with hibp_prefix and hibp_check_hmac set, for use
    by the HIBP breach checking background job.

    Args:
        tenant_id: Tenant ID for scoping

    Returns:
        List of dicts with id, hibp_prefix, hibp_check_hmac
    """
    return fetchall(
        tenant_id,
        """
        select id, hibp_prefix, hibp_check_hmac
        from users
        where hibp_prefix is not null
          and hibp_check_hmac is not null
          and is_inactivated = false
          and password_hash is not null
        """,
        {},
    )


def clear_hibp_data(tenant_id: TenantArg, user_id: str) -> int:
    """
    Clear HIBP monitoring data for a user after a breach is detected.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """update users
           set hibp_prefix = null,
               hibp_check_hmac = null
           where id = :user_id""",
        {"user_id": user_id},
    )


def get_users_with_weak_policy(
    tenant_id: TenantArg,
    new_min_length: int,
    new_min_score: int,
) -> list[dict]:
    """
    Get active password users whose password was set under a weaker policy.

    A user is non-compliant if either their stored policy length is less than
    the new minimum or their stored policy score is less than the new minimum.

    Args:
        tenant_id: Tenant ID for scoping
        new_min_length: New minimum password length
        new_min_score: New minimum zxcvbn score

    Returns:
        List of dicts with id
    """
    return fetchall(
        tenant_id,
        """
        select id
        from users
        where is_inactivated = false
          and password_hash is not null
          and password_reset_required = false
          and (
              (password_policy_length_at_set is not null
               and password_policy_length_at_set < :new_min_length)
              or
              (password_policy_score_at_set is not null
               and password_policy_score_at_set < :new_min_score)
          )
        """,
        {"new_min_length": new_min_length, "new_min_score": new_min_score},
    )


def bulk_set_password_reset_required(tenant_id: TenantArg, user_ids: list[str]) -> int:
    """
    Set password_reset_required for multiple users at once.

    Args:
        tenant_id: Tenant ID for scoping
        user_ids: List of user IDs to flag

    Returns:
        Number of rows affected
    """
    if not user_ids:
        return 0
    return execute(
        tenant_id,
        """update users
           set password_reset_required = true
           where id = any(:user_ids)""",
        {"user_ids": user_ids},
    )
