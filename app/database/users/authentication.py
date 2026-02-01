"""User authentication state database operations."""

from database._core import TenantArg, execute, fetchall, fetchone


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


def update_password(tenant_id: TenantArg, user_id: str, password_hash: str) -> int:
    """
    Update a user's password hash.

    Args:
        tenant_id: Tenant ID
        user_id: User ID to update
        password_hash: New hashed password

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set password_hash = :password_hash where id = :user_id",
        {"password_hash": password_hash, "user_id": user_id},
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
