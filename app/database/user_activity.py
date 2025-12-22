"""User activity database operations.

This module provides database-level operations for the user_activity table.
It is used by the service layer to track user's last activity timestamp.
"""

from ._core import TenantArg, execute, fetchone


def upsert_activity(tenant_id: TenantArg, user_id: str) -> int:
    """
    Update or insert user activity timestamp.

    Uses PostgreSQL UPSERT (ON CONFLICT) to efficiently update the
    last_activity_at timestamp if a record exists, or insert a new
    record if not.

    Args:
        tenant_id: Tenant ID for RLS scoping and storage
        user_id: User ID to track activity for

    Returns:
        Number of rows affected (always 1 on success)
    """
    return execute(
        tenant_id,
        """
        INSERT INTO user_activity (user_id, tenant_id, last_activity_at)
        VALUES (:user_id, :tenant_id, now())
        ON CONFLICT (user_id) DO UPDATE SET last_activity_at = now()
        """,
        {"user_id": user_id, "tenant_id": str(tenant_id)},
    )


def get_activity(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get user activity record.

    Args:
        tenant_id: Tenant ID for RLS scoping
        user_id: User ID to get activity for

    Returns:
        Dict with user_id, tenant_id, last_activity_at, or None if not found
    """
    return fetchone(
        tenant_id,
        """
        SELECT user_id, tenant_id, last_activity_at
        FROM user_activity
        WHERE user_id = :user_id
        """,
        {"user_id": user_id},
    )
