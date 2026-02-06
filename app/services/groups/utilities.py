"""Utility functions for groups service.

These are internal utility functions used by other services.
"""

import database


def get_user_group_ids(tenant_id: str, user_id: str) -> list[str]:
    """
    Get all group IDs a user belongs to (direct membership only).

    This is a utility function for other services.
    """
    rows = database.groups.get_user_groups(tenant_id, user_id)
    return [str(row["id"]) for row in rows]
