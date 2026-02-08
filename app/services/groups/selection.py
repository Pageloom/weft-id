"""Group selection/dropdown operations.

This module provides functions for UI dropdown/selection lists:
- list_available_users_for_group
- list_available_groups_for_user
- list_available_parents
- list_available_children

All functions:
- Receive a RequestingUser for authorization
- Return lists of option schemas
- Raise ServiceError subclasses on failures
- Track activity for reads
"""

import database
from schemas.groups import AvailableGroupOption, AvailableUserOption
from services.activity import track_activity
from services.auth import require_admin
from services.exceptions import NotFoundError
from services.types import RequestingUser


def list_available_users_for_group(
    requesting_user: RequestingUser,
    group_id: str,
) -> list[AvailableUserOption]:
    """
    List users available to add to a group (not already members).

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        group_id: Group UUID

    Returns:
        List of users not already in the group
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    if not database.groups.get_group_by_id(tenant_id, group_id):
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    # Get all users (limited for dropdown)
    all_users = database.users.list_users(tenant_id, page=1, page_size=100)

    # Get current member IDs
    member_rows = database.groups.get_group_members(tenant_id, group_id, page=1, page_size=1000)
    member_user_ids = {str(m["user_id"]) for m in member_rows}

    # Filter out existing members
    available = [
        AvailableUserOption(
            id=str(u["id"]),
            email=u.get("email"),
            first_name=u.get("first_name", ""),
            last_name=u.get("last_name", ""),
        )
        for u in all_users
        if str(u["id"]) not in member_user_ids
    ]

    return available


def list_available_groups_for_user(
    requesting_user: RequestingUser,
    user_id: str,
) -> list[AvailableGroupOption]:
    """
    List WeftID groups available to add a user to (not already a member).

    Excludes IdP groups (managed by identity provider) and groups the user
    is already in.

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        user_id: User UUID to find available groups for

    Returns:
        List of WeftID groups the user is not yet a member of
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify user exists
    if not database.users.get_user_by_id(tenant_id, user_id):
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    rows = database.groups.get_groups_for_user_select(tenant_id, exclude_user_id=user_id)

    # Filter to WeftID groups only (IdP groups can't be manually assigned)
    return [
        AvailableGroupOption(
            id=str(r["id"]),
            name=r["name"],
            group_type=r["group_type"],
        )
        for r in rows
        if r["group_type"] == "weftid"
    ]


def list_available_parents(
    requesting_user: RequestingUser,
    group_id: str,
) -> list[AvailableGroupOption]:
    """
    List groups that can be parents of the given group.

    Excludes the group itself, existing parents, and descendants (cycle prevention).

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        group_id: Group UUID

    Returns:
        List of groups valid as parents
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    if not database.groups.get_group_by_id(tenant_id, group_id):
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    rows = database.groups.get_groups_for_parent_select(tenant_id, group_id)

    return [
        AvailableGroupOption(
            id=str(r["id"]),
            name=r["name"],
            group_type=r["group_type"],
        )
        for r in rows
    ]


def list_available_children(
    requesting_user: RequestingUser,
    group_id: str,
) -> list[AvailableGroupOption]:
    """
    List groups that can be children of the given group.

    Excludes the group itself, existing children, and ancestors (cycle prevention).
    IdP groups CAN be children (Phase 2 change). The constraint that IdP groups
    cannot be parents is enforced separately in add_child().

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        group_id: Group UUID

    Returns:
        List of groups valid as children
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    if not database.groups.get_group_by_id(tenant_id, group_id):
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    rows = database.groups.get_groups_for_child_select(tenant_id, group_id)

    return [
        AvailableGroupOption(
            id=str(r["id"]),
            name=r["name"],
            group_type=r["group_type"],
        )
        for r in rows
    ]
