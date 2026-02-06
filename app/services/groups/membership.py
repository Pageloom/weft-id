"""Group membership operations.

This module provides business logic for group membership management:
- list_members
- add_member
- remove_member

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/groups.py
- Raise ServiceError subclasses on failures
- Log events after successful writes
- Track activity for reads
"""

import database
from schemas.groups import GroupMemberList
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError
from services.groups._converters import _row_to_member
from services.groups._helpers import _require_not_idp_group
from services.types import RequestingUser


def list_members(
    requesting_user: RequestingUser,
    group_id: str,
    page: int = 1,
    page_size: int = 50,
) -> GroupMemberList:
    """
    List members of a group.

    Authorization: Requires admin role.
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

    total = database.groups.count_group_members(tenant_id, group_id)
    rows = database.groups.get_group_members(tenant_id, group_id, page, page_size)

    return GroupMemberList(
        items=[_row_to_member(row) for row in rows],
        total=total,
    )


def add_member(
    requesting_user: RequestingUser,
    group_id: str,
    user_id: str,
) -> None:
    """
    Add a user to a group.

    Authorization: Requires admin role.

    Raises:
        NotFoundError: If group or user doesn't exist
        ConflictError: If user is already a member
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    group = database.groups.get_group_by_id(tenant_id, group_id)
    if not group:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    # IdP groups are managed by the identity provider
    _require_not_idp_group(group, "add member")

    # Verify user exists
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    # Check if already a member
    if database.groups.is_group_member(tenant_id, group_id, user_id):
        raise ConflictError(
            message="User is already a member of this group",
            code="already_member",
        )

    # Add member
    database.groups.add_group_member(tenant_id, tenant_id, group_id, user_id)

    # Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="group_membership",
        artifact_id=f"{group_id}:{user_id}",
        event_type="group_member_added",
        metadata={
            "group_id": group_id,
            "group_name": group["name"],
            "user_id": user_id,
        },
    )


def remove_member(
    requesting_user: RequestingUser,
    group_id: str,
    user_id: str,
) -> None:
    """
    Remove a user from a group.

    Authorization: Requires admin role.

    Raises:
        NotFoundError: If group doesn't exist or user is not a member
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    group = database.groups.get_group_by_id(tenant_id, group_id)
    if not group:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    # IdP groups are managed by the identity provider
    _require_not_idp_group(group, "remove member")

    # Remove member
    rows_affected = database.groups.remove_group_member(tenant_id, group_id, user_id)
    if rows_affected == 0:
        raise NotFoundError(
            message="User is not a member of this group",
            code="not_a_member",
        )

    # Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="group_membership",
        artifact_id=f"{group_id}:{user_id}",
        event_type="group_member_removed",
        metadata={
            "group_id": group_id,
            "group_name": group["name"],
            "user_id": user_id,
        },
    )
