"""Group membership operations.

This module provides business logic for group membership management:
- list_members
- add_member
- remove_member
- get_direct_memberships
- bulk_add_user_to_groups

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/groups.py
- Raise ServiceError subclasses on failures
- Log events after successful writes
- Track activity for reads
"""

import database
from schemas.groups import (
    EffectiveMember,
    EffectiveMemberList,
    EffectiveMembership,
    EffectiveMembershipList,
    GroupMemberList,
    UserGroup,
    UserGroupsList,
)
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import ConflictError, ForbiddenError, NotFoundError
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


def get_my_groups(requesting_user: RequestingUser) -> UserGroupsList:
    """
    Get the current user's direct groups with hierarchy context.

    Authorization: Any authenticated user.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    rows = database.groups.get_user_groups_with_context(
        requesting_user["tenant_id"],
        requesting_user["id"],
    )

    items = [
        UserGroup(
            id=str(row["id"]),
            name=row["name"],
            description=row.get("description"),
            group_type=row["group_type"],
            joined_at=row["joined_at"],
            parent_names=row.get("parent_names"),
        )
        for row in rows
    ]

    return UserGroupsList(items=items)


def get_effective_memberships(
    requesting_user: RequestingUser,
    user_id: str,
) -> EffectiveMembershipList:
    """
    Get all groups a user is effectively in (direct + inherited).

    Authorization: Admin, or self (user_id == requesting_user["id"]).
    """
    # Allow admin or self
    if requesting_user["role"] not in ("admin", "super_admin") and requesting_user["id"] != user_id:
        raise ForbiddenError(
            message="You can only view your own effective memberships",
            code="forbidden",
        )

    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    rows = database.groups.get_effective_memberships(
        requesting_user["tenant_id"],
        user_id,
    )

    items = [
        EffectiveMembership(
            id=str(row["id"]),
            name=row["name"],
            description=row.get("description"),
            group_type=row["group_type"],
            idp_id=str(row["idp_id"]) if row.get("idp_id") else None,
            idp_name=row.get("idp_name"),
            is_direct=row["is_direct"],
        )
        for row in rows
    ]

    return EffectiveMembershipList(items=items)


def get_effective_members(
    requesting_user: RequestingUser,
    group_id: str,
    page: int = 1,
    page_size: int = 50,
) -> EffectiveMemberList:
    """
    Get all effective members of a group (direct + via descendants).

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

    total = database.groups.count_effective_members(tenant_id, group_id)
    rows = database.groups.get_effective_members(tenant_id, group_id, page, page_size)

    items = [
        EffectiveMember(
            user_id=str(row["user_id"]),
            email=row.get("email"),
            first_name=row.get("first_name", ""),
            last_name=row.get("last_name", ""),
            is_direct=row["is_direct"],
        )
        for row in rows
    ]

    return EffectiveMemberList(items=items, total=total, page=page, limit=page_size)


def bulk_add_members(
    requesting_user: RequestingUser,
    group_id: str,
    user_ids: list[str],
) -> int:
    """
    Add multiple users to a group in bulk.

    Authorization: Requires admin role.

    Returns:
        Count of new memberships created.
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
    _require_not_idp_group(group, "bulk add members")

    # Add members
    count = database.groups.bulk_add_group_members(tenant_id, tenant_id, group_id, user_ids)

    # Log event
    if count > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="group_membership",
            artifact_id=group_id,
            event_type="group_members_bulk_added",
            metadata={
                "group_name": group["name"],
                "count": count,
                "user_ids": user_ids,
            },
        )

    return count


def get_direct_memberships(
    requesting_user: RequestingUser,
    user_id: str,
) -> EffectiveMembershipList:
    """
    Get only the direct group memberships for a user.

    Unlike get_effective_memberships, this excludes inherited groups.

    Authorization: Admin, or self (user_id == requesting_user["id"]).
    """
    # Allow admin or self
    if requesting_user["role"] not in ("admin", "super_admin") and requesting_user["id"] != user_id:
        raise ForbiddenError(
            message="You can only view your own group memberships",
            code="forbidden",
        )

    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    rows = database.groups.get_user_groups(
        requesting_user["tenant_id"],
        user_id,
    )

    items = [
        EffectiveMembership(
            id=str(row["id"]),
            name=row["name"],
            description=row.get("description"),
            group_type=row["group_type"],
            idp_id=None,
            idp_name=None,
            is_direct=True,
        )
        for row in rows
    ]

    return EffectiveMembershipList(items=items)


def bulk_add_user_to_groups(
    requesting_user: RequestingUser,
    user_id: str,
    group_ids: list[str],
) -> int:
    """
    Add a user to multiple groups.

    Skips IdP groups, missing groups, and groups where user is already a member.

    Authorization: Requires admin role.

    Returns:
        Count of new memberships created.
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify user exists
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user:
        raise NotFoundError(
            message="User not found",
            code="user_not_found",
        )

    added_count = 0
    added_group_names = []

    for group_id in group_ids:
        group = database.groups.get_group_by_id(tenant_id, group_id)
        if not group:
            continue

        # Skip IdP groups
        if group.get("group_type") == "idp":
            continue

        # Skip if already a member
        if database.groups.is_group_member(tenant_id, group_id, user_id):
            continue

        database.groups.add_group_member(tenant_id, tenant_id, group_id, user_id)
        added_count += 1
        added_group_names.append(group["name"])

    if added_count > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_groups_bulk_added",
            metadata={
                "count": added_count,
                "group_names": added_group_names,
            },
        )

    return added_count
