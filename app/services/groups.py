"""Group service layer.

This module provides business logic for group management:
- Group CRUD operations
- User membership management
- Hierarchical relationships with cycle detection

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/groups.py
- Raise ServiceError subclasses on failures
- Log events after successful writes
- Track activity for reads
"""

import database
from schemas.groups import (
    AvailableGroupOption,
    AvailableUserOption,
    GroupChildrenList,
    GroupCreate,
    GroupDetail,
    GroupListResponse,
    GroupMember,
    GroupMemberList,
    GroupParentsList,
    GroupRelationship,
    GroupSummary,
    GroupUpdate,
)
from services.activity import track_activity
from services.event_log import log_event
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser

# =============================================================================
# Authorization Helpers (private)
# =============================================================================


def _require_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not admin or super_admin."""
    if user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )


# =============================================================================
# Conversion Helpers (private)
# =============================================================================


def _row_to_summary(row: dict) -> GroupSummary:
    """Convert database row to GroupSummary."""
    return GroupSummary(
        id=str(row["id"]),
        name=row["name"],
        description=row.get("description"),
        group_type=row["group_type"],
        is_valid=row.get("is_valid", True),
        member_count=row.get("member_count", 0),
        created_at=row["created_at"],
    )


def _row_to_detail(row: dict) -> GroupDetail:
    """Convert database row to GroupDetail."""
    return GroupDetail(
        id=str(row["id"]),
        name=row["name"],
        description=row.get("description"),
        group_type=row["group_type"],
        idp_id=str(row["idp_id"]) if row.get("idp_id") else None,
        is_valid=row.get("is_valid", True),
        member_count=row.get("member_count", 0),
        parent_count=row.get("parent_count", 0),
        child_count=row.get("child_count", 0),
        created_by=str(row["created_by"]) if row.get("created_by") else None,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_member(row: dict) -> GroupMember:
    """Convert database row to GroupMember."""
    return GroupMember(
        id=str(row["id"]),
        user_id=str(row["user_id"]),
        email=row.get("email"),
        first_name=row.get("first_name", ""),
        last_name=row.get("last_name", ""),
        created_at=row["created_at"],
    )


def _row_to_relationship(row: dict) -> GroupRelationship:
    """Convert database row to GroupRelationship."""
    return GroupRelationship(
        id=str(row["id"]),
        group_id=str(row["group_id"]),
        name=row["name"],
        group_type=row["group_type"],
        member_count=row.get("member_count", 0),
        created_at=row["created_at"],
    )


# =============================================================================
# Group CRUD Operations
# =============================================================================


def list_groups(
    requesting_user: RequestingUser,
    search: str | None = None,
    group_type: str | None = None,
    sort_field: str = "created_at",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 25,
) -> GroupListResponse:
    """
    List groups for the tenant.

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        search: Optional search term for name/description
        group_type: Optional filter by type (weftid, idp)
        sort_field: Field to sort by (name, created_at, member_count)
        sort_order: Sort order (asc, desc)
        page: Page number (1-indexed)
        page_size: Results per page

    Returns:
        GroupListResponse with paginated groups
    """
    _require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    total = database.groups.count_groups(tenant_id, search, group_type)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = min(max(1, page), total_pages)

    rows = database.groups.list_groups(
        tenant_id,
        search=search,
        group_type=group_type,
        sort_field=sort_field,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )

    return GroupListResponse(
        items=[_row_to_summary(row) for row in rows],
        total=total,
        page=page,
        limit=page_size,
    )


def get_group(
    requesting_user: RequestingUser,
    group_id: str,
) -> GroupDetail:
    """
    Get a group by ID.

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        group_id: Group UUID

    Returns:
        GroupDetail with full information

    Raises:
        NotFoundError: If group doesn't exist
    """
    _require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    row = database.groups.get_group_by_id(requesting_user["tenant_id"], group_id)
    if not row:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    return _row_to_detail(row)


def create_group(
    requesting_user: RequestingUser,
    group_data: GroupCreate,
) -> GroupDetail:
    """
    Create a new group.

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        group_data: Group creation data

    Returns:
        The created GroupDetail

    Raises:
        ValidationError: If name is empty
        ConflictError: If name already exists
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    name = group_data.name.strip()

    if not name:
        raise ValidationError(
            message="Group name is required",
            code="name_required",
            field="name",
        )

    # Check for duplicate name
    if database.groups.get_group_by_name(tenant_id, name):
        raise ConflictError(
            message=f"A group named '{name}' already exists",
            code="group_name_exists",
        )

    # Create group (also creates self-referential lineage entry)
    result = database.groups.create_group(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=name,
        description=group_data.description,
        created_by=requesting_user["id"],
    )

    if not result:
        raise ValidationError(
            message="Failed to create group",
            code="creation_failed",
        )

    group_id = str(result["id"])

    # Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="group",
        artifact_id=group_id,
        event_type="group_created",
        metadata={"name": name},
    )

    # Fetch and return
    row = database.groups.get_group_by_id(tenant_id, group_id)
    if not row:
        raise ValidationError(
            message="Failed to fetch created group",
            code="fetch_failed",
        )
    return _row_to_detail(row)


def update_group(
    requesting_user: RequestingUser,
    group_id: str,
    group_data: GroupUpdate,
) -> GroupDetail:
    """
    Update a group.

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        group_id: Group UUID
        group_data: Fields to update

    Returns:
        Updated GroupDetail

    Raises:
        NotFoundError: If group doesn't exist
        ValidationError: If new name is empty
        ConflictError: If new name already exists
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    existing = database.groups.get_group_by_id(tenant_id, group_id)
    if not existing:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    # Validate name if provided
    name = None
    if group_data.name is not None:
        name = group_data.name.strip()
        if not name:
            raise ValidationError(
                message="Group name cannot be empty",
                code="name_required",
                field="name",
            )
        # Check for duplicate (if name changed)
        if name != existing["name"]:
            other = database.groups.get_group_by_name(tenant_id, name)
            if other:
                raise ConflictError(
                    message=f"A group named '{name}' already exists",
                    code="group_name_exists",
                )

    # Update
    database.groups.update_group(
        tenant_id=tenant_id,
        group_id=group_id,
        name=name,
        description=group_data.description,
    )

    # Log event
    changes = {}
    if name is not None and name != existing["name"]:
        changes["name"] = {"old": existing["name"], "new": name}
    if group_data.description is not None:
        changes["description"] = {"old": existing.get("description"), "new": group_data.description}

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="group",
        artifact_id=group_id,
        event_type="group_updated",
        metadata={"changes": changes} if changes else None,
    )

    # Fetch and return
    row = database.groups.get_group_by_id(tenant_id, group_id)
    if not row:
        raise NotFoundError(
            message="Group not found after update",
            code="group_not_found",
        )
    return _row_to_detail(row)


def delete_group(
    requesting_user: RequestingUser,
    group_id: str,
) -> None:
    """
    Delete a group.

    Children become orphaned (keep other parents if any).

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        group_id: Group UUID

    Raises:
        NotFoundError: If group doesn't exist
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    existing = database.groups.get_group_by_id(tenant_id, group_id)
    if not existing:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    # Delete (cascades to memberships, relationships, lineage)
    database.groups.delete_group(tenant_id, group_id)

    # Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="group",
        artifact_id=group_id,
        event_type="group_deleted",
        metadata={"name": existing["name"]},
    )


# =============================================================================
# Group Membership Operations
# =============================================================================


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
    _require_admin(requesting_user)
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
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    group = database.groups.get_group_by_id(tenant_id, group_id)
    if not group:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

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
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    group = database.groups.get_group_by_id(tenant_id, group_id)
    if not group:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

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


# =============================================================================
# Group Relationship Operations
# =============================================================================


def list_parents(
    requesting_user: RequestingUser,
    group_id: str,
) -> GroupParentsList:
    """
    List parent groups of a group.

    Authorization: Requires admin role.
    """
    _require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    if not database.groups.get_group_by_id(tenant_id, group_id):
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    rows = database.groups.get_group_parents(tenant_id, group_id)

    return GroupParentsList(
        items=[_row_to_relationship(row) for row in rows],
        total=len(rows),
    )


def list_children(
    requesting_user: RequestingUser,
    group_id: str,
) -> GroupChildrenList:
    """
    List child groups of a group.

    Authorization: Requires admin role.
    """
    _require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    if not database.groups.get_group_by_id(tenant_id, group_id):
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    rows = database.groups.get_group_children(tenant_id, group_id)

    return GroupChildrenList(
        items=[_row_to_relationship(row) for row in rows],
        total=len(rows),
    )


def add_child(
    requesting_user: RequestingUser,
    parent_group_id: str,
    child_group_id: str,
) -> None:
    """
    Add a child group to a parent group.

    Authorization: Requires admin role.

    Raises:
        NotFoundError: If either group doesn't exist
        ValidationError: If would create a cycle or self-reference
        ConflictError: If relationship already exists
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Cannot add self as child
    if parent_group_id == child_group_id:
        raise ValidationError(
            message="A group cannot be a child of itself",
            code="self_reference",
        )

    # Verify both groups exist
    parent = database.groups.get_group_by_id(tenant_id, parent_group_id)
    if not parent:
        raise NotFoundError(
            message="Parent group not found",
            code="parent_not_found",
        )

    child = database.groups.get_group_by_id(tenant_id, child_group_id)
    if not child:
        raise NotFoundError(
            message="Child group not found",
            code="child_not_found",
        )

    # Check for existing relationship
    if database.groups.relationship_exists(tenant_id, parent_group_id, child_group_id):
        raise ConflictError(
            message="This relationship already exists",
            code="relationship_exists",
        )

    # Check for cycle
    if database.groups.would_create_cycle(tenant_id, parent_group_id, child_group_id):
        raise ValidationError(
            message="Adding this relationship would create a cycle",
            code="would_create_cycle",
        )

    # Add relationship (transactional: updates both relationships and lineage)
    database.groups.add_group_relationship(
        tenant_id, tenant_id, parent_group_id, child_group_id
    )

    # Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="group_relationship",
        artifact_id=f"{parent_group_id}:{child_group_id}",
        event_type="group_relationship_created",
        metadata={
            "parent_group_id": parent_group_id,
            "parent_group_name": parent["name"],
            "child_group_id": child_group_id,
            "child_group_name": child["name"],
        },
    )


def remove_child(
    requesting_user: RequestingUser,
    parent_group_id: str,
    child_group_id: str,
) -> None:
    """
    Remove a child group from a parent group.

    Authorization: Requires admin role.

    Raises:
        NotFoundError: If relationship doesn't exist
    """
    _require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Get group names for logging
    parent = database.groups.get_group_by_id(tenant_id, parent_group_id)
    child = database.groups.get_group_by_id(tenant_id, child_group_id)

    # Remove relationship (transactional: updates both relationships and lineage)
    rows_affected = database.groups.remove_group_relationship(
        tenant_id, parent_group_id, child_group_id
    )

    if rows_affected == 0:
        raise NotFoundError(
            message="Relationship not found",
            code="relationship_not_found",
        )

    # Log event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="group_relationship",
        artifact_id=f"{parent_group_id}:{child_group_id}",
        event_type="group_relationship_deleted",
        metadata={
            "parent_group_id": parent_group_id,
            "parent_group_name": parent["name"] if parent else None,
            "child_group_id": child_group_id,
            "child_group_name": child["name"] if child else None,
        },
    )


# =============================================================================
# Utility Functions (for other services)
# =============================================================================


def get_user_group_ids(tenant_id: str, user_id: str) -> list[str]:
    """
    Get all group IDs a user belongs to (direct membership only).

    This is a utility function for other services.
    """
    rows = database.groups.get_user_groups(tenant_id, user_id)
    return [str(row["id"]) for row in rows]


# =============================================================================
# Dropdown/Selection Functions (for UI)
# =============================================================================


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
    _require_admin(requesting_user)
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
    _require_admin(requesting_user)
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

    Excludes the group itself, existing children, ancestors (cycle prevention),
    and IdP groups (which cannot have parents in Phase 1).

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user
        group_id: Group UUID

    Returns:
        List of groups valid as children
    """
    _require_admin(requesting_user)
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
