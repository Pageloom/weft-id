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
from services.auth import require_admin
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser
from utils.request_context import system_context


def _is_idp_group(group: dict) -> bool:
    """Check if a group is managed by an IdP (read-only)."""
    return group.get("group_type") == "idp"


def _require_not_idp_group(group: dict, operation: str) -> None:
    """Raise ForbiddenError if trying to modify an IdP-managed group."""
    if _is_idp_group(group):
        raise ForbiddenError(
            message=f"Cannot {operation}: this group is managed by an identity provider",
            code="idp_group_readonly",
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
        idp_id=str(row["idp_id"]) if row.get("idp_id") else None,
        idp_name=row.get("idp_name"),
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
        idp_name=row.get("idp_name"),
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
    require_admin(requesting_user)
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
    require_admin(requesting_user)
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
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]
    name = group_data.name.strip()

    if not name:
        raise ValidationError(
            message="Group name is required",
            code="name_required",
            field="name",
        )

    # Check for duplicate name (only among WeftID groups)
    if database.groups.get_weftid_group_by_name(tenant_id, name):
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
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    existing = database.groups.get_group_by_id(tenant_id, group_id)
    if not existing:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    # IdP groups are read-only
    _require_not_idp_group(existing, "update group")

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
        # Check for duplicate (if name changed, only among WeftID groups)
        if name != existing["name"]:
            other = database.groups.get_weftid_group_by_name(tenant_id, name)
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
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    existing = database.groups.get_group_by_id(tenant_id, group_id)
    if not existing:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    # IdP groups can only be deleted if they are invalid (IdP was deleted)
    if _is_idp_group(existing) and existing.get("is_valid", True):
        raise ForbiddenError(
            message="Cannot delete IdP group while its identity provider exists",
            code="idp_group_active",
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
    require_admin(requesting_user)
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
    require_admin(requesting_user)
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
    require_admin(requesting_user)

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

    # IdP groups cannot be parents (they can only be children)
    if _is_idp_group(parent):
        raise ValidationError(
            message="IdP groups cannot have children",
            code="idp_cannot_be_parent",
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
    database.groups.add_group_relationship(tenant_id, tenant_id, parent_group_id, child_group_id)

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
    require_admin(requesting_user)

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


# =============================================================================
# IdP Group Operations (Phase 2)
# =============================================================================


def create_idp_base_group(
    tenant_id: str,
    idp_id: str,
    idp_name: str,
) -> GroupDetail:
    """
    Create the base group for an IdP.

    Called automatically when an IdP is created. The group:
    - Has the same name as the IdP
    - Is marked as type='idp'
    - Is linked to the IdP via idp_id
    - All users authenticating via this IdP will be added to this group

    This is a system operation (not user-initiated), so it uses SYSTEM_ACTOR_ID.

    Args:
        tenant_id: Tenant UUID
        idp_id: The IdP UUID
        idp_name: The IdP name (used as group name)

    Returns:
        The created GroupDetail

    Raises:
        ValidationError: If group creation fails
        ConflictError: If a group with this name already exists
    """
    # Check for duplicate name within this IdP (IdP groups are namespaced to their IdP)
    if database.groups.get_group_by_idp_and_name(tenant_id, idp_id, idp_name):
        raise ConflictError(
            message=f"A group named '{idp_name}' already exists for this IdP",
            code="group_name_exists",
        )

    # Create the IdP group (also creates self-referential lineage entry)
    result = database.groups.create_idp_group(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        idp_id=idp_id,
        name=idp_name,
        description=f"All users authenticating via {idp_name}",
    )

    if not result:
        raise ValidationError(
            message="Failed to create IdP group",
            code="creation_failed",
        )

    group_id = str(result["id"])

    # Log event with IdP attribution
    with system_context():
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="group",
            artifact_id=group_id,
            event_type="idp_group_created",
            metadata={
                "idp_id": idp_id,
                "idp_name": idp_name,
                "group_name": idp_name,
            },
        )

    # Fetch and return
    row = database.groups.get_group_by_id(tenant_id, group_id)
    if not row:
        raise ValidationError(
            message="Failed to fetch created group",
            code="fetch_failed",
        )
    return _row_to_detail(row)


def get_or_create_idp_group(
    tenant_id: str,
    idp_id: str,
    idp_name: str,
    group_name: str,
) -> dict:
    """
    Get or create an IdP-scoped group by name.

    Used during SAML authentication to handle discovered group claims.
    If a group with this name already exists for this IdP, returns it.
    Otherwise creates a new IdP group.

    Args:
        tenant_id: Tenant UUID
        idp_id: The IdP UUID
        idp_name: The IdP name (for logging)
        group_name: The group name from SAML claims

    Returns:
        Dict with id and name of the group
    """
    # Check if group already exists for this IdP
    existing = database.groups.get_group_by_idp_and_name(tenant_id, idp_id, group_name)
    if existing:
        return {"id": str(existing["id"]), "name": existing["name"], "created": False}

    # Create new IdP group
    result = database.groups.create_idp_group(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        idp_id=idp_id,
        name=group_name,
        description=f"Discovered from {idp_name}",
    )

    if not result:
        raise ValidationError(
            message=f"Failed to create IdP group '{group_name}'",
            code="creation_failed",
        )

    group_id = str(result["id"])

    # Log discovery event with IdP attribution
    with system_context():
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="group",
            artifact_id=group_id,
            event_type="idp_group_discovered",
            metadata={
                "idp_id": idp_id,
                "idp_name": idp_name,
                "group_name": group_name,
            },
        )

    return {"id": group_id, "name": group_name, "created": True}


def _apply_membership_additions(
    tenant_id: str,
    user_id: str,
    user_email: str,
    idp_id: str,
    idp_name: str,
    group_ids: set[str],
) -> list[str]:
    """Add user to the given groups and log each addition.

    Returns list of added group names.
    """
    if not group_ids:
        return []

    database.groups.bulk_add_user_to_groups(tenant_id, tenant_id, user_id, list(group_ids))

    added: list[str] = []
    for group_id in group_ids:
        group = database.groups.get_group_by_id(tenant_id, group_id)
        group_name = group["name"] if group else "Unknown"
        added.append(group_name)

        with system_context():
            log_event(
                tenant_id=tenant_id,
                actor_user_id=SYSTEM_ACTOR_ID,
                artifact_type="group_membership",
                artifact_id=f"{group_id}:{user_id}",
                event_type="idp_group_member_added",
                metadata={
                    "idp_id": idp_id,
                    "idp_name": idp_name,
                    "user_id": user_id,
                    "user_email": user_email,
                    "group_id": group_id,
                    "group_name": group_name,
                    "sync_source": "saml_authentication",
                },
            )

    return added


def _apply_membership_removals(
    tenant_id: str,
    user_id: str,
    user_email: str,
    idp_id: str,
    idp_name: str,
    group_ids: set[str],
) -> list[str]:
    """Remove user from the given groups and log each removal.

    Returns list of removed group names.
    """
    if not group_ids:
        return []

    # Collect group names before removal for logging
    groups_to_remove: list[tuple[str, str]] = []
    for group_id in group_ids:
        group = database.groups.get_group_by_id(tenant_id, group_id)
        group_name = group["name"] if group else "Unknown"
        groups_to_remove.append((group_id, group_name))

    database.groups.bulk_remove_user_from_groups(tenant_id, user_id, list(group_ids))

    removed: list[str] = []
    for group_id, group_name in groups_to_remove:
        removed.append(group_name)

        with system_context():
            log_event(
                tenant_id=tenant_id,
                actor_user_id=SYSTEM_ACTOR_ID,
                artifact_type="group_membership",
                artifact_id=f"{group_id}:{user_id}",
                event_type="idp_group_member_removed",
                metadata={
                    "idp_id": idp_id,
                    "idp_name": idp_name,
                    "user_id": user_id,
                    "user_email": user_email,
                    "group_id": group_id,
                    "group_name": group_name,
                    "sync_source": "saml_authentication",
                },
            )

    return removed


def sync_user_idp_groups(
    tenant_id: str,
    user_id: str,
    user_email: str,
    idp_id: str,
    idp_name: str,
    group_names: list[str],
) -> dict:
    """
    Full sync of user's IdP group memberships.

    Called during SAML authentication to update the user's group memberships
    based on the group claims in the SAML assertion.

    This performs a full sync:
    - Adds user to groups they're in according to IdP
    - Removes user from IdP groups they're no longer in
    - Creates new IdP groups for newly discovered group names

    Uses SYSTEM_ACTOR_ID as the actor since this is IdP-driven, not user-initiated.
    The IdP name is included in event metadata for audit attribution.

    Args:
        tenant_id: Tenant UUID
        user_id: The user UUID
        user_email: The user's email (for logging)
        idp_id: The IdP UUID
        idp_name: The IdP name (for logging)
        group_names: List of group names from SAML claims

    Returns:
        Dict with sync results: {"added": [...], "removed": [...], "created": [...]}
    """
    result: dict[str, list[str]] = {"added": [], "removed": [], "created": []}

    # Get current IdP group memberships for this user
    current_group_ids = set(database.groups.get_user_idp_group_ids(tenant_id, user_id, idp_id))

    # Resolve group names to group IDs (creating groups as needed)
    target_group_ids: set[str] = set()
    for group_name in group_names:
        group_info = get_or_create_idp_group(tenant_id, idp_id, idp_name, group_name)
        if group_info:
            target_group_ids.add(group_info["id"])
            if group_info.get("created"):
                result["created"].append(group_name)

    # Apply additions and removals
    to_add = target_group_ids - current_group_ids
    to_remove = current_group_ids - target_group_ids

    result["added"] = _apply_membership_additions(
        tenant_id, user_id, user_email, idp_id, idp_name, to_add
    )
    result["removed"] = _apply_membership_removals(
        tenant_id, user_id, user_email, idp_id, idp_name, to_remove
    )

    return result


def invalidate_idp_groups(
    tenant_id: str,
    idp_id: str,
    idp_name: str,
) -> int:
    """
    Mark all groups for an IdP as invalid.

    Called when an IdP is deleted. Groups are preserved for historical reference
    but marked as invalid so they cannot be used for future operations.

    This is a system operation, so it uses SYSTEM_ACTOR_ID.

    Args:
        tenant_id: Tenant UUID
        idp_id: The IdP UUID
        idp_name: The IdP name (for logging)

    Returns:
        Number of groups invalidated
    """
    # Get groups before invalidation for logging
    groups = database.groups.get_groups_by_idp(tenant_id, idp_id)

    if not groups:
        return 0

    # Invalidate all groups for this IdP
    count = database.groups.invalidate_groups_by_idp(tenant_id, idp_id)

    # Log invalidation for each group
    with system_context():
        for group in groups:
            if group.get("is_valid", True):  # Only log if was valid
                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=SYSTEM_ACTOR_ID,
                    artifact_type="group",
                    artifact_id=str(group["id"]),
                    event_type="idp_group_invalidated",
                    metadata={
                        "idp_id": idp_id,
                        "idp_name": idp_name,
                        "group_name": group["name"],
                        "reason": "idp_deleted",
                    },
                )

    return count


def list_groups_for_idp(
    requesting_user: RequestingUser,
    idp_id: str,
) -> list[GroupSummary]:
    """
    List all groups belonging to an IdP.

    Authorization: Requires admin role.

    Args:
        requesting_user: The user making the request
        idp_id: The IdP UUID

    Returns:
        List of GroupSummary for all groups linked to this IdP
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    rows = database.groups.get_groups_by_idp(requesting_user["tenant_id"], idp_id)
    return [_row_to_summary(row) for row in rows]
