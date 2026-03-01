"""Group CRUD operations.

This module provides business logic for group create, read, update, delete:
- list_groups
- get_group
- create_group
- update_group
- delete_group

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/groups.py
- Raise ServiceError subclasses on failures
- Log events after successful writes
- Track activity for reads
"""

import database
from schemas.groups import (
    GroupCreate,
    GroupDetail,
    GroupGraphData,
    GroupGraphEdge,
    GroupGraphNode,
    GroupListResponse,
    GroupUpdate,
)
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import (
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.groups._converters import _row_to_detail, _row_to_summary
from services.groups._helpers import _is_idp_group, _require_not_idp_group
from services.types import RequestingUser


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
        raise ValidationError(
            message="A group with this name already exists",
            code="group_name_exists",
            field="name",
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
                raise ValidationError(
                    message="A group with this name already exists",
                    code="group_name_exists",
                    field="name",
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

    # Require all relationships to be removed first
    parents = database.groups.get_group_parents(tenant_id, group_id)
    children = database.groups.get_group_children(tenant_id, group_id)
    if parents or children:
        raise ValidationError(
            message="Remove all parent and child relationships before deleting this group",
            code="has_relationships",
        )

    # Delete (cascades to memberships, lineage)
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


def get_group_graph_data(requesting_user: RequestingUser) -> GroupGraphData:
    """
    Get all groups and relationships for graph rendering.

    Authorization: Requires admin role.

    Args:
        requesting_user: The authenticated user

    Returns:
        GroupGraphData with nodes and edges for Cytoscape.js
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    data = database.groups.list_all_groups_for_graph(tenant_id)

    nodes = [
        GroupGraphNode(
            id=str(row["id"]),
            name=row["name"],
            group_type=row["group_type"],
            is_umbrella=bool(row.get("is_umbrella", False)),
            member_count=row.get("member_count", 0),
            effective_member_count=row.get("effective_member_count", 0),
            has_logo=bool(row.get("has_logo", False)),
            logo_updated_at=row.get("logo_updated_at"),
        )
        for row in data["groups"]
    ]
    edges = [
        GroupGraphEdge(
            source=str(row["child_group_id"]),
            target=str(row["parent_group_id"]),
        )
        for row in data["relationships"]
    ]
    return GroupGraphData(nodes=nodes, edges=edges)
