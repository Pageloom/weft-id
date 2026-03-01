"""Group hierarchy operations.

This module provides business logic for group hierarchy (DAG) management:
- list_parents
- list_children
- add_child
- remove_child

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/groups.py
- Raise ServiceError subclasses on failures
- Log events after successful writes
- Track activity for reads
"""

import database
from schemas.groups import GroupChildrenList, GroupParentsList
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.groups._converters import _row_to_relationship
from services.groups._helpers import (
    _is_idp_group,
    _is_idp_managed_relationship,
    _is_idp_umbrella_group,
)
from services.types import RequestingUser


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

    # IdP assertion sub-groups cannot be parents; umbrella groups can
    if _is_idp_group(parent) and not _is_idp_umbrella_group(tenant_id, parent):
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
        artifact_id=parent_group_id,
        event_type="group_relationship_created",
        metadata={
            "parent_group_id": parent_group_id,
            "parent_group_name": parent["name"],
            "child_group_id": child_group_id,
            "child_group_name": child["name"],
        },
    )


def remove_all_relationships(
    requesting_user: RequestingUser,
    group_id: str,
) -> int:
    """
    Remove all parent and child relationships for a group.

    Authorization: Requires admin role.

    Returns:
        Number of relationships removed.

    Raises:
        NotFoundError: If the group doesn't exist
    """
    require_admin(requesting_user)

    tenant_id = requesting_user["tenant_id"]

    group = database.groups.get_group_by_id(tenant_id, group_id)
    if not group:
        raise NotFoundError(
            message="Group not found",
            code="group_not_found",
        )

    parents = database.groups.get_group_parents(tenant_id, group_id)
    children = database.groups.get_group_children(tenant_id, group_id)

    count = 0

    for parent in parents:
        parent_id = str(parent["group_id"])
        # Skip IdP-managed relationships
        parent_data = database.groups.get_group_by_id(tenant_id, parent_id)
        if parent_data and _is_idp_managed_relationship(tenant_id, parent_data, group):
            continue
        rows_affected = database.groups.remove_group_relationship(tenant_id, parent_id, group_id)
        if rows_affected > 0:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=requesting_user["id"],
                artifact_type="group_relationship",
                artifact_id=parent_id,
                event_type="group_relationship_deleted",
                metadata={
                    "parent_group_id": parent_id,
                    "parent_group_name": parent["name"],
                    "child_group_id": group_id,
                    "child_group_name": group["name"],
                },
            )
            count += 1

    for child in children:
        child_id = str(child["group_id"])
        # Skip IdP-managed relationships
        child_data = database.groups.get_group_by_id(tenant_id, child_id)
        if child_data and _is_idp_managed_relationship(tenant_id, group, child_data):
            continue
        rows_affected = database.groups.remove_group_relationship(tenant_id, group_id, child_id)
        if rows_affected > 0:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=requesting_user["id"],
                artifact_type="group_relationship",
                artifact_id=group_id,
                event_type="group_relationship_deleted",
                metadata={
                    "parent_group_id": group_id,
                    "parent_group_name": group["name"],
                    "child_group_id": child_id,
                    "child_group_name": child["name"],
                },
            )
            count += 1

    return count


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

    # Get group data for logging and protection checks
    parent = database.groups.get_group_by_id(tenant_id, parent_group_id)
    child = database.groups.get_group_by_id(tenant_id, child_group_id)

    # Protect IdP-managed relationships from manual removal
    if parent and child and _is_idp_managed_relationship(tenant_id, parent, child):
        raise ForbiddenError(
            message="Cannot remove IdP-managed relationship",
            code="idp_managed_relationship",
        )

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
        artifact_id=parent_group_id,
        event_type="group_relationship_deleted",
        metadata={
            "parent_group_id": parent_group_id,
            "parent_group_name": parent["name"] if parent else None,
            "child_group_id": child_group_id,
            "child_group_name": child["name"] if child else None,
        },
    )
