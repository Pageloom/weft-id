"""SP group assignments and user access checks.

Manage which groups are assigned to service providers, and check
whether users can access SPs via their group memberships.
"""

import logging

import database
from schemas.service_providers import (
    GrantingGroup,
    GroupSPAssignment,
    GroupSPAssignmentList,
    SPGroupAssignment,
    SPGroupAssignmentList,
    UserAccessibleApp,
    UserAccessibleAppList,
    UserApp,
    UserAppList,
)
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import ConflictError, NotFoundError
from services.types import RequestingUser

logger = logging.getLogger(__name__)


def count_sp_group_assignments(
    requesting_user: RequestingUser,
    sp_id: str,
) -> int:
    """Count group assignments for an SP (for tab bar label).

    Authorization: Requires admin role.
    """
    require_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    return database.sp_group_assignments.count_assignments_for_sp(tenant_id, sp_id)


def list_sp_group_assignments(
    requesting_user: RequestingUser,
    sp_id: str,
) -> SPGroupAssignmentList:
    """List group assignments for an SP.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    rows = database.sp_group_assignments.list_assignments_for_sp(tenant_id, sp_id)
    items = [
        SPGroupAssignment(
            id=str(row["id"]),
            sp_id=str(row["sp_id"]),
            group_id=str(row["group_id"]),
            group_name=row["group_name"],
            group_description=row.get("group_description"),
            group_type=row["group_type"],
            assigned_by=str(row["assigned_by"]),
            assigned_at=row["assigned_at"],
        )
        for row in rows
    ]
    return SPGroupAssignmentList(items=items, total=len(items))


def assign_sp_to_group(
    requesting_user: RequestingUser,
    sp_id: str,
    group_id: str,
) -> SPGroupAssignment:
    """Assign a group to an SP.

    Authorization: Requires admin role.
    Logs: sp_group_assigned event.
    """
    require_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    # Verify group exists
    group_row = database.groups.get_group_by_id(tenant_id, group_id)
    if group_row is None:
        raise NotFoundError(message="Group not found", code="group_not_found")

    row = database.sp_group_assignments.create_assignment(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        sp_id=sp_id,
        group_id=group_id,
        assigned_by=requesting_user["id"],
    )

    if row is None:
        raise ConflictError(
            message="Group is already assigned to this service provider",
            code="sp_group_already_assigned",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="sp_group_assigned",
        metadata={
            "group_id": group_id,
            "group_name": group_row["name"],
            "sp_name": sp_row["name"],
        },
    )

    return SPGroupAssignment(
        id=str(row["id"]),
        sp_id=str(row["sp_id"]),
        group_id=str(row["group_id"]),
        group_name=group_row["name"],
        group_description=group_row.get("description"),
        group_type=group_row["group_type"],
        assigned_by=str(row["assigned_by"]),
        assigned_at=row["assigned_at"],
    )


def remove_sp_group_assignment(
    requesting_user: RequestingUser,
    sp_id: str,
    group_id: str,
) -> None:
    """Remove a group assignment from an SP.

    Authorization: Requires admin role.
    Logs: sp_group_unassigned event.
    """
    require_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    deleted = database.sp_group_assignments.delete_assignment(tenant_id, sp_id, group_id)
    if deleted == 0:
        raise NotFoundError(
            message="Group assignment not found",
            code="sp_group_assignment_not_found",
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="service_provider",
        artifact_id=sp_id,
        event_type="sp_group_unassigned",
        metadata={
            "group_id": group_id,
            "sp_name": sp_row["name"],
        },
    )


def bulk_assign_sp_to_groups(
    requesting_user: RequestingUser,
    sp_id: str,
    group_ids: list[str],
) -> int:
    """Bulk-assign groups to an SP.

    Authorization: Requires admin role.
    Logs: sp_groups_bulk_assigned event.

    Returns:
        Number of new assignments created.
    """
    require_admin(requesting_user, log_failure=True, service_name="service_providers")

    tenant_id = requesting_user["tenant_id"]

    # Verify SP exists
    sp_row = database.service_providers.get_service_provider(tenant_id, sp_id)
    if sp_row is None:
        raise NotFoundError(message="Service provider not found", code="sp_not_found")

    count = database.sp_group_assignments.bulk_create_assignments(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        sp_id=sp_id,
        group_ids=group_ids,
        assigned_by=requesting_user["id"],
    )

    if count > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="service_provider",
            artifact_id=sp_id,
            event_type="sp_groups_bulk_assigned",
            metadata={
                "group_ids": group_ids,
                "count": count,
                "sp_name": sp_row["name"],
            },
        )

    return count


def list_group_sp_assignments(
    requesting_user: RequestingUser,
    group_id: str,
) -> GroupSPAssignmentList:
    """List SP assignments for a group.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify group exists
    group_row = database.groups.get_group_by_id(tenant_id, group_id)
    if group_row is None:
        raise NotFoundError(message="Group not found", code="group_not_found")

    rows = database.sp_group_assignments.list_assignments_for_group(tenant_id, group_id)
    items = [
        GroupSPAssignment(
            id=str(row["id"]),
            sp_id=str(row["sp_id"]),
            group_id=str(row["group_id"]),
            sp_name=row["sp_name"],
            sp_entity_id=row["sp_entity_id"],
            sp_description=row.get("sp_description"),
            assigned_by=str(row["assigned_by"]),
            assigned_at=row["assigned_at"],
        )
        for row in rows
    ]
    return GroupSPAssignmentList(items=items, total=len(items))


def list_available_groups_for_sp(
    requesting_user: RequestingUser,
    sp_id: str,
) -> list[dict]:
    """List groups not yet assigned to an SP (for dropdown).

    Authorization: Requires admin role.

    Returns:
        List of dicts with id, name, group_type for unassigned groups.
    """
    require_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get all groups
    all_groups = database.groups.list_groups(tenant_id)

    # Get assigned group IDs
    assigned = database.sp_group_assignments.list_assignments_for_sp(tenant_id, sp_id)
    assigned_ids = {str(row["group_id"]) for row in assigned}

    # Filter to unassigned
    return [
        {"id": str(g["id"]), "name": g["name"], "group_type": g["group_type"]}
        for g in all_groups
        if str(g["id"]) not in assigned_ids
    ]


def list_available_sps_for_group(
    requesting_user: RequestingUser,
    group_id: str,
) -> list[dict]:
    """List SPs not yet directly assigned to a group (for assign dropdown).

    Authorization: Requires admin role.

    Returns:
        List of dicts with id, name for unassigned SPs.
    """
    require_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Get all SPs
    all_sps = database.service_providers.list_service_providers(tenant_id)

    # Get already-assigned SP IDs for this group
    assigned = database.sp_group_assignments.list_assignments_for_group(tenant_id, group_id)
    assigned_ids = {str(row["sp_id"]) for row in assigned}

    return [
        {"id": str(sp["id"]), "name": sp["name"]}
        for sp in all_sps
        if str(sp["id"]) not in assigned_ids
    ]


def check_user_sp_access(tenant_id: str, user_id: str, sp_id: str) -> bool:
    """Check if a user can access an SP via group assignments.

    Internal function, no authorization check. Returns True if user
    has access (is a member of an assigned group or a descendant).
    """
    return database.sp_group_assignments.user_can_access_sp(tenant_id, user_id, sp_id)


def get_user_accessible_apps_admin(
    requesting_user: RequestingUser,
    target_user_id: str,
) -> UserAccessibleAppList:
    """Get all apps accessible to a target user, with group attribution.

    Authorization: Requires admin role.
    """
    require_admin(requesting_user, log_failure=True, service_name="service_providers")
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    # Verify target user exists
    user_row = database.users.get_user_by_id(tenant_id, target_user_id)
    if user_row is None:
        raise NotFoundError(message="User not found", code="user_not_found")

    rows = database.sp_group_assignments.get_accessible_sps_with_attribution(
        tenant_id, target_user_id
    )

    # Aggregate rows by SP id
    apps_by_id: dict[str, UserAccessibleApp] = {}
    for row in rows:
        sp_id = str(row["id"])
        if sp_id not in apps_by_id:
            apps_by_id[sp_id] = UserAccessibleApp(
                id=sp_id,
                name=row["name"],
                description=row.get("description"),
                entity_id=row.get("entity_id"),
                available_to_all=bool(row["available_to_all"]),
                granting_groups=[],
            )
        # Add granting group if present (not for available_to_all rows)
        if row.get("granting_group_id"):
            group = GrantingGroup(
                id=str(row["granting_group_id"]),
                name=row["granting_group_name"],
            )
            # Avoid duplicate groups (user may be in multiple descendant groups)
            existing_ids = {g.id for g in apps_by_id[sp_id].granting_groups}
            if group.id not in existing_ids:
                apps_by_id[sp_id].granting_groups.append(group)

    items = sorted(apps_by_id.values(), key=lambda a: a.name.lower())
    return UserAccessibleAppList(items=items, total=len(items))


def get_user_accessible_apps(
    requesting_user: RequestingUser,
) -> UserAppList:
    """Get all apps accessible to the requesting user.

    Authorization: Any authenticated user.
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    user_id = requesting_user["id"]

    rows = database.sp_group_assignments.get_accessible_sps_for_user(tenant_id, user_id)
    items = [
        UserApp(
            id=str(row["id"]),
            name=row["name"],
            description=row.get("description"),
            entity_id=row["entity_id"],
            has_logo=row.get("has_logo", False),
            logo_updated_at=row.get("logo_updated_at"),
        )
        for row in rows
    ]
    return UserAppList(items=items, total=len(items))
