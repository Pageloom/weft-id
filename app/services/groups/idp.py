"""IdP group operations.

This module provides business logic for IdP-managed group operations:
- create_idp_base_group
- get_or_create_idp_group
- sync_user_idp_groups
- invalidate_idp_groups
- list_groups_for_idp
- ensure_user_in_base_group / remove_user_from_base_group
- ensure_users_in_base_group
- remove_user_from_all_idp_groups
- move_users_between_idps

These are system-level operations typically invoked during SAML authentication
or IdP lifecycle events.
"""

import logging

import database
from schemas.groups import GroupDetail, GroupSummary
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.exceptions import ConflictError, ValidationError
from services.groups._converters import _row_to_detail, _row_to_summary
from services.types import RequestingUser
from utils.request_context import system_context


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
                artifact_id=group_id,
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
                artifact_id=group_id,
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

    # Protect base group from removal (managed by assignment, not assertions)
    base_group_id = database.groups.get_idp_base_group_id(tenant_id, idp_id)
    if base_group_id:
        current_group_ids.discard(base_group_id)

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


logger = logging.getLogger(__name__)


# ============================================================================
# Base Group Membership Helpers
# ============================================================================


def _get_or_create_base_group_id(
    tenant_id: str,
    idp_id: str,
    idp_name: str,
) -> str:
    """Get the base group ID for an IdP, creating it if it doesn't exist."""
    base_group_id = database.groups.get_idp_base_group_id(tenant_id, idp_id)
    if base_group_id:
        return base_group_id

    # Base group missing (IdP created outside service layer). Auto-create it.
    logger.info(
        "Auto-creating missing base group for IdP %s (%s)",
        idp_id,
        idp_name,
    )
    try:
        group = create_idp_base_group(tenant_id, idp_id, idp_name)
        return str(group.id)
    except ConflictError:
        # Race condition: another request created it between our check and create.
        # Re-query to get the existing group.
        base_group_id = database.groups.get_idp_base_group_id(tenant_id, idp_id)
        if base_group_id:
            return base_group_id
        raise ValidationError(
            message=f"Failed to create or find base group for IdP {idp_name}",
            code="base_group_creation_failed",
        )


def ensure_user_in_base_group(
    tenant_id: str,
    user_id: str,
    user_email: str,
    idp_id: str,
    idp_name: str,
) -> None:
    """Add user to the IdP's base group if not already a member.

    Called from all IdP assignment paths to guarantee every assigned user
    is in the base group.
    """
    base_group_id = _get_or_create_base_group_id(tenant_id, idp_id, idp_name)

    if database.groups.is_group_member(tenant_id, base_group_id, user_id):
        return

    database.groups.bulk_add_user_to_groups(tenant_id, tenant_id, user_id, [base_group_id])

    with system_context():
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="group_membership",
            artifact_id=base_group_id,
            event_type="idp_group_member_added",
            metadata={
                "idp_id": idp_id,
                "idp_name": idp_name,
                "user_id": user_id,
                "user_email": user_email,
                "group_id": base_group_id,
                "group_name": idp_name,
                "sync_source": "idp_assignment",
            },
        )


def remove_user_from_base_group(
    tenant_id: str,
    user_id: str,
    user_email: str,
    idp_id: str,
    idp_name: str,
) -> None:
    """Remove user from the IdP's base group."""
    base_group_id = database.groups.get_idp_base_group_id(tenant_id, idp_id)
    if not base_group_id:
        return

    database.groups.bulk_remove_user_from_groups(tenant_id, user_id, [base_group_id])

    with system_context():
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="group_membership",
            artifact_id=base_group_id,
            event_type="idp_group_member_removed",
            metadata={
                "idp_id": idp_id,
                "idp_name": idp_name,
                "user_id": user_id,
                "user_email": user_email,
                "group_id": base_group_id,
                "group_name": idp_name,
                "sync_source": "idp_reassignment",
            },
        )


def ensure_users_in_base_group(
    tenant_id: str,
    user_ids: list[str],
    idp_id: str,
    idp_name: str,
) -> int:
    """Add multiple users to the IdP's base group.

    Uses bulk_add_user_to_groups which handles ON CONFLICT DO NOTHING,
    so already-members are silently skipped.

    Returns:
        Number of memberships actually created.
    """
    if not user_ids:
        return 0

    base_group_id = _get_or_create_base_group_id(tenant_id, idp_id, idp_name)

    total_added = 0
    for user_id in user_ids:
        added = database.groups.bulk_add_user_to_groups(
            tenant_id, tenant_id, user_id, [base_group_id]
        )
        if added:
            total_added += added
            with system_context():
                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=SYSTEM_ACTOR_ID,
                    artifact_type="group_membership",
                    artifact_id=base_group_id,
                    event_type="idp_group_member_added",
                    metadata={
                        "idp_id": idp_id,
                        "idp_name": idp_name,
                        "user_id": user_id,
                        "group_id": base_group_id,
                        "group_name": idp_name,
                        "sync_source": "idp_assignment",
                    },
                )

    return total_added


def remove_user_from_all_idp_groups(
    tenant_id: str,
    user_id: str,
    user_email: str,
    idp_id: str,
    idp_name: str,
) -> None:
    """Remove user from all groups (base + sub-groups) for an IdP."""
    group_ids = database.groups.get_user_idp_group_ids(tenant_id, user_id, idp_id)
    if not group_ids:
        return

    # Collect group names before removal for logging
    groups_info: list[tuple[str, str]] = []
    for gid in group_ids:
        group = database.groups.get_group_by_id(tenant_id, gid)
        groups_info.append((gid, group["name"] if group else "Unknown"))

    database.groups.bulk_remove_user_from_groups(tenant_id, user_id, group_ids)

    with system_context():
        for gid, gname in groups_info:
            log_event(
                tenant_id=tenant_id,
                actor_user_id=SYSTEM_ACTOR_ID,
                artifact_type="group_membership",
                artifact_id=gid,
                event_type="idp_group_member_removed",
                metadata={
                    "idp_id": idp_id,
                    "idp_name": idp_name,
                    "user_id": user_id,
                    "user_email": user_email,
                    "group_id": gid,
                    "group_name": gname,
                    "sync_source": "idp_reassignment",
                },
            )


def move_users_between_idps(
    tenant_id: str,
    user_ids: list[str],
    old_idp_id: str,
    old_idp_name: str,
    new_idp_id: str,
    new_idp_name: str,
) -> None:
    """Remove users from all old IdP groups and add them to the new IdP's base group."""
    for user_id in user_ids:
        # Remove from all old IdP groups (base + sub-groups)
        old_group_ids = database.groups.get_user_idp_group_ids(tenant_id, user_id, old_idp_id)
        if old_group_ids:
            database.groups.bulk_remove_user_from_groups(tenant_id, user_id, old_group_ids)
            with system_context():
                for gid in old_group_ids:
                    log_event(
                        tenant_id=tenant_id,
                        actor_user_id=SYSTEM_ACTOR_ID,
                        artifact_type="group_membership",
                        artifact_id=gid,
                        event_type="idp_group_member_removed",
                        metadata={
                            "idp_id": old_idp_id,
                            "idp_name": old_idp_name,
                            "user_id": user_id,
                            "group_id": gid,
                            "sync_source": "idp_reassignment",
                        },
                    )

    # Add all users to new IdP's base group
    ensure_users_in_base_group(tenant_id, user_ids, new_idp_id, new_idp_name)


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
