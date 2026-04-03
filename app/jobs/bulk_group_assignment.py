"""Bulk group assignment job handler.

Processes a list of user IDs, adding each one to a specified group.
Skips users that are already members or not found. Rejects IdP groups.
Logs an audit event for each successful addition.
"""

import logging
from typing import Any

import database
from jobs.registry import register_handler
from services.event_log import log_event
from utils.request_context import system_context

logger = logging.getLogger(__name__)


@register_handler("bulk_group_assignment")
def handle_bulk_group_assignment(task: dict) -> dict[str, Any]:
    """Add users to a group in bulk.

    Args:
        task: Dict with id, tenant_id, job_type, payload, created_by.
              payload contains {"group_id": str, "user_ids": [str, ...]}

    Returns:
        Dict with output summary, counts, and per-item details.
    """
    tenant_id = str(task["tenant_id"])
    created_by = str(task["created_by"])
    group_id = task["payload"]["group_id"]
    user_ids = task["payload"]["user_ids"]

    added = 0
    skipped = 0
    errors = 0
    details: list[dict[str, str]] = []

    with system_context():
        # Validate group exists and is not IdP-managed
        group = database.groups.get_group_by_id(tenant_id, group_id)
        if not group:
            return {
                "output": "Group not found",
                "added": 0,
                "skipped": 0,
                "errors": len(user_ids),
                "details": [
                    {
                        "user_id": uid,
                        "name": "Unknown",
                        "status": "error",
                        "reason": "Group not found",
                    }
                    for uid in user_ids
                ],
            }

        group_name = group["name"]

        if group.get("group_type") == "idp":
            return {
                "output": "IdP groups cannot be modified manually",
                "added": 0,
                "skipped": 0,
                "errors": len(user_ids),
                "details": [
                    {
                        "user_id": uid,
                        "name": "Unknown",
                        "status": "error",
                        "reason": "IdP group (read-only)",
                    }
                    for uid in user_ids
                ],
            }

        for user_id in user_ids:
            try:
                user = database.users.get_user_by_id(tenant_id, user_id)
                if not user:
                    skipped += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "name": "Unknown",
                            "status": "skipped",
                            "reason": "User not found",
                        }
                    )
                    continue

                name = f"{user['first_name']} {user['last_name']}"

                # Already a member
                if database.groups.is_group_member(tenant_id, group_id, user_id):
                    skipped += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "name": name,
                            "status": "skipped",
                            "reason": "Already a member",
                        }
                    )
                    continue

                database.groups.add_group_member(tenant_id, tenant_id, group_id, user_id)

                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=created_by,
                    artifact_type="group_membership",
                    artifact_id=group_id,
                    event_type="group_member_added",
                    metadata={
                        "user_id": user_id,
                        "user_name": name,
                        "group_name": group_name,
                        "bulk_operation": True,
                    },
                )

                added += 1
                details.append(
                    {
                        "user_id": user_id,
                        "name": name,
                        "status": "added",
                        "reason": f"Added to {group_name}",
                    }
                )

            except Exception:
                logger.exception("Failed to add user %s to group %s", user_id, group_id)
                errors += 1
                details.append(
                    {
                        "user_id": user_id,
                        "name": "Unknown",
                        "status": "error",
                        "reason": "Unexpected error",
                    }
                )

    output = f"{added} added, {skipped} skipped, {errors} errors"
    logger.info(
        "Bulk group assignment complete: %s (group=%s, tenant=%s)",
        output,
        group_id,
        tenant_id,
    )

    return {
        "output": output,
        "added": added,
        "skipped": skipped,
        "errors": errors,
        "details": details,
    }
