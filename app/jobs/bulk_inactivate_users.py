"""Bulk inactivation job handler.

Processes a list of user IDs, inactivating each one. Skips users that
are already inactivated, are service users, or are the last super admin.
Revokes OAuth tokens for each inactivated user. Logs an audit event for
each successful inactivation.
"""

import logging
from typing import Any

import database
from jobs.registry import register_handler
from services.event_log import log_event
from utils.request_context import system_context

logger = logging.getLogger(__name__)


@register_handler("bulk_inactivate_users")
def handle_bulk_inactivate_users(task: dict) -> dict[str, Any]:
    """Inactivate users in bulk.

    Args:
        task: Dict with id, tenant_id, job_type, payload, created_by.
              payload contains {"user_ids": [str, ...]}

    Returns:
        Dict with output summary, counts, and per-item details.
    """
    tenant_id = str(task["tenant_id"])
    created_by = str(task["created_by"])
    user_ids = task["payload"]["user_ids"]

    inactivated = 0
    skipped = 0
    errors = 0
    details: list[dict[str, str]] = []

    with system_context():
        for user_id in user_ids:
            try:
                user = database.users.get_user_by_id(tenant_id, user_id)
                if not user:
                    errors += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "name": "Unknown",
                            "status": "error",
                            "reason": "User not found",
                        }
                    )
                    continue

                name = f"{user['first_name']} {user['last_name']}"

                # Cannot inactivate the requesting admin
                if user_id == created_by:
                    skipped += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "name": name,
                            "status": "skipped",
                            "reason": "Cannot inactivate yourself",
                        }
                    )
                    continue

                # Already inactivated
                if user.get("is_inactivated"):
                    skipped += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "name": name,
                            "status": "skipped",
                            "reason": "Already inactivated",
                        }
                    )
                    continue

                # Service user protection
                if database.users.is_service_user(tenant_id, user_id):
                    skipped += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "name": name,
                            "status": "skipped",
                            "reason": "Service user",
                        }
                    )
                    continue

                # Last super admin protection
                if user["role"] == "super_admin":
                    active_count = database.users.count_active_super_admins(tenant_id)
                    if active_count <= 1:
                        skipped += 1
                        details.append(
                            {
                                "user_id": user_id,
                                "name": name,
                                "status": "skipped",
                                "reason": "Last super admin",
                            }
                        )
                        continue

                database.users.inactivate_user(tenant_id, user_id)
                database.oauth2.revoke_all_user_tokens(tenant_id, user_id)

                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=created_by,
                    artifact_type="user",
                    artifact_id=user_id,
                    event_type="user_inactivated",
                    metadata={"bulk_operation": True},
                )

                inactivated += 1
                details.append(
                    {
                        "user_id": user_id,
                        "name": name,
                        "status": "inactivated",
                        "reason": "Inactivated and tokens revoked",
                    }
                )

            except Exception:
                logger.exception("Failed to inactivate user %s", user_id)
                errors += 1
                details.append(
                    {
                        "user_id": user_id,
                        "name": "Unknown",
                        "status": "error",
                        "reason": "Unexpected error",
                    }
                )

    output = f"{inactivated} inactivated, {skipped} skipped, {errors} errors"
    logger.info("Bulk inactivation complete: %s (tenant=%s)", output, tenant_id)

    return {
        "output": output,
        "inactivated": inactivated,
        "skipped": skipped,
        "errors": errors,
        "details": details,
    }
