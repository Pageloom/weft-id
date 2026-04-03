"""Bulk reactivation job handler.

Processes a list of user IDs, reactivating each one. Skips users that
are not inactivated or are anonymized. Clears reactivation denial flags.
Logs an audit event for each successful reactivation.
"""

import logging
from typing import Any

import database
from jobs.registry import register_handler
from services.event_log import log_event
from utils.request_context import system_context

logger = logging.getLogger(__name__)


@register_handler("bulk_reactivate_users")
def handle_bulk_reactivate_users(task: dict) -> dict[str, Any]:
    """Reactivate users in bulk.

    Args:
        task: Dict with id, tenant_id, job_type, payload, created_by.
              payload contains {"user_ids": [str, ...]}

    Returns:
        Dict with output summary, counts, and per-item details.
    """
    tenant_id = str(task["tenant_id"])
    created_by = str(task["created_by"])
    user_ids = task["payload"]["user_ids"]

    reactivated = 0
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

                # Cannot reactivate anonymized users (irreversible)
                if user.get("is_anonymized"):
                    skipped += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "name": name,
                            "status": "skipped",
                            "reason": "Anonymized user",
                        }
                    )
                    continue

                # Not inactivated
                if not user.get("is_inactivated"):
                    skipped += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "name": name,
                            "status": "skipped",
                            "reason": "Not inactivated",
                        }
                    )
                    continue

                database.users.reactivate_user(tenant_id, user_id)
                database.users.clear_reactivation_denied(tenant_id, user_id)

                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=created_by,
                    artifact_type="user",
                    artifact_id=user_id,
                    event_type="user_reactivated",
                    metadata={"bulk_operation": True},
                )

                reactivated += 1
                details.append(
                    {
                        "user_id": user_id,
                        "name": name,
                        "status": "reactivated",
                        "reason": "Reactivated",
                    }
                )

            except Exception:
                logger.exception("Failed to reactivate user %s", user_id)
                errors += 1
                details.append(
                    {
                        "user_id": user_id,
                        "name": "Unknown",
                        "status": "error",
                        "reason": "Unexpected error",
                    }
                )

    output = f"{reactivated} reactivated, {skipped} skipped, {errors} errors"
    logger.info("Bulk reactivation complete: %s (tenant=%s)", output, tenant_id)

    return {
        "output": output,
        "reactivated": reactivated,
        "skipped": skipped,
        "errors": errors,
        "details": details,
    }
