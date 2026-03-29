"""Bulk add secondary emails job handler.

Processes a list of user-email pairs, adding each as a verified secondary
email address. Skips emails that already exist in the tenant. Logs an
audit event for each successful addition.
"""

import logging
from typing import Any

import database
from jobs.registry import register_handler
from services.event_log import log_event
from utils.request_context import system_context

logger = logging.getLogger(__name__)


@register_handler("bulk_add_secondary_emails")
def handle_bulk_add_secondary_emails(task: dict) -> dict[str, Any]:
    """Add secondary emails to users in bulk.

    Args:
        task: Dict with id, tenant_id, job_type, payload, created_by.
              payload contains {"items": [{"user_id": str, "email": str}, ...]}

    Returns:
        Dict with output summary, counts, and per-item details.
    """
    tenant_id = str(task["tenant_id"])
    created_by = str(task["created_by"])
    items = task["payload"]["items"]

    added = 0
    skipped = 0
    errors = 0
    details: list[dict[str, str]] = []

    with system_context():
        for item in items:
            user_id = item["user_id"]
            email = item["email"].strip().lower()

            try:
                # Check if email already exists in tenant
                if database.user_emails.email_exists(tenant_id, email):
                    skipped += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "email": email,
                            "status": "skipped",
                            "reason": "Email already exists in tenant",
                        }
                    )
                    continue

                # Verify user exists
                user = database.users.get_user_by_id(tenant_id, user_id)
                if not user:
                    errors += 1
                    details.append(
                        {
                            "user_id": user_id,
                            "email": email,
                            "status": "error",
                            "reason": "User not found",
                        }
                    )
                    continue

                # Add as verified secondary email (admin action)
                database.user_emails.add_verified_email(
                    tenant_id=tenant_id,
                    tenant_id_value=tenant_id,
                    user_id=user_id,
                    email=email,
                    is_primary=False,
                )

                # Log audit event for each addition
                log_event(
                    tenant_id=tenant_id,
                    actor_user_id=created_by,
                    artifact_type="user",
                    artifact_id=user_id,
                    event_type="email_added",
                    metadata={
                        "email": email,
                        "is_admin_action": True,
                        "auto_verified": True,
                        "bulk_operation": True,
                    },
                )

                added += 1
                details.append(
                    {
                        "user_id": user_id,
                        "email": email,
                        "status": "added",
                        "reason": "Added as verified secondary email",
                    }
                )

            except Exception:
                logger.exception("Failed to add email %s for user %s", email, user_id)
                errors += 1
                details.append(
                    {
                        "user_id": user_id,
                        "email": email,
                        "status": "error",
                        "reason": "Unexpected error",
                    }
                )

    output = f"{added} added, {skipped} skipped, {errors} errors"
    logger.info("Bulk add secondary emails complete: %s (tenant=%s)", output, tenant_id)

    return {
        "output": output,
        "added": added,
        "skipped": skipped,
        "errors": errors,
        "details": details,
    }
