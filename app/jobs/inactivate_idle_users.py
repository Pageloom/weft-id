"""Automatic user inactivation for idle accounts.

This module provides the scheduled job that inactivates users who haven't
been active for longer than their tenant's configured threshold.
"""

import logging
from typing import Any

import database
from database._core import session
from services.event_log import log_event

logger = logging.getLogger(__name__)


def inactivate_idle_users() -> dict[str, Any]:
    """
    Check all tenants for idle users and inactivate them.

    This function is called directly by the worker's cleanup timer (daily),
    not as a queued job.

    For each tenant with inactivity_threshold_days configured:
    - Find active users where last_activity_at < threshold
    - Inactivate each user
    - Revoke OAuth tokens
    - Log event for each inactivation

    Returns:
        Dict with tenants_processed, users_inactivated, and details
    """
    logger.info("Starting idle user inactivation check...")

    # Get all tenants with inactivity threshold configured
    tenants = database.security.get_all_tenants_with_inactivity_threshold()

    if not tenants:
        logger.info("No tenants have inactivity threshold configured")
        return {"tenants_processed": 0, "users_inactivated": 0, "details": []}

    logger.info("Found %d tenants with inactivity threshold", len(tenants))

    total_inactivated = 0
    details = []

    for tenant in tenants:
        tenant_id = str(tenant["tenant_id"])
        threshold_days = tenant["inactivity_threshold_days"]

        try:
            # Use tenant-scoped session for RLS
            with session(tenant_id=tenant_id):
                result = _process_tenant(tenant_id, threshold_days)
                total_inactivated += result["count"]
                if result["count"] > 0:
                    details.append(
                        {
                            "tenant_id": tenant_id,
                            "inactivated": result["count"],
                            "user_ids": result["user_ids"],
                        }
                    )
        except Exception as e:
            logger.exception(
                "Failed to process tenant %s for idle user inactivation: %s",
                tenant_id,
                e,
            )
            details.append(
                {
                    "tenant_id": tenant_id,
                    "error": str(e),
                }
            )

    logger.info(
        "Idle user inactivation completed: %d tenants processed, %d users inactivated",
        len(tenants),
        total_inactivated,
    )

    return {
        "tenants_processed": len(tenants),
        "users_inactivated": total_inactivated,
        "details": details,
    }


def _process_tenant(tenant_id: str, threshold_days: int) -> dict[str, Any]:
    """
    Process a single tenant for idle user inactivation.

    Args:
        tenant_id: Tenant ID to process
        threshold_days: Number of days of inactivity before auto-inactivation

    Returns:
        Dict with count and user_ids of inactivated users
    """
    # Get idle users
    idle_users = database.users.get_idle_users_for_tenant(tenant_id, threshold_days)

    if not idle_users:
        logger.debug("Tenant %s: no idle users found", tenant_id)
        return {"count": 0, "user_ids": []}

    logger.info(
        "Tenant %s: found %d idle users (threshold: %d days)",
        tenant_id,
        len(idle_users),
        threshold_days,
    )

    inactivated_user_ids = []

    for user in idle_users:
        user_id = str(user["user_id"])

        try:
            # Inactivate the user
            database.users.inactivate_user(tenant_id, user_id)

            # Revoke OAuth tokens
            database.oauth2.revoke_all_user_tokens(tenant_id, user_id)

            # Log the event (with system as actor since this is automated)
            log_event(
                tenant_id=tenant_id,
                actor_user_id="system",  # System action (no real user)
                artifact_type="user",
                artifact_id=user_id,
                event_type="user_auto_inactivated",
                metadata={
                    "reason": "inactivity",
                    "threshold_days": threshold_days,
                    "last_activity_at": (
                        user["last_activity_at"].isoformat()
                        if user.get("last_activity_at")
                        else None
                    ),
                },
            )

            inactivated_user_ids.append(user_id)
            logger.info(
                "Tenant %s: inactivated user %s (%s %s) due to inactivity",
                tenant_id,
                user_id,
                user.get("first_name", ""),
                user.get("last_name", ""),
            )

        except Exception as e:
            logger.error(
                "Tenant %s: failed to inactivate user %s: %s",
                tenant_id,
                user_id,
                e,
            )

    return {"count": len(inactivated_user_ids), "user_ids": inactivated_user_ids}
