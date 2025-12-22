"""Event logging utilities for service layer.

This module provides the logging helper that service functions call after
successful writes. The culture is: "If there is a write, there is a log."

Usage in service functions:
    from services.event_log import log_event, SYSTEM_ACTOR_ID

    def create_user(requesting_user: RequestingUser, ...):
        # ... business logic ...
        # ... database write ...

        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_created",
            metadata={"role": user_data.role},
        )

        return result
"""

import logging
from typing import Any

import database

# System actor UUID for automated/background processes.
# This is a well-known constant, not a real user record.
# Use this when there's no human actor (e.g., cron jobs, system migrations).
SYSTEM_ACTOR_ID = "00000000-0000-0000-0000-000000000000"

logger = logging.getLogger(__name__)


def log_event(
    tenant_id: str,
    actor_user_id: str,
    artifact_type: str,
    artifact_id: str,
    event_type: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    """
    Log a service layer write operation.

    This is the primary interface for event logging. Call this after every
    successful database write in a service function.

    Args:
        tenant_id: Tenant ID
        actor_user_id: User who performed the action (use SYSTEM_ACTOR_ID for system actions)
        artifact_type: Entity type (e.g., "user", "privileged_domain", "tenant_settings")
        artifact_id: UUID of the affected entity
        event_type: Descriptive event (e.g., "user_created", "password_changed")
        metadata: Optional context-specific details as dict

    Note:
        This function is synchronous - the log entry is written before returning.
        It does not raise on failure to avoid disrupting the main business operation.
    """
    try:
        database.event_log.create_event(
            tenant_id=tenant_id,
            tenant_id_value=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            event_type=event_type,
            metadata=metadata,
        )
    except Exception as e:
        # Log the error but don't fail the main operation
        logger.error(
            "Failed to log event: %s (tenant=%s, actor=%s, artifact=%s/%s, event=%s)",
            str(e),
            tenant_id,
            actor_user_id,
            artifact_type,
            artifact_id,
            event_type,
        )
