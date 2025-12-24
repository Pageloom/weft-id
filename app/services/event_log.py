"""Event logging utilities for service layer.

This module provides:
1. The logging helper that service functions call after successful writes.
   The culture is: "If there is a write, there is a log."
2. Read functions for the event log viewer (admin only).

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
from schemas.event_log import EventLogItem, EventLogListResponse
from services.activity import track_activity
from services.exceptions import ForbiddenError, NotFoundError
from services.types import RequestingUser

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

    # Track activity on every write (force=True bypasses cache)
    # Skip for system actor since it's not a real user
    if actor_user_id != SYSTEM_ACTOR_ID:
        track_activity(tenant_id, actor_user_id, force=True)


# ============================================================================
# Event Log Viewer Functions (Admin Only)
# ============================================================================


def _require_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not admin or super_admin."""
    if user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
        )


def _get_actor_name(tenant_id: str, user_id: str) -> str:
    """Get display name for an actor."""
    if user_id == SYSTEM_ACTOR_ID:
        return "System"

    user = database.users.get_user_by_id(tenant_id, user_id)
    if user:
        if user.get("is_anonymized"):
            return "[Anonymized User]"
        first_name = user.get("first_name", "")
        last_name = user.get("last_name", "")
        return f"{first_name} {last_name}".strip() or "Unknown User"

    return "Unknown User"


def list_events(
    requesting_user: RequestingUser,
    page: int = 1,
    limit: int = 50,
) -> EventLogListResponse:
    """
    List event logs with pagination.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request
        page: Page number (1-indexed)
        limit: Number of items per page

    Returns:
        EventLogListResponse with paginated items
    """
    _require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    offset = (page - 1) * limit

    events = database.event_log.list_events(tenant_id, limit=limit, offset=offset)
    total = database.event_log.count_events(tenant_id)

    # Enrich with actor names
    items = []
    for e in events:
        actor_name = _get_actor_name(tenant_id, str(e["actor_user_id"]))
        items.append(
            EventLogItem(
                id=str(e["id"]),
                actor_user_id=str(e["actor_user_id"]),
                actor_name=actor_name,
                artifact_type=e["artifact_type"],
                artifact_id=str(e["artifact_id"]),
                event_type=e["event_type"],
                metadata=e["metadata"],
                created_at=e["created_at"],
            )
        )

    return EventLogListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
    )


def get_event(
    requesting_user: RequestingUser,
    event_id: str,
) -> EventLogItem:
    """
    Get a single event log entry with full details.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request
        event_id: The event log ID

    Returns:
        EventLogItem with full details

    Raises:
        NotFoundError: If event not found
    """
    _require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]

    event = database.event_log.get_event_by_id(tenant_id, event_id)
    if not event:
        raise NotFoundError(
            message="Event not found",
            code="event_not_found",
        )

    actor_name = _get_actor_name(tenant_id, str(event["actor_user_id"]))

    return EventLogItem(
        id=str(event["id"]),
        actor_user_id=str(event["actor_user_id"]),
        actor_name=actor_name,
        artifact_type=event["artifact_type"],
        artifact_id=str(event["artifact_id"]),
        event_type=event["event_type"],
        metadata=event["metadata"],
        created_at=event["created_at"],
    )
