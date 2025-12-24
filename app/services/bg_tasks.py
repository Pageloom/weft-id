"""Background tasks service layer.

This module provides service-level functions for creating and managing
background tasks.
"""

import logging

import database
from services.activity import track_activity
from services.event_log import log_event
from services.exceptions import ForbiddenError
from services.types import RequestingUser

logger = logging.getLogger(__name__)


def _require_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not admin or super_admin."""
    if user["role"] not in ("admin", "super_admin"):
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
        )


def create_export_task(requesting_user: RequestingUser) -> dict | None:
    """
    Create a background task to export all event logs.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request

    Returns:
        Dict with task_id and created_at, or None if creation failed
    """
    _require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    result = database.bg_tasks.create_task(
        tenant_id=requesting_user["tenant_id"],
        job_type="export_events",
        created_by=requesting_user["id"],
        payload=None,  # No payload needed for full export
    )

    if result:
        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="bg_task",
            artifact_id=str(result["id"]),
            event_type="export_task_created",
            metadata={"job_type": "export_events"},
        )

    return result
