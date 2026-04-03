"""Background tasks service layer.

This module provides service-level functions for creating and managing
background tasks.
"""

import logging
from datetime import UTC, date, datetime

import database
from schemas.bg_tasks import JobDetail, JobListItem, JobListResponse, JobStatus
from services.activity import track_activity
from services.auth import require_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, ValidationError
from services.types import RequestingUser

logger = logging.getLogger(__name__)


def create_export_task(
    requesting_user: RequestingUser,
    start_date: date | None = None,
    end_date: date | None = None,
) -> dict | None:
    """
    Create a background task to export event logs as encrypted XLSX.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request
        start_date: Optional start date filter (inclusive)
        end_date: Optional end date filter (inclusive)

    Returns:
        Dict with task_id and created_at, or None if creation failed
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    today = datetime.now(UTC).date()
    if start_date and end_date and start_date > end_date:
        raise ValidationError(
            message="Start date must be before end date",
            code="invalid_date_range",
        )
    if start_date and start_date > today:
        raise ValidationError(
            message="Start date cannot be in the future",
            code="future_date",
        )
    if end_date and end_date > today:
        raise ValidationError(
            message="End date cannot be in the future",
            code="future_date",
        )

    payload: dict | None = None
    if start_date or end_date:
        payload = {}
        if start_date:
            payload["start_date"] = start_date.isoformat()
        if end_date:
            payload["end_date"] = end_date.isoformat()

    result = database.bg_tasks.create_task(
        tenant_id=requesting_user["tenant_id"],
        job_type="export_events",
        created_by=requesting_user["id"],
        payload=payload,
    )

    if result:
        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="bg_task",
            artifact_id=str(result["id"]),
            event_type="export_task_created",
            metadata={
                "job_type": "export_events",
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None,
            },
        )

    return result


def create_user_export_task(
    requesting_user: RequestingUser,
) -> dict | None:
    """
    Create a background task to export user audit data as encrypted XLSX.

    Authorization: Requires admin or super_admin role.

    Returns:
        Dict with task id and created_at, or None if creation failed.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    result = database.bg_tasks.create_task(
        tenant_id=requesting_user["tenant_id"],
        job_type="export_users",
        created_by=requesting_user["id"],
    )

    if result:
        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="bg_task",
            artifact_id=str(result["id"]),
            event_type="user_export_task_created",
            metadata={"job_type": "export_users"},
        )

    return result


def create_bulk_add_emails_task(
    requesting_user: RequestingUser,
    items: list[dict],
) -> dict | None:
    """
    Create a background task to add secondary emails to users in bulk.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request
        items: List of dicts with user_id and email keys

    Returns:
        Dict with task_id and created_at, or None if creation failed

    Raises:
        ValidationError: If items list is empty
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    if not items:
        raise ValidationError(
            message="At least one user-email pair is required",
            code="empty_items",
        )

    result = database.bg_tasks.create_task(
        tenant_id=requesting_user["tenant_id"],
        job_type="bulk_add_secondary_emails",
        created_by=requesting_user["id"],
        payload={"items": items},
    )

    if result:
        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="bg_task",
            artifact_id=str(result["id"]),
            event_type="bulk_secondary_emails_task_created",
            metadata={
                "job_type": "bulk_add_secondary_emails",
                "item_count": len(items),
            },
        )

    return result


def create_bulk_primary_email_preview_task(
    requesting_user: RequestingUser,
    items: list[dict],
) -> dict | None:
    """Create a dry-run background task to preview bulk primary email changes.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request
        items: List of dicts with user_id and new_primary_email keys

    Returns:
        Dict with task id and created_at, or None if creation failed
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    if not items:
        raise ValidationError(
            message="At least one user-email pair is required",
            code="empty_items",
        )

    result = database.bg_tasks.create_task(
        tenant_id=requesting_user["tenant_id"],
        job_type="bulk_primary_email_preview",
        created_by=requesting_user["id"],
        payload={"items": items},
    )

    if result:
        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="bg_task",
            artifact_id=str(result["id"]),
            event_type="bulk_primary_email_preview_task_created",
            metadata={
                "job_type": "bulk_primary_email_preview",
                "item_count": len(items),
            },
        )

    return result


def create_bulk_primary_email_apply_task(
    requesting_user: RequestingUser,
    items: list[dict],
    preview_job_id: str,
) -> dict | None:
    """Create a background task to execute bulk primary email changes.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request
        items: List of dicts with user_id, new_primary_email, and idp_disposition keys
        preview_job_id: ID of the completed preview job

    Returns:
        Dict with task id and created_at, or None if creation failed
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    if not items:
        raise ValidationError(
            message="At least one user-email pair is required",
            code="empty_items",
        )

    result = database.bg_tasks.create_task(
        tenant_id=requesting_user["tenant_id"],
        job_type="bulk_primary_email_apply",
        created_by=requesting_user["id"],
        payload={"items": items, "preview_job_id": preview_job_id},
    )

    if result:
        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="bg_task",
            artifact_id=str(result["id"]),
            event_type="bulk_primary_email_apply_task_created",
            metadata={
                "job_type": "bulk_primary_email_apply",
                "item_count": len(items),
                "preview_job_id": preview_job_id,
            },
        )

    return result


def preview_bulk_inactivate(
    requesting_user: RequestingUser,
    user_ids: list[str],
) -> dict:
    """Check eligibility for bulk inactivation without executing it.

    Authorization: Requires admin or super_admin role.

    Returns:
        Dict with eligible_ids, eligible count, skipped list with reasons.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    admin_id = requesting_user["id"]
    eligible_ids: list[str] = []
    skipped: list[dict[str, str]] = []

    for user_id in user_ids:
        user = database.users.get_user_by_id(tenant_id, user_id)
        if not user:
            skipped.append({"user_id": user_id, "name": "Unknown", "reason": "User not found"})
            continue

        name = f"{user['first_name']} {user['last_name']}"

        if user_id == admin_id:
            skipped.append(
                {
                    "user_id": user_id,
                    "name": name,
                    "reason": "Cannot inactivate yourself",
                }
            )
            continue

        if user.get("is_inactivated"):
            skipped.append({"user_id": user_id, "name": name, "reason": "Already inactivated"})
            continue

        if database.users.is_service_user(tenant_id, user_id):
            skipped.append({"user_id": user_id, "name": name, "reason": "Service user"})
            continue

        if user["role"] == "super_admin":
            active_count = database.users.count_active_super_admins(tenant_id)
            if active_count <= 1:
                skipped.append({"user_id": user_id, "name": name, "reason": "Last super admin"})
                continue

        eligible_ids.append(user_id)

    return {
        "eligible_ids": eligible_ids,
        "eligible": len(eligible_ids),
        "skipped": skipped,
    }


def preview_bulk_reactivate(
    requesting_user: RequestingUser,
    user_ids: list[str],
) -> dict:
    """Check eligibility for bulk reactivation without executing it.

    Authorization: Requires admin or super_admin role.

    Returns:
        Dict with eligible_ids, eligible count, skipped list with reasons.
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tenant_id = requesting_user["tenant_id"]
    eligible_ids: list[str] = []
    skipped: list[dict[str, str]] = []

    for user_id in user_ids:
        user = database.users.get_user_by_id(tenant_id, user_id)
        if not user:
            skipped.append({"user_id": user_id, "name": "Unknown", "reason": "User not found"})
            continue

        name = f"{user['first_name']} {user['last_name']}"

        if user.get("is_anonymized"):
            skipped.append({"user_id": user_id, "name": name, "reason": "Anonymized user"})
            continue

        if not user.get("is_inactivated"):
            skipped.append({"user_id": user_id, "name": name, "reason": "Not inactivated"})
            continue

        eligible_ids.append(user_id)

    return {
        "eligible_ids": eligible_ids,
        "eligible": len(eligible_ids),
        "skipped": skipped,
    }


def create_bulk_inactivate_task(
    requesting_user: RequestingUser,
    user_ids: list[str],
) -> dict | None:
    """Create a background task to inactivate users in bulk.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request
        user_ids: List of user IDs to inactivate

    Returns:
        Dict with task id and created_at, or None if creation failed
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    if not user_ids:
        raise ValidationError(
            message="At least one user ID is required",
            code="empty_user_ids",
        )

    result = database.bg_tasks.create_task(
        tenant_id=requesting_user["tenant_id"],
        job_type="bulk_inactivate_users",
        created_by=requesting_user["id"],
        payload={"user_ids": user_ids},
    )

    if result:
        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="bg_task",
            artifact_id=str(result["id"]),
            event_type="bulk_inactivate_task_created",
            metadata={
                "job_type": "bulk_inactivate_users",
                "item_count": len(user_ids),
            },
        )

    return result


def create_bulk_reactivate_task(
    requesting_user: RequestingUser,
    user_ids: list[str],
) -> dict | None:
    """Create a background task to reactivate users in bulk.

    Authorization: Requires admin or super_admin role.

    Args:
        requesting_user: The user making the request
        user_ids: List of user IDs to reactivate

    Returns:
        Dict with task id and created_at, or None if creation failed
    """
    require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    if not user_ids:
        raise ValidationError(
            message="At least one user ID is required",
            code="empty_user_ids",
        )

    result = database.bg_tasks.create_task(
        tenant_id=requesting_user["tenant_id"],
        job_type="bulk_reactivate_users",
        created_by=requesting_user["id"],
        payload={"user_ids": user_ids},
    )

    if result:
        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="bg_task",
            artifact_id=str(result["id"]),
            event_type="bulk_reactivate_task_created",
            metadata={
                "job_type": "bulk_reactivate_users",
                "item_count": len(user_ids),
            },
        )

    return result


def list_user_jobs(requesting_user: RequestingUser) -> JobListResponse:
    """
    List background jobs created by the requesting user.

    Authorization: Authenticated users see their own jobs.

    Args:
        requesting_user: The user making the request

    Returns:
        JobListResponse with jobs and polling flag
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    tasks = database.bg_tasks.list_tasks_for_user(
        tenant_id=requesting_user["tenant_id"],
        user_id=requesting_user["id"],
        limit=50,
    )

    jobs = [
        JobListItem(
            id=str(task["id"]),
            job_type=task["job_type"],
            status=JobStatus(task["status"]),
            created_at=task["created_at"],
            started_at=task.get("started_at"),
            completed_at=task.get("completed_at"),
            error=task.get("error"),
            result=task.get("result"),
            created_by=str(task["created_by"]),
        )
        for task in tasks
    ]

    has_active_jobs = any(job.status in (JobStatus.PENDING, JobStatus.PROCESSING) for job in jobs)

    return JobListResponse(jobs=jobs, has_active_jobs=has_active_jobs)


def get_job_detail(requesting_user: RequestingUser, job_id: str) -> JobDetail:
    """
    Get detailed job information including output.

    Authorization: User must own the job (created_by match).

    Args:
        requesting_user: The user making the request
        job_id: The job ID

    Returns:
        JobDetail with full job information

    Raises:
        NotFoundError: If job not found or not owned by user
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    task = database.bg_tasks.get_task_for_user(
        tenant_id=requesting_user["tenant_id"],
        user_id=requesting_user["id"],
        task_id=job_id,
    )

    if not task:
        raise NotFoundError(
            message="Job not found",
            code="job_not_found",
        )

    return JobDetail(
        id=str(task["id"]),
        job_type=task["job_type"],
        status=JobStatus(task["status"]),
        created_at=task["created_at"],
        started_at=task.get("started_at"),
        completed_at=task.get("completed_at"),
        error=task.get("error"),
        result=task.get("result"),
        created_by=str(task["created_by"]),
    )


def delete_jobs(requesting_user: RequestingUser, job_ids: list[str]) -> int:
    """
    Delete multiple completed/failed jobs.

    Authorization: User can only delete their own completed/failed jobs.

    Args:
        requesting_user: The user making the request
        job_ids: List of job IDs to delete

    Returns:
        Number of jobs deleted
    """
    track_activity(requesting_user["tenant_id"], requesting_user["id"])

    count = database.bg_tasks.delete_tasks(
        tenant_id=requesting_user["tenant_id"],
        user_id=requesting_user["id"],
        task_ids=job_ids,
    )

    if count > 0:
        log_event(
            tenant_id=requesting_user["tenant_id"],
            actor_user_id=requesting_user["id"],
            artifact_type="bg_task",
            artifact_id=job_ids[0],
            event_type="jobs_deleted",
            metadata={"count": count, "job_ids": job_ids},
        )

    return count
