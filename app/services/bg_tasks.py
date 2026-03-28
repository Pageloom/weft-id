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
