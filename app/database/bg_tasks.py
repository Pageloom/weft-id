"""Background tasks database operations.

This module handles CRUD operations for background tasks.
The bg_tasks table has NO RLS - it's a system table accessed by the worker process.
"""

from typing import Any

from psycopg.types.json import Json

from ._core import UNSCOPED, TenantArg, execute, fetchall, fetchone


def create_task(
    tenant_id: str,
    job_type: str,
    created_by: str,
    payload: dict[str, Any] | None = None,
) -> dict | None:
    """Create a new background task.

    Args:
        tenant_id: The tenant this task belongs to
        job_type: The type of job (e.g., "export_events")
        created_by: User ID who triggered the task
        payload: Optional JSON payload for the job

    Returns:
        Dict with id and created_at, or None if insert failed
    """
    return fetchone(
        UNSCOPED,  # No RLS for bg_tasks
        """
        INSERT INTO bg_tasks (tenant_id, job_type, payload, created_by)
        VALUES (:tenant_id, :job_type, :payload, :created_by)
        RETURNING id, created_at
        """,
        {
            "tenant_id": tenant_id,
            "job_type": job_type,
            "payload": Json(payload) if payload else None,
            "created_by": created_by,
        },
    )


def claim_next_task() -> dict | None:
    """Atomically claim the next pending task for processing.

    Uses FOR UPDATE SKIP LOCKED to allow concurrent workers without conflicts.

    Returns:
        Task dict with id, tenant_id, job_type, payload, created_by, or None if no pending tasks
    """
    return fetchone(
        UNSCOPED,
        """
        UPDATE bg_tasks
        SET status = 'processing', started_at = now()
        WHERE id = (
            SELECT id FROM bg_tasks
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, tenant_id, job_type, payload, created_by
        """,
        {},
    )


def complete_task(task_id: str, result: dict[str, Any] | None = None) -> None:
    """Mark a task as completed.

    Args:
        task_id: The task ID
        result: Optional result data to store
    """
    execute(
        UNSCOPED,
        """
        UPDATE bg_tasks
        SET status = 'completed', completed_at = now(), result = :result
        WHERE id = :task_id
        """,
        {"task_id": task_id, "result": Json(result) if result else None},
    )


def fail_task(task_id: str, error: str) -> None:
    """Mark a task as failed.

    Args:
        task_id: The task ID
        error: Error message describing the failure
    """
    execute(
        UNSCOPED,
        """
        UPDATE bg_tasks
        SET status = 'failed', completed_at = now(), error = :error
        WHERE id = :task_id
        """,
        {"task_id": task_id, "error": error},
    )


def get_task(task_id: str) -> dict | None:
    """Get a task by ID.

    Args:
        task_id: The task ID

    Returns:
        Task dict or None if not found
    """
    return fetchone(
        UNSCOPED,
        """
        SELECT id, tenant_id, job_type, payload, status, result,
               created_by, created_at, started_at, completed_at, error
        FROM bg_tasks
        WHERE id = :task_id
        """,
        {"task_id": task_id},
    )


def list_tasks_for_tenant(
    tenant_id: TenantArg,
    limit: int = 50,
    job_type: str | None = None,
) -> list[dict]:
    """List recent tasks for a tenant.

    Args:
        tenant_id: The tenant ID
        limit: Maximum number of tasks to return
        job_type: Optional filter by job type

    Returns:
        List of task dicts
    """
    if job_type:
        return fetchall(
            UNSCOPED,  # We filter by tenant_id in WHERE clause
            """
            SELECT id, job_type, status, created_at, started_at, completed_at, error
            FROM bg_tasks
            WHERE tenant_id = :tenant_id AND job_type = :job_type
            ORDER BY created_at DESC
            LIMIT :limit
            """,
            {"tenant_id": tenant_id, "job_type": job_type, "limit": limit},
        )
    return fetchall(
        UNSCOPED,
        """
        SELECT id, job_type, status, created_at, started_at, completed_at, error
        FROM bg_tasks
        WHERE tenant_id = :tenant_id
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        {"tenant_id": tenant_id, "limit": limit},
    )


def count_pending_tasks(job_type: str | None = None) -> int:
    """Count pending tasks across all tenants.

    Args:
        job_type: Optional filter by job type

    Returns:
        Number of pending tasks
    """
    if job_type:
        result = fetchone(
            UNSCOPED,
            """
            SELECT COUNT(*) as count FROM bg_tasks
            WHERE status = 'pending' AND job_type = :job_type
            """,
            {"job_type": job_type},
        )
    else:
        result = fetchone(
            UNSCOPED,
            "SELECT COUNT(*) as count FROM bg_tasks WHERE status = 'pending'",
            {},
        )
    return result["count"] if result else 0


def list_tasks_for_user(
    tenant_id: TenantArg,
    user_id: str,
    limit: int = 50,
) -> list[dict]:
    """List tasks created by a specific user.

    Args:
        tenant_id: The tenant ID
        user_id: The user ID who created the tasks
        limit: Maximum number of tasks to return

    Returns:
        List of task dicts with id, job_type, status, result, created_at,
        started_at, completed_at, error
    """
    return fetchall(
        UNSCOPED,
        """
        SELECT id, job_type, status, result, created_at, started_at,
               completed_at, error, created_by
        FROM bg_tasks
        WHERE tenant_id = :tenant_id AND created_by = :user_id
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        {"tenant_id": tenant_id, "user_id": user_id, "limit": limit},
    )


def get_task_for_user(
    tenant_id: TenantArg,
    user_id: str,
    task_id: str,
) -> dict | None:
    """Get a single task if it belongs to the user.

    Args:
        tenant_id: The tenant ID
        user_id: The user ID who should own the task
        task_id: The task ID

    Returns:
        Full task record or None if not found or not owned by user
    """
    return fetchone(
        UNSCOPED,
        """
        SELECT id, tenant_id, job_type, payload, status, result,
               created_by, created_at, started_at, completed_at, error
        FROM bg_tasks
        WHERE id = :task_id AND tenant_id = :tenant_id AND created_by = :user_id
        """,
        {"task_id": task_id, "tenant_id": tenant_id, "user_id": user_id},
    )


def delete_tasks(
    tenant_id: TenantArg,
    user_id: str,
    task_ids: list[str],
) -> int:
    """Delete completed/failed tasks that belong to the user.

    Only tasks with status 'completed' or 'failed' can be deleted.

    Args:
        tenant_id: The tenant ID
        user_id: The user ID who owns the tasks
        task_ids: List of task IDs to delete

    Returns:
        Number of tasks deleted
    """
    if not task_ids:
        return 0

    return execute(
        UNSCOPED,
        """
        DELETE FROM bg_tasks
        WHERE tenant_id = :tenant_id
          AND created_by = :user_id
          AND id = ANY(:task_ids)
          AND status IN ('completed', 'failed')
        """,
        {"tenant_id": tenant_id, "user_id": user_id, "task_ids": task_ids},
    )
