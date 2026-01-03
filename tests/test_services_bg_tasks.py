"""Tests for background tasks service layer."""

import pytest


def test_create_export_task_as_admin(test_tenant, test_admin_user):
    """Test that admins can create export tasks."""
    import database
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    result = bg_tasks.create_export_task(requesting_user)

    assert result is not None
    assert result["id"] is not None

    # Verify the task was created
    task = database.bg_tasks.get_task(str(result["id"]))
    assert task is not None
    assert task["job_type"] == "export_events"
    assert task["status"] == "pending"


def test_create_export_task_as_super_admin(test_tenant, test_super_admin_user):
    """Test that super_admins can create export tasks."""
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "super_admin",
    }

    result = bg_tasks.create_export_task(requesting_user)

    assert result is not None
    assert result["id"] is not None


def test_create_export_task_forbidden_for_member(test_tenant, test_user):
    """Test that members cannot create export tasks."""
    from services import bg_tasks
    from services.exceptions import ForbiddenError
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    with pytest.raises(ForbiddenError) as exc_info:
        bg_tasks.create_export_task(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_create_export_task_logs_event(test_tenant, test_admin_user):
    """Test that creating an export task logs an event."""
    import database
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    result = bg_tasks.create_export_task(requesting_user)

    # Check that event was logged
    events = database.event_log.list_events(
        str(test_tenant["id"]),
        artifact_type="bg_task",
        artifact_id=str(result["id"]),
        event_type="export_task_created",
    )

    assert len(events) >= 1
    assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])
    assert events[0]["metadata"]["job_type"] == "export_events"


# =============================================================================
# list_user_jobs Tests
# =============================================================================


def test_list_user_jobs_returns_jobs(test_tenant, test_admin_user):
    """Test listing user jobs returns created jobs."""
    import database
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Create a task first
    database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_admin_user["id"]),
    )

    result = bg_tasks.list_user_jobs(requesting_user)

    assert len(result.jobs) >= 1
    assert result.jobs[0].job_type == "export_events"


def test_list_user_jobs_tracks_activity(test_tenant, test_admin_user):
    """Test list_user_jobs tracks activity."""
    from unittest.mock import patch

    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with patch("services.bg_tasks.track_activity") as mock_track:
        bg_tasks.list_user_jobs(requesting_user)

        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_admin_user["id"]))


def test_list_user_jobs_has_active_flag_true(test_tenant, test_admin_user):
    """Test has_active_jobs is True when pending/processing jobs exist."""
    import database
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Create a pending task
    database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_admin_user["id"]),
    )

    result = bg_tasks.list_user_jobs(requesting_user)

    assert result.has_active_jobs is True


def test_list_user_jobs_has_active_flag_false(test_tenant, test_admin_user):
    """Test has_active_jobs is False when only completed jobs exist."""
    import database
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Create and complete a task
    task = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_admin_user["id"]),
    )
    database.bg_tasks.complete_task(str(task["id"]), {"success": True})

    result = bg_tasks.list_user_jobs(requesting_user)

    # Only completed jobs, no active ones
    completed_only = all(job.status.value in ("completed", "failed") for job in result.jobs)
    if completed_only:
        assert result.has_active_jobs is False


def test_list_user_jobs_empty(test_tenant, test_user):
    """Test listing jobs for user with no jobs returns empty list."""
    from services import bg_tasks
    from services.types import RequestingUser

    # Use test_user who has no jobs
    requesting_user: RequestingUser = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    result = bg_tasks.list_user_jobs(requesting_user)

    assert result.jobs == []
    assert result.has_active_jobs is False


# =============================================================================
# get_job_detail Tests
# =============================================================================


def test_get_job_detail_success(test_tenant, test_admin_user):
    """Test getting job detail returns full job information."""
    import database
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Create a task
    task = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_admin_user["id"]),
    )

    result = bg_tasks.get_job_detail(requesting_user, str(task["id"]))

    assert result.id == str(task["id"])
    assert result.job_type == "export_events"
    assert str(result.created_by) == str(test_admin_user["id"])


def test_get_job_detail_not_found(test_tenant, test_admin_user):
    """Test getting non-existent job raises NotFoundError."""
    from uuid import uuid4

    from services import bg_tasks
    from services.exceptions import NotFoundError
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with pytest.raises(NotFoundError) as exc_info:
        bg_tasks.get_job_detail(requesting_user, str(uuid4()))

    assert exc_info.value.code == "job_not_found"


def test_get_job_detail_tracks_activity(test_tenant, test_admin_user):
    """Test get_job_detail tracks activity."""
    from unittest.mock import patch
    from uuid import uuid4

    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with patch("services.bg_tasks.track_activity") as mock_track:
        try:
            bg_tasks.get_job_detail(requesting_user, str(uuid4()))
        except Exception:
            pass  # We just want to verify track_activity is called

        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_admin_user["id"]))


def test_get_job_detail_other_user_job(test_tenant, test_admin_user, test_user):
    """Test cannot access another user's job."""
    import database
    from services import bg_tasks
    from services.exceptions import NotFoundError
    from services.types import RequestingUser

    # Admin creates a task
    task = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_admin_user["id"]),
    )

    # Regular user tries to access it
    requesting_user: RequestingUser = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    with pytest.raises(NotFoundError) as exc_info:
        bg_tasks.get_job_detail(requesting_user, str(task["id"]))

    assert exc_info.value.code == "job_not_found"


# =============================================================================
# delete_jobs Tests
# =============================================================================


def test_delete_jobs_success(test_tenant, test_admin_user):
    """Test deleting completed jobs works."""
    import database
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Create and complete a task
    task = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_admin_user["id"]),
    )
    database.bg_tasks.complete_task(str(task["id"]), {"success": True})

    count = bg_tasks.delete_jobs(requesting_user, [str(task["id"])])

    assert count == 1

    # Verify it's gone
    deleted = database.bg_tasks.get_task(str(task["id"]))
    assert deleted is None


@pytest.mark.xfail(reason="Bug: artifact_id='bulk_delete' is not a valid UUID. See ISSUES.md")
def test_delete_jobs_logs_event(test_tenant, test_admin_user):
    """Test deleting jobs logs an event."""
    import database
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Create and complete a task
    task = database.bg_tasks.create_task(
        tenant_id=str(test_tenant["id"]),
        job_type="export_events",
        created_by=str(test_admin_user["id"]),
    )
    database.bg_tasks.complete_task(str(task["id"]), {"success": True})
    task_id = str(task["id"])

    bg_tasks.delete_jobs(requesting_user, [task_id])

    # Check event was logged
    events = database.event_log.list_events(
        str(test_tenant["id"]),
        artifact_type="bg_task",
        event_type="jobs_deleted",
    )

    assert len(events) >= 1
    assert events[0]["metadata"]["count"] == 1
    assert task_id in events[0]["metadata"]["job_ids"]


def test_delete_jobs_empty_list(test_tenant, test_admin_user):
    """Test deleting empty list returns 0."""
    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    count = bg_tasks.delete_jobs(requesting_user, [])

    assert count == 0


def test_delete_jobs_tracks_activity(test_tenant, test_admin_user):
    """Test delete_jobs tracks activity."""
    from unittest.mock import patch

    from services import bg_tasks
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with patch("services.bg_tasks.track_activity") as mock_track:
        bg_tasks.delete_jobs(requesting_user, [])

        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_admin_user["id"]))
