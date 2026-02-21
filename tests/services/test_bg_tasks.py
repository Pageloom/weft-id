"""Tests for background tasks service layer."""

from unittest.mock import patch
from uuid import uuid4

import pytest


def test_create_export_task_as_admin_success(make_requesting_user, make_bg_task_dict):
    """Test that admins can create export tasks."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event"),
    ):
        mock_db.bg_tasks.create_task.return_value = task

        result = bg_tasks.create_export_task(requesting_user)

        assert result is not None
        assert result["id"] == task["id"]
        mock_db.bg_tasks.create_task.assert_called_once()


def test_create_export_task_as_super_admin_success(make_requesting_user, make_bg_task_dict):
    """Test that super_admins can create export tasks."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="super_admin",
    )

    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event"),
    ):
        mock_db.bg_tasks.create_task.return_value = task

        result = bg_tasks.create_export_task(requesting_user)

        assert result is not None
        assert result["id"] is not None


def test_create_export_task_forbidden_for_member(make_requesting_user):
    """Test that members cannot create export tasks."""
    from services import bg_tasks
    from services.exceptions import ForbiddenError

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        bg_tasks.create_export_task(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_create_export_task_logs_event(make_requesting_user, make_bg_task_dict):
    """Test that creating an export task logs an event."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event") as mock_log,
    ):
        mock_db.bg_tasks.create_task.return_value = task

        bg_tasks.create_export_task(requesting_user)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["artifact_type"] == "bg_task"
        assert call_kwargs["event_type"] == "export_task_created"
        assert call_kwargs["metadata"]["job_type"] == "export_events"


# =============================================================================
# list_user_jobs Tests
# =============================================================================


def test_list_user_jobs_returns_jobs(make_requesting_user, make_bg_task_dict):
    """Test listing user jobs returns created jobs."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id, status="pending")

    with patch("services.bg_tasks.database") as mock_db, patch("services.bg_tasks.track_activity"):
        mock_db.bg_tasks.list_tasks_for_user.return_value = [task]

        result = bg_tasks.list_user_jobs(requesting_user)

        assert len(result.jobs) == 1
        assert result.jobs[0].job_type == "export_events"


def test_list_user_jobs_tracks_activity(make_requesting_user):
    """Test list_user_jobs tracks activity."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity") as mock_track,
    ):
        mock_db.bg_tasks.list_tasks_for_user.return_value = []

        bg_tasks.list_user_jobs(requesting_user)

        mock_track.assert_called_once_with(tenant_id, admin_id)


def test_list_user_jobs_has_active_flag_true(make_requesting_user, make_bg_task_dict):
    """Test has_active_jobs is True when pending/processing jobs exist."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id, status="pending")

    with patch("services.bg_tasks.database") as mock_db, patch("services.bg_tasks.track_activity"):
        mock_db.bg_tasks.list_tasks_for_user.return_value = [task]

        result = bg_tasks.list_user_jobs(requesting_user)

        assert result.has_active_jobs is True


def test_list_user_jobs_has_active_flag_false(make_requesting_user, make_bg_task_dict):
    """Test has_active_jobs is False when only completed jobs exist."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id, status="completed")

    with patch("services.bg_tasks.database") as mock_db, patch("services.bg_tasks.track_activity"):
        mock_db.bg_tasks.list_tasks_for_user.return_value = [task]

        result = bg_tasks.list_user_jobs(requesting_user)

        assert result.has_active_jobs is False


def test_list_user_jobs_empty(make_requesting_user):
    """Test listing jobs for user with no jobs returns empty list."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    user_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=user_id,
        tenant_id=tenant_id,
        role="member",
    )

    with patch("services.bg_tasks.database") as mock_db, patch("services.bg_tasks.track_activity"):
        mock_db.bg_tasks.list_tasks_for_user.return_value = []

        result = bg_tasks.list_user_jobs(requesting_user)

        assert result.jobs == []
        assert result.has_active_jobs is False


# =============================================================================
# get_job_detail Tests
# =============================================================================


def test_get_job_detail_success(make_requesting_user, make_bg_task_dict):
    """Test getting job detail returns full job information."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)

    with patch("services.bg_tasks.database") as mock_db, patch("services.bg_tasks.track_activity"):
        mock_db.bg_tasks.get_task_for_user.return_value = task

        result = bg_tasks.get_job_detail(requesting_user, task["id"])

        assert result.id == task["id"]
        assert result.job_type == "export_events"
        assert str(result.created_by) == admin_id


def test_get_job_detail_not_found(make_requesting_user):
    """Test getting non-existent job raises NotFoundError."""
    from services import bg_tasks
    from services.exceptions import NotFoundError

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    with patch("services.bg_tasks.database") as mock_db, patch("services.bg_tasks.track_activity"):
        mock_db.bg_tasks.get_task_for_user.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            bg_tasks.get_job_detail(requesting_user, str(uuid4()))

        assert exc_info.value.code == "job_not_found"


def test_get_job_detail_tracks_activity(make_requesting_user):
    """Test get_job_detail tracks activity."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity") as mock_track,
    ):
        mock_db.bg_tasks.get_task_for_user.return_value = None

        try:
            bg_tasks.get_job_detail(requesting_user, str(uuid4()))
        except Exception:
            pass

        mock_track.assert_called_once_with(tenant_id, admin_id)


def test_get_job_detail_other_user_job(make_requesting_user, make_bg_task_dict):
    """Test cannot access another user's job - returns not found."""
    from services import bg_tasks
    from services.exceptions import NotFoundError

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user_id = str(uuid4())

    # Admin creates a task
    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)

    # Regular user tries to access it
    requesting_user = make_requesting_user(
        user_id=user_id,
        tenant_id=tenant_id,
        role="member",
    )

    with patch("services.bg_tasks.database") as mock_db, patch("services.bg_tasks.track_activity"):
        # Service filters by user, so it won't find other user's job
        mock_db.bg_tasks.get_task_for_user.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            bg_tasks.get_job_detail(requesting_user, task["id"])

        assert exc_info.value.code == "job_not_found"


# =============================================================================
# delete_jobs Tests
# =============================================================================


def test_delete_jobs_success(make_requesting_user, make_bg_task_dict):
    """Test deleting completed jobs works."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id, status="completed")

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event"),
    ):
        mock_db.bg_tasks.delete_tasks.return_value = 1

        count = bg_tasks.delete_jobs(requesting_user, [task["id"]])

        assert count == 1
        mock_db.bg_tasks.delete_tasks.assert_called_once()


def test_delete_jobs_logs_event(make_requesting_user, make_bg_task_dict):
    """Test deleting jobs logs an event."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id, status="completed")
    task_id = task["id"]

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event") as mock_log,
    ):
        mock_db.bg_tasks.delete_tasks.return_value = 1

        bg_tasks.delete_jobs(requesting_user, [task_id])

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args.kwargs
        assert call_kwargs["event_type"] == "jobs_deleted"
        assert call_kwargs["metadata"]["count"] == 1
        assert task_id in call_kwargs["metadata"]["job_ids"]


def test_delete_jobs_empty_list(make_requesting_user):
    """Test deleting empty list returns 0."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    with patch("services.bg_tasks.database") as mock_db, patch("services.bg_tasks.track_activity"):
        mock_db.bg_tasks.delete_tasks.return_value = 0

        count = bg_tasks.delete_jobs(requesting_user, [])

        assert count == 0


def test_delete_jobs_tracks_activity(make_requesting_user):
    """Test delete_jobs tracks activity."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity") as mock_track,
    ):
        mock_db.bg_tasks.delete_tasks.return_value = 0

        bg_tasks.delete_jobs(requesting_user, [])

        mock_track.assert_called_once_with(tenant_id, admin_id)
