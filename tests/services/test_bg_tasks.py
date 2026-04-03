"""Tests for background tasks service layer."""

from datetime import date
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


def test_create_export_task_with_date_range(make_requesting_user, make_bg_task_dict):
    """Test export task passes date range as payload."""
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

        bg_tasks.create_export_task(
            requesting_user,
            start_date=date(2026, 1, 1),
            end_date=date(2026, 3, 15),
        )

        call_kwargs = mock_db.bg_tasks.create_task.call_args.kwargs
        assert call_kwargs["payload"]["start_date"] == "2026-01-01"
        assert call_kwargs["payload"]["end_date"] == "2026-03-15"


def test_create_export_task_invalid_date_range(make_requesting_user):
    """Test export task rejects start_date after end_date."""
    from services import bg_tasks
    from services.exceptions import ValidationError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="admin")

    with pytest.raises(ValidationError, match="Start date must be before"):
        bg_tasks.create_export_task(
            requesting_user,
            start_date=date(2026, 6, 1),
            end_date=date(2026, 1, 1),
        )


def test_create_export_task_future_date(make_requesting_user):
    """Test export task rejects future dates."""
    from services import bg_tasks
    from services.exceptions import ValidationError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="admin")

    with pytest.raises(ValidationError, match="future"):
        bg_tasks.create_export_task(
            requesting_user,
            start_date=date(2099, 1, 1),
        )


def test_create_export_task_no_dates_sends_null_payload(make_requesting_user, make_bg_task_dict):
    """Test export task with no dates sends null payload."""
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

        bg_tasks.create_export_task(requesting_user)

        call_kwargs = mock_db.bg_tasks.create_task.call_args.kwargs
        assert call_kwargs["payload"] is None


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


# =============================================================================
# create_bulk_inactivate_task Tests
# =============================================================================


def test_create_bulk_inactivate_task(make_requesting_user, make_bg_task_dict):
    """Test that admins can create bulk inactivate tasks."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(
        tenant_id=tenant_id,
        created_by=admin_id,
        job_type="bulk_inactivate_users",
    )

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event") as mock_log,
    ):
        mock_db.bg_tasks.create_task.return_value = task

        user_ids = [str(uuid4()), str(uuid4())]
        result = bg_tasks.create_bulk_inactivate_task(requesting_user, user_ids)

        assert result is not None
        assert result["id"] == task["id"]
        mock_db.bg_tasks.create_task.assert_called_once()

        call_kwargs = mock_db.bg_tasks.create_task.call_args.kwargs
        assert call_kwargs["job_type"] == "bulk_inactivate_users"
        assert call_kwargs["payload"]["user_ids"] == user_ids

        mock_log.assert_called_once()
        log_kwargs = mock_log.call_args.kwargs
        assert log_kwargs["event_type"] == "bulk_inactivate_task_created"
        assert log_kwargs["metadata"]["item_count"] == 2


def test_create_bulk_inactivate_task_empty_ids(make_requesting_user):
    """Test that empty user_ids raises ValidationError."""
    from services import bg_tasks
    from services.exceptions import ValidationError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="admin")

    with pytest.raises(ValidationError) as exc_info:
        bg_tasks.create_bulk_inactivate_task(requesting_user, [])

    assert exc_info.value.code == "empty_user_ids"


def test_create_bulk_inactivate_task_forbidden(make_requesting_user):
    """Test that members cannot create bulk inactivate tasks."""
    from services import bg_tasks
    from services.exceptions import ForbiddenError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        bg_tasks.create_bulk_inactivate_task(requesting_user, [str(uuid4())])

    assert exc_info.value.code == "admin_required"


# =============================================================================
# create_bulk_reactivate_task Tests
# =============================================================================


def test_create_bulk_reactivate_task(make_requesting_user, make_bg_task_dict):
    """Test that admins can create bulk reactivate tasks."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(
        tenant_id=tenant_id,
        created_by=admin_id,
        job_type="bulk_reactivate_users",
    )

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event") as mock_log,
    ):
        mock_db.bg_tasks.create_task.return_value = task

        user_ids = [str(uuid4()), str(uuid4()), str(uuid4())]
        result = bg_tasks.create_bulk_reactivate_task(requesting_user, user_ids)

        assert result is not None
        assert result["id"] == task["id"]
        mock_db.bg_tasks.create_task.assert_called_once()

        call_kwargs = mock_db.bg_tasks.create_task.call_args.kwargs
        assert call_kwargs["job_type"] == "bulk_reactivate_users"
        assert call_kwargs["payload"]["user_ids"] == user_ids

        mock_log.assert_called_once()
        log_kwargs = mock_log.call_args.kwargs
        assert log_kwargs["event_type"] == "bulk_reactivate_task_created"
        assert log_kwargs["metadata"]["item_count"] == 3


def test_create_bulk_reactivate_task_empty_ids(make_requesting_user):
    """Test that empty user_ids raises ValidationError."""
    from services import bg_tasks
    from services.exceptions import ValidationError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="admin")

    with pytest.raises(ValidationError) as exc_info:
        bg_tasks.create_bulk_reactivate_task(requesting_user, [])

    assert exc_info.value.code == "empty_user_ids"


def test_create_bulk_reactivate_task_forbidden(make_requesting_user):
    """Test that members cannot create bulk reactivate tasks."""
    from services import bg_tasks
    from services.exceptions import ForbiddenError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        bg_tasks.create_bulk_reactivate_task(requesting_user, [str(uuid4())])

    assert exc_info.value.code == "admin_required"


# --- Preview Bulk Inactivate ---


def test_preview_bulk_inactivate_eligible(make_requesting_user):
    """Preview returns eligible users and skips ineligible ones."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            {
                "id": user1_id,
                "role": "member",
                "is_inactivated": False,
                "first_name": "Active",
                "last_name": "User",
            },
            {
                "id": user2_id,
                "role": "member",
                "is_inactivated": True,
                "first_name": "Inactive",
                "last_name": "User",
            },
        ]
        mock_db.users.is_service_user.return_value = False

        result = bg_tasks.preview_bulk_inactivate(requesting_user, [user1_id, user2_id])

    assert result["eligible"] == 1
    assert result["eligible_ids"] == [user1_id]
    assert len(result["skipped"]) == 1
    assert result["skipped"][0]["reason"] == "Already inactivated"


def test_preview_bulk_inactivate_forbidden(make_requesting_user):
    """Members cannot preview bulk inactivation."""
    from services import bg_tasks
    from services.exceptions import ForbiddenError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="member")

    with pytest.raises(ForbiddenError):
        bg_tasks.preview_bulk_inactivate(requesting_user, [str(uuid4())])


# --- Preview Bulk Reactivate ---


def test_preview_bulk_reactivate_eligible(make_requesting_user):
    """Preview returns eligible users and skips ineligible ones."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
    ):
        mock_db.users.get_user_by_id.side_effect = [
            {
                "id": user1_id,
                "is_inactivated": True,
                "is_anonymized": False,
                "first_name": "Inactive",
                "last_name": "User",
            },
            {
                "id": user2_id,
                "is_inactivated": False,
                "is_anonymized": False,
                "first_name": "Active",
                "last_name": "User",
            },
        ]

        result = bg_tasks.preview_bulk_reactivate(requesting_user, [user1_id, user2_id])

    assert result["eligible"] == 1
    assert result["eligible_ids"] == [user1_id]
    assert len(result["skipped"]) == 1
    assert result["skipped"][0]["reason"] == "Not inactivated"


def test_preview_bulk_reactivate_forbidden(make_requesting_user):
    """Members cannot preview bulk reactivation."""
    from services import bg_tasks
    from services.exceptions import ForbiddenError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="member")

    with pytest.raises(ForbiddenError):
        bg_tasks.preview_bulk_reactivate(requesting_user, [str(uuid4())])


# =============================================================================
# preview_bulk_group_assignment Tests
# =============================================================================


def test_preview_bulk_group_assignment_eligible(make_requesting_user):
    """Preview returns eligible users and skips existing members."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    group_id = str(uuid4())
    user1_id = str(uuid4())
    user2_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = {
            "id": group_id,
            "name": "Engineering",
            "group_type": "weftid",
        }
        mock_db.users.get_user_by_id.side_effect = [
            {"id": user1_id, "first_name": "New", "last_name": "User"},
            {"id": user2_id, "first_name": "Existing", "last_name": "Member"},
        ]
        mock_db.groups.is_group_member.side_effect = [False, True]

        result = bg_tasks.preview_bulk_group_assignment(
            requesting_user, group_id, [user1_id, user2_id]
        )

    assert result["eligible"] == 1
    assert result["eligible_ids"] == [user1_id]
    assert len(result["skipped"]) == 1
    assert result["skipped"][0]["reason"] == "Already a member"
    assert result["group_name"] == "Engineering"


def test_preview_bulk_group_assignment_idp_group(make_requesting_user):
    """Preview rejects IdP groups."""
    from services import bg_tasks
    from services.exceptions import ValidationError

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = {
            "id": group_id,
            "name": "Okta Group",
            "group_type": "idp",
        }

        with pytest.raises(ValidationError) as exc_info:
            bg_tasks.preview_bulk_group_assignment(requesting_user, group_id, [str(uuid4())])

        assert exc_info.value.code == "idp_group_read_only"


def test_preview_bulk_group_assignment_group_not_found(make_requesting_user):
    """Preview raises NotFoundError when group doesn't exist."""
    from services import bg_tasks
    from services.exceptions import NotFoundError

    tenant_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(tenant_id=tenant_id, role="admin")

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
    ):
        mock_db.groups.get_group_by_id.return_value = None

        with pytest.raises(NotFoundError):
            bg_tasks.preview_bulk_group_assignment(requesting_user, group_id, [str(uuid4())])


def test_preview_bulk_group_assignment_forbidden(make_requesting_user):
    """Members cannot preview bulk group assignment."""
    from services import bg_tasks
    from services.exceptions import ForbiddenError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="member")

    with pytest.raises(ForbiddenError):
        bg_tasks.preview_bulk_group_assignment(requesting_user, str(uuid4()), [str(uuid4())])


# =============================================================================
# create_bulk_group_assignment_task Tests
# =============================================================================


def test_create_bulk_group_assignment_task(make_requesting_user, make_bg_task_dict):
    """Test that admins can create bulk group assignment tasks."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    group_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id,
        tenant_id=tenant_id,
        role="admin",
    )

    task = make_bg_task_dict(
        tenant_id=tenant_id,
        created_by=admin_id,
        job_type="bulk_group_assignment",
    )

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event") as mock_log,
    ):
        mock_db.bg_tasks.create_task.return_value = task

        user_ids = [str(uuid4()), str(uuid4())]
        result = bg_tasks.create_bulk_group_assignment_task(requesting_user, group_id, user_ids)

        assert result is not None
        assert result["id"] == task["id"]
        mock_db.bg_tasks.create_task.assert_called_once()

        call_kwargs = mock_db.bg_tasks.create_task.call_args.kwargs
        assert call_kwargs["job_type"] == "bulk_group_assignment"
        assert call_kwargs["payload"]["group_id"] == group_id
        assert call_kwargs["payload"]["user_ids"] == user_ids

        mock_log.assert_called_once()
        log_kwargs = mock_log.call_args.kwargs
        assert log_kwargs["event_type"] == "bulk_group_assignment_task_created"
        assert log_kwargs["metadata"]["group_id"] == group_id
        assert log_kwargs["metadata"]["item_count"] == 2


def test_create_bulk_group_assignment_task_empty_ids(make_requesting_user):
    """Test that empty user_ids raises ValidationError."""
    from services import bg_tasks
    from services.exceptions import ValidationError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="admin")

    with pytest.raises(ValidationError) as exc_info:
        bg_tasks.create_bulk_group_assignment_task(requesting_user, str(uuid4()), [])

    assert exc_info.value.code == "empty_user_ids"


def test_create_bulk_group_assignment_task_forbidden(make_requesting_user):
    """Test that members cannot create bulk group assignment tasks."""
    from services import bg_tasks
    from services.exceptions import ForbiddenError

    requesting_user = make_requesting_user(tenant_id=str(uuid4()), role="member")

    with pytest.raises(ForbiddenError):
        bg_tasks.create_bulk_group_assignment_task(requesting_user, str(uuid4()), [str(uuid4())])
