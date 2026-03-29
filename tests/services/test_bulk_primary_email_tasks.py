"""Tests for bulk primary email task creation service functions."""

from unittest.mock import patch
from uuid import uuid4

import pytest
from services.exceptions import ForbiddenError, ValidationError


def test_create_preview_task_as_admin(make_requesting_user, make_bg_task_dict):
    """Admin can create a bulk primary email preview task."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")
    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)
    items = [{"user_id": str(uuid4()), "new_primary_email": "new@example.com"}]

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event") as mock_log,
    ):
        mock_db.bg_tasks.create_task.return_value = task
        result = bg_tasks.create_bulk_primary_email_preview_task(requesting_user, items)

    assert result is not None
    call_kwargs = mock_db.bg_tasks.create_task.call_args.kwargs
    assert call_kwargs["job_type"] == "bulk_primary_email_preview"
    assert call_kwargs["payload"]["items"] == items
    mock_log.assert_called_once()
    assert mock_log.call_args.kwargs["event_type"] == "bulk_primary_email_preview_task_created"


def test_create_preview_task_as_member_forbidden(make_requesting_user):
    """Members cannot create preview tasks."""
    from services import bg_tasks

    requesting_user = make_requesting_user(role="member")

    items = [{"user_id": "x", "new_primary_email": "y"}]
    with pytest.raises(ForbiddenError):
        bg_tasks.create_bulk_primary_email_preview_task(requesting_user, items)


def test_create_preview_task_empty_items(make_requesting_user):
    """Empty items raises ValidationError."""
    from services import bg_tasks

    requesting_user = make_requesting_user(role="admin")

    with (
        patch("services.bg_tasks.track_activity"),
        pytest.raises(ValidationError, match="At least one"),
    ):
        bg_tasks.create_bulk_primary_email_preview_task(requesting_user, [])


def test_create_apply_task_as_admin(make_requesting_user, make_bg_task_dict):
    """Admin can create a bulk primary email apply task."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")
    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)
    items = [
        {
            "user_id": str(uuid4()),
            "new_primary_email": "new@example.com",
            "idp_disposition": "keep",
        }
    ]
    preview_job_id = str(uuid4())

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event") as mock_log,
    ):
        mock_db.bg_tasks.create_task.return_value = task
        result = bg_tasks.create_bulk_primary_email_apply_task(
            requesting_user, items, preview_job_id
        )

    assert result is not None
    call_kwargs = mock_db.bg_tasks.create_task.call_args.kwargs
    assert call_kwargs["job_type"] == "bulk_primary_email_apply"
    assert call_kwargs["payload"]["preview_job_id"] == preview_job_id
    mock_log.assert_called_once()
    assert mock_log.call_args.kwargs["event_type"] == "bulk_primary_email_apply_task_created"


def test_create_apply_task_as_member_forbidden(make_requesting_user):
    """Members cannot create apply tasks."""
    from services import bg_tasks

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError):
        bg_tasks.create_bulk_primary_email_apply_task(requesting_user, [{"user_id": "x"}], "job-id")


def test_create_apply_task_empty_items(make_requesting_user):
    """Empty items raises ValidationError."""
    from services import bg_tasks

    requesting_user = make_requesting_user(role="admin")

    with (
        patch("services.bg_tasks.track_activity"),
        pytest.raises(ValidationError, match="At least one"),
    ):
        bg_tasks.create_bulk_primary_email_apply_task(requesting_user, [], "job-id")
