"""Tests for bulk add secondary emails service function."""

from unittest.mock import patch
from uuid import uuid4

import pytest


def test_create_bulk_add_emails_task_as_admin(make_requesting_user, make_bg_task_dict):
    """Admin can create a bulk add emails background task."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")
    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)
    items = [
        {"user_id": str(uuid4()), "email": "a@example.com"},
        {"user_id": str(uuid4()), "email": "b@example.com"},
    ]

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event"),
    ):
        mock_db.bg_tasks.create_task.return_value = task
        result = bg_tasks.create_bulk_add_emails_task(requesting_user, items)

    assert result is not None
    assert result["id"] == task["id"]
    mock_db.bg_tasks.create_task.assert_called_once()
    call_kwargs = mock_db.bg_tasks.create_task.call_args.kwargs
    assert call_kwargs["job_type"] == "bulk_add_secondary_emails"
    assert call_kwargs["payload"]["items"] == items


def test_create_bulk_add_emails_task_as_super_admin(make_requesting_user, make_bg_task_dict):
    """Super admin can create a bulk add emails background task."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(
        user_id=admin_id, tenant_id=tenant_id, role="super_admin"
    )
    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event"),
    ):
        mock_db.bg_tasks.create_task.return_value = task
        result = bg_tasks.create_bulk_add_emails_task(
            requesting_user, [{"user_id": str(uuid4()), "email": "x@example.com"}]
        )

    assert result is not None


def test_create_bulk_add_emails_task_forbidden_for_member(make_requesting_user):
    """Members cannot create bulk add emails tasks."""
    from services import bg_tasks
    from services.exceptions import ForbiddenError

    requesting_user = make_requesting_user(role="member")

    with pytest.raises(ForbiddenError) as exc_info:
        bg_tasks.create_bulk_add_emails_task(
            requesting_user, [{"user_id": str(uuid4()), "email": "x@example.com"}]
        )

    assert exc_info.value.code == "admin_required"


def test_create_bulk_add_emails_task_empty_items_fails(make_requesting_user):
    """Empty items list raises ValidationError."""
    from services import bg_tasks
    from services.exceptions import ValidationError

    requesting_user = make_requesting_user(role="admin")

    with pytest.raises(ValidationError) as exc_info:
        bg_tasks.create_bulk_add_emails_task(requesting_user, [])

    assert exc_info.value.code == "empty_items"


def test_create_bulk_add_emails_task_logs_event(make_requesting_user, make_bg_task_dict):
    """Creating bulk add emails task logs the correct audit event."""
    from services import bg_tasks

    tenant_id = str(uuid4())
    admin_id = str(uuid4())
    requesting_user = make_requesting_user(user_id=admin_id, tenant_id=tenant_id, role="admin")
    task = make_bg_task_dict(tenant_id=tenant_id, created_by=admin_id)
    items = [{"user_id": str(uuid4()), "email": "a@example.com"}]

    with (
        patch("services.bg_tasks.database") as mock_db,
        patch("services.bg_tasks.track_activity"),
        patch("services.bg_tasks.log_event") as mock_log,
    ):
        mock_db.bg_tasks.create_task.return_value = task
        bg_tasks.create_bulk_add_emails_task(requesting_user, items)

    mock_log.assert_called_once()
    call_kwargs = mock_log.call_args.kwargs
    assert call_kwargs["event_type"] == "bulk_secondary_emails_task_created"
    assert call_kwargs["artifact_type"] == "bg_task"
    assert call_kwargs["metadata"]["item_count"] == 1
