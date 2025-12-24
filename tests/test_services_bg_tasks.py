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
