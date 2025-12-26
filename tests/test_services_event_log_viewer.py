"""Tests for event log viewer service functions."""

from uuid import uuid4

import pytest


def test_list_events_as_admin(test_tenant, test_admin_user, test_user):
    """Test that admins can list events."""
    from services import event_log
    from services.event_log import log_event
    from services.types import RequestingUser

    # Create some events first
    unique_type = f"test_list_{uuid4().hex[:8]}"
    for i in range(3):
        log_event(
            tenant_id=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="test",
            artifact_id=str(uuid4()),
            event_type=unique_type,
            metadata={"index": i},
        )

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    result = event_log.list_events(requesting_user, page=1, limit=50)

    assert result.total >= 3
    assert result.page == 1
    assert result.limit == 50
    assert len(result.items) >= 3


def test_list_events_as_super_admin(test_tenant, test_super_admin_user):
    """Test that super_admins can list events."""
    from services import event_log
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "super_admin",
    }

    result = event_log.list_events(requesting_user, page=1, limit=10)

    assert result.page == 1
    assert result.limit == 10


def test_list_events_forbidden_for_member(test_tenant, test_user):
    """Test that members cannot list events."""
    from services import event_log
    from services.exceptions import ForbiddenError
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    with pytest.raises(ForbiddenError) as exc_info:
        event_log.list_events(requesting_user, page=1, limit=10)

    assert exc_info.value.code == "admin_required"


def test_list_events_pagination(test_tenant, test_admin_user, test_user):
    """Test event list pagination."""
    from services import event_log
    from services.event_log import log_event
    from services.types import RequestingUser

    # Create 5 events
    unique_type = f"test_pagination_{uuid4().hex[:8]}"
    for i in range(5):
        log_event(
            tenant_id=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="test",
            artifact_id=str(uuid4()),
            event_type=unique_type,
            metadata={"index": i},
        )

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # Get first page with limit of 2
    page1 = event_log.list_events(requesting_user, page=1, limit=2)
    assert len(page1.items) == 2

    # Get second page
    page2 = event_log.list_events(requesting_user, page=2, limit=2)
    assert len(page2.items) == 2

    # Ensure different items
    page1_ids = {item.id for item in page1.items}
    page2_ids = {item.id for item in page2.items}
    assert page1_ids.isdisjoint(page2_ids)


def test_list_events_includes_actor_name(test_tenant, test_admin_user, test_user):
    """Test that events include actor names."""
    from services import event_log
    from services.event_log import log_event
    from services.types import RequestingUser

    # Create an event with test_user as actor
    unique_type = f"test_actor_{uuid4().hex[:8]}"
    artifact_id = str(uuid4())
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="test",
        artifact_id=artifact_id,
        event_type=unique_type,
    )

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    result = event_log.list_events(requesting_user, page=1, limit=100)

    # Find our event
    matching = [e for e in result.items if e.event_type == unique_type]
    assert len(matching) == 1
    assert matching[0].actor_name != ""
    assert matching[0].actor_name != "Unknown User"


def test_list_events_system_actor_name(test_tenant, test_admin_user):
    """Test that system actor events show 'System' as actor name."""
    from services import event_log
    from services.event_log import SYSTEM_ACTOR_ID, log_event
    from services.types import RequestingUser

    # Create an event with system actor
    unique_type = f"test_system_{uuid4().hex[:8]}"
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="test",
        artifact_id=str(uuid4()),
        event_type=unique_type,
    )

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    result = event_log.list_events(requesting_user, page=1, limit=100)

    # Find our event
    matching = [e for e in result.items if e.event_type == unique_type]
    assert len(matching) == 1
    assert matching[0].actor_name == "System"


def test_get_event_as_admin(test_tenant, test_admin_user, test_user):
    """Test that admins can get a single event."""
    import database
    from services import event_log
    from services.event_log import log_event
    from services.types import RequestingUser

    # Create an event
    unique_type = f"test_get_{uuid4().hex[:8]}"
    artifact_id = str(uuid4())
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="test",
        artifact_id=artifact_id,
        event_type=unique_type,
        metadata={"key": "value"},
    )

    # Get the event ID
    events = database.event_log.list_events(
        str(test_tenant["id"]),
        event_type=unique_type,
    )
    assert len(events) == 1
    event_id = str(events[0]["id"])

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    result = event_log.get_event(requesting_user, event_id)

    assert result.id == event_id
    assert result.event_type == unique_type
    assert result.artifact_id == artifact_id
    # Metadata now includes both custom fields and base request metadata fields
    assert result.metadata["key"] == "value"
    assert "device" in result.metadata
    assert "remote_address" in result.metadata
    assert "session_id_hash" in result.metadata
    assert "user_agent" in result.metadata


def test_get_event_forbidden_for_member(test_tenant, test_user):
    """Test that members cannot get event details."""
    from services import event_log
    from services.exceptions import ForbiddenError
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    with pytest.raises(ForbiddenError) as exc_info:
        event_log.get_event(requesting_user, str(uuid4()))

    assert exc_info.value.code == "admin_required"


def test_get_event_not_found(test_tenant, test_admin_user):
    """Test that getting a non-existent event raises NotFoundError."""
    from services import event_log
    from services.exceptions import NotFoundError
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with pytest.raises(NotFoundError) as exc_info:
        event_log.get_event(requesting_user, str(uuid4()))

    assert exc_info.value.code == "event_not_found"
