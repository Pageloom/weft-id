"""Tests for event log viewer service functions."""

from unittest.mock import patch
from uuid import uuid4

import pytest


def test_list_events_as_admin_success(make_requesting_user, make_event_log_dict, make_user_dict):
    """Test that admins can list events."""
    from services import event_log

    tenant_id = str(uuid4())
    admin = make_user_dict(tenant_id=tenant_id, role="admin")
    requesting_user = make_requesting_user(
        user_id=admin["id"],
        tenant_id=tenant_id,
        role="admin",
    )

    event1 = make_event_log_dict(tenant_id=tenant_id, event_type="test_event_1")
    event2 = make_event_log_dict(tenant_id=tenant_id, event_type="test_event_2")
    event3 = make_event_log_dict(tenant_id=tenant_id, event_type="test_event_3")

    with patch("services.event_log.database") as mock_db, \
         patch("services.event_log.track_activity"):
        mock_db.event_log.list_events.return_value = [event1, event2, event3]
        mock_db.event_log.count_events.return_value = 3
        mock_db.users.get_user_by_id.return_value = admin

        result = event_log.list_events(requesting_user, page=1, limit=50)

        assert result.total == 3
        assert result.page == 1
        assert result.limit == 50
        assert len(result.items) == 3
        mock_db.event_log.list_events.assert_called_once()

def test_list_events_as_super_admin_success(make_requesting_user, make_event_log_dict):
    """Test that super_admins can list events."""
    from services import event_log

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(
        tenant_id=tenant_id,
        role="super_admin",
    )

    with patch("services.event_log.database") as mock_db, \
         patch("services.event_log.track_activity"):
        mock_db.event_log.list_events.return_value = []
        mock_db.event_log.count_events.return_value = 0

        result = event_log.list_events(requesting_user, page=1, limit=10)

        assert result.page == 1
        assert result.limit == 10

def test_list_events_forbidden_for_member(make_requesting_user):
    """Test that members cannot list events."""
    from services import event_log
    from services.exceptions import ForbiddenError

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(
        tenant_id=tenant_id,
        role="member",
    )

    with pytest.raises(ForbiddenError) as exc_info:
        event_log.list_events(requesting_user, page=1, limit=10)

    assert exc_info.value.code == "admin_required"

def test_list_events_pagination(make_requesting_user, make_event_log_dict, make_user_dict):
    """Test event list pagination."""
    from services import event_log

    tenant_id = str(uuid4())
    admin = make_user_dict(tenant_id=tenant_id, role="admin")
    requesting_user = make_requesting_user(
        user_id=admin["id"],
        tenant_id=tenant_id,
        role="admin",
    )

    # Create 5 events
    events = [make_event_log_dict(tenant_id=tenant_id, event_type=f"test_{i}") for i in range(5)]

    with patch("services.event_log.database") as mock_db, \
         patch("services.event_log.track_activity"):
        # First page
        mock_db.event_log.list_events.return_value = events[:2]
        mock_db.event_log.count_events.return_value = 5
        mock_db.users.get_user_by_id.return_value = admin

        page1 = event_log.list_events(requesting_user, page=1, limit=2)
        assert len(page1.items) == 2

        # Second page
        mock_db.event_log.list_events.return_value = events[2:4]
        page2 = event_log.list_events(requesting_user, page=2, limit=2)
        assert len(page2.items) == 2

def test_list_events_includes_actor_name(make_requesting_user, make_event_log_dict, make_user_dict):
    """Test that events include actor names."""
    from services import event_log

    tenant_id = str(uuid4())
    actor = make_user_dict(tenant_id=tenant_id, first_name="Test", last_name="Actor")
    admin = make_user_dict(tenant_id=tenant_id, role="admin")
    requesting_user = make_requesting_user(
        user_id=admin["id"],
        tenant_id=tenant_id,
        role="admin",
    )

    event = make_event_log_dict(
        tenant_id=tenant_id,
        actor_user_id=actor["id"],
        event_type="test_actor",
    )

    with patch("services.event_log.database") as mock_db, \
         patch("services.event_log.track_activity"):
        mock_db.event_log.list_events.return_value = [event]
        mock_db.event_log.count_events.return_value = 1
        mock_db.users.get_user_by_id.return_value = actor

        result = event_log.list_events(requesting_user, page=1, limit=100)

        assert len(result.items) == 1
        assert result.items[0].actor_name == "Test Actor"

def test_list_events_system_actor_name(make_requesting_user, make_event_log_dict):
    """Test that system actor events show 'System' as actor name."""
    from services import event_log
    from services.event_log import SYSTEM_ACTOR_ID

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(
        tenant_id=tenant_id,
        role="admin",
    )

    event = make_event_log_dict(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        event_type="test_system",
    )

    with patch("services.event_log.database") as mock_db, \
         patch("services.event_log.track_activity"):
        mock_db.event_log.list_events.return_value = [event]
        mock_db.event_log.count_events.return_value = 1
        # System actor - get_user_by_id is not called for system actor
        mock_db.users.get_user_by_id.return_value = None

        result = event_log.list_events(requesting_user, page=1, limit=100)

        assert len(result.items) == 1
        assert result.items[0].actor_name == "System"

def test_get_event_as_admin_success(make_requesting_user, make_event_log_dict, make_user_dict):
    """Test that admins can get a single event."""
    from services import event_log

    tenant_id = str(uuid4())
    actor = make_user_dict(tenant_id=tenant_id, first_name="Test", last_name="Actor")
    admin = make_user_dict(tenant_id=tenant_id, role="admin")
    requesting_user = make_requesting_user(
        user_id=admin["id"],
        tenant_id=tenant_id,
        role="admin",
    )

    event_id = str(uuid4())
    artifact_id = str(uuid4())
    event = make_event_log_dict(
        event_id=event_id,
        tenant_id=tenant_id,
        actor_user_id=actor["id"],
        artifact_id=artifact_id,
        event_type="test_get",
        metadata={
            "key": "value",
            "device": "desktop",
            "remote_address": "127.0.0.1",
            "session_id_hash": "abc123",
            "user_agent": "TestAgent",
        },
    )

    with patch("services.event_log.database") as mock_db, \
         patch("services.event_log.track_activity"):
        mock_db.event_log.get_event_by_id.return_value = event
        mock_db.users.get_user_by_id.return_value = actor

        result = event_log.get_event(requesting_user, event_id)

        assert result.id == event_id
        assert result.event_type == "test_get"
        assert result.artifact_id == artifact_id
        assert result.metadata["key"] == "value"
        mock_db.event_log.get_event_by_id.assert_called_once()

def test_get_event_forbidden_for_member(make_requesting_user):
    """Test that members cannot get event details."""
    from services import event_log
    from services.exceptions import ForbiddenError

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(
        tenant_id=tenant_id,
        role="member",
    )

    with pytest.raises(ForbiddenError) as exc_info:
        event_log.get_event(requesting_user, str(uuid4()))

    assert exc_info.value.code == "admin_required"

def test_get_event_not_found(make_requesting_user):
    """Test that getting a non-existent event raises NotFoundError."""
    from services import event_log
    from services.exceptions import NotFoundError

    tenant_id = str(uuid4())
    requesting_user = make_requesting_user(
        tenant_id=tenant_id,
        role="admin",
    )

    with patch("services.event_log.database") as mock_db, \
         patch("services.event_log.track_activity"):
        mock_db.event_log.get_event_by_id.return_value = None

        with pytest.raises(NotFoundError) as exc_info:
            event_log.get_event(requesting_user, str(uuid4()))

        assert exc_info.value.code == "event_not_found"
