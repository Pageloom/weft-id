"""Tests for event logging integration in service layer.

These tests verify that service layer write operations correctly log events.
"""

from uuid import uuid4


def test_user_create_logs_event(test_tenant, test_super_admin_user):
    """Test that creating a user logs an event."""
    import database
    from schemas.api import UserCreate
    from services import users
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "super_admin",
    }

    unique_email = f"newuser-{uuid4().hex[:8]}@example.com"
    user_data = UserCreate(
        first_name="New",
        last_name="User",
        email=unique_email,
        role="member",
    )

    result = users.create_user(requesting_user, user_data)

    # Check that event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="user",
        artifact_id=result.id,
        event_type="user_created",
    )

    assert len(events) >= 1
    event = events[0]
    assert str(event["actor_user_id"]) == str(test_super_admin_user["id"])
    assert event["metadata"]["role"] == "member"
    assert event["metadata"]["email"] == unique_email


def test_user_update_logs_event(test_tenant, test_admin_user, test_user):
    """Test that updating a user logs an event."""
    import database
    from schemas.api import UserUpdate
    from services import users
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    user_update = UserUpdate(
        first_name="Updated",
        last_name="Name",
    )

    users.update_user(requesting_user, str(test_user["id"]), user_update)

    # Check that event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_updated",
    )

    assert len(events) >= 1
    event = events[0]
    assert str(event["actor_user_id"]) == str(test_admin_user["id"])
    assert "changes" in event["metadata"]


def test_user_inactivate_logs_event(test_tenant, test_admin_user, test_user):
    """Test that inactivating a user logs an event."""
    import database
    from services import users
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    users.inactivate_user(requesting_user, str(test_user["id"]))

    # Check that event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_inactivated",
    )

    assert len(events) >= 1
    assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])


def test_user_reactivate_logs_event(test_tenant, test_admin_user, test_user):
    """Test that reactivating a user logs an event."""
    import database
    from services import users
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # First inactivate
    users.inactivate_user(requesting_user, str(test_user["id"]))

    # Then reactivate
    users.reactivate_user(requesting_user, str(test_user["id"]))

    # Check that event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_reactivated",
    )

    assert len(events) >= 1
    assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])


def test_privileged_domain_add_logs_event(test_tenant, test_admin_user):
    """Test that adding a privileged domain logs an event."""
    import database
    from schemas.settings import PrivilegedDomainCreate
    from services import settings
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    unique_domain = f"test-{uuid4().hex[:8]}.example.com"
    domain_data = PrivilegedDomainCreate(domain=unique_domain)

    settings.add_privileged_domain(requesting_user, domain_data)

    # Check that event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="privileged_domain",
        event_type="privileged_domain_added",
    )

    assert len(events) >= 1
    # Find the event for this specific domain
    matching_events = [e for e in events if e["metadata"].get("domain") == unique_domain]
    assert len(matching_events) >= 1
    assert str(matching_events[0]["actor_user_id"]) == str(test_admin_user["id"])


def test_privileged_domain_delete_logs_event(test_tenant, test_admin_user):
    """Test that deleting a privileged domain logs an event."""
    import database
    from schemas.settings import PrivilegedDomainCreate
    from services import settings
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    # First create a domain
    unique_domain = f"delete-{uuid4().hex[:8]}.example.com"
    domain_data = PrivilegedDomainCreate(domain=unique_domain)
    result = settings.add_privileged_domain(requesting_user, domain_data)

    # Then delete it
    settings.delete_privileged_domain(requesting_user, result.id)

    # Check that delete event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="privileged_domain",
        artifact_id=result.id,
        event_type="privileged_domain_deleted",
    )

    assert len(events) >= 1
    assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])
    assert events[0]["metadata"]["domain"] == unique_domain


def test_tenant_settings_update_logs_event(test_tenant, test_super_admin_user):
    """Test that updating tenant settings logs an event."""
    import database
    from schemas.settings import TenantSecuritySettingsUpdate
    from services import settings
    from services.types import RequestingUser

    requesting_user: RequestingUser = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "super_admin",
    }

    settings_update = TenantSecuritySettingsUpdate(
        session_timeout_seconds=7200,
    )

    settings.update_security_settings(requesting_user, settings_update)

    # Check that event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="tenant_settings",
        event_type="tenant_settings_updated",
    )

    assert len(events) >= 1
    assert str(events[0]["actor_user_id"]) == str(test_super_admin_user["id"])
    assert "changes" in events[0]["metadata"]


def test_oauth2_client_created_logs_event(test_tenant, test_admin_user):
    """Test that creating an OAuth2 client logs an event."""
    import database
    from services import oauth2

    unique_name = f"Test Client {uuid4().hex[:8]}"

    result = oauth2.create_normal_client(
        tenant_id=str(test_tenant["id"]),
        name=unique_name,
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(test_admin_user["id"]),
    )

    # Check that event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="oauth2_client",
        artifact_id=str(result["id"]),
        event_type="oauth2_client_created",
    )

    assert len(events) >= 1
    event = events[0]
    assert str(event["actor_user_id"]) == str(test_admin_user["id"])
    assert event["metadata"]["name"] == unique_name
    assert event["metadata"]["type"] == "normal"


def test_log_event_helper_function(test_tenant, test_user):
    """Test the log_event helper function directly."""
    import database
    from services.event_log import log_event

    unique_event_type = f"test_helper_{uuid4().hex[:8]}"

    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="test",
        artifact_id=str(test_user["id"]),
        event_type=unique_event_type,
        metadata={"test": True},
    )

    # Verify the event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        event_type=unique_event_type,
    )

    assert len(events) == 1
    assert events[0]["metadata"]["test"] is True


def test_log_event_does_not_raise_on_failure(test_tenant, test_user):
    """Test that log_event fails silently and doesn't disrupt operations."""
    from services.event_log import log_event

    # This should not raise even with an invalid tenant_id
    # (the function should catch the exception internally)
    log_event(
        tenant_id="invalid-uuid",  # Invalid UUID format
        actor_user_id=str(test_user["id"]),
        artifact_type="test",
        artifact_id=str(test_user["id"]),
        event_type="test_failure",
    )

    # If we get here, the function didn't raise
    assert True
