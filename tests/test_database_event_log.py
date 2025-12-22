"""Tests for database.event_log module."""

from uuid import uuid4


def test_create_event(test_tenant, test_user):
    """Test creating an event log entry."""
    import database

    result = database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_created",
        metadata={"role": "member"},
    )

    assert result is not None
    assert result["id"] is not None
    assert result["created_at"] is not None


def test_create_event_without_metadata(test_tenant, test_user):
    """Test creating an event log entry without metadata."""
    import database

    result = database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_deleted",
        metadata=None,
    )

    assert result is not None
    assert result["id"] is not None


def test_list_events(test_tenant, test_user):
    """Test listing event logs."""
    import database

    # Create some events
    for i in range(3):
        database.event_log.create_event(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="user",
            artifact_id=str(test_user["id"]),
            event_type=f"test_event_{i}_{uuid4().hex[:8]}",
        )

    events = database.event_log.list_events(test_tenant["id"], limit=10)

    assert len(events) >= 3


def test_list_events_filter_by_artifact_type(test_tenant, test_user):
    """Test filtering events by artifact type."""
    import database

    unique_suffix = uuid4().hex[:8]
    other_artifact_id = str(uuid4())

    # Create events for different artifact types
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=f"user_updated_{unique_suffix}",
    )
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="privileged_domain",
        artifact_id=other_artifact_id,
        event_type=f"privileged_domain_added_{unique_suffix}",
    )

    # Filter by artifact type
    user_events = database.event_log.list_events(test_tenant["id"], artifact_type="user")
    domain_events = database.event_log.list_events(
        test_tenant["id"], artifact_type="privileged_domain"
    )

    assert all(e["artifact_type"] == "user" for e in user_events)
    assert all(e["artifact_type"] == "privileged_domain" for e in domain_events)


def test_list_events_filter_by_event_type(test_tenant, test_user):
    """Test filtering events by event type."""
    import database

    unique_suffix = uuid4().hex[:8]
    event_type = f"unique_event_type_{unique_suffix}"

    # Create an event with unique type
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=event_type,
    )

    # Filter by event type
    events = database.event_log.list_events(test_tenant["id"], event_type=event_type)

    assert len(events) == 1
    assert events[0]["event_type"] == event_type


def test_list_events_filter_by_actor(test_tenant, test_user, test_admin_user):
    """Test filtering events by actor."""
    import database

    unique_suffix = uuid4().hex[:8]

    # Create events by different actors
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=f"event_by_user_{unique_suffix}",
    )
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_admin_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=f"event_by_admin_{unique_suffix}",
    )

    # Filter by actor
    user_events = database.event_log.list_events(
        test_tenant["id"], actor_user_id=str(test_user["id"])
    )
    admin_events = database.event_log.list_events(
        test_tenant["id"], actor_user_id=str(test_admin_user["id"])
    )

    assert all(str(e["actor_user_id"]) == str(test_user["id"]) for e in user_events)
    assert all(str(e["actor_user_id"]) == str(test_admin_user["id"]) for e in admin_events)


def test_list_events_pagination(test_tenant, test_user):
    """Test pagination of event logs."""
    import database

    unique_suffix = uuid4().hex[:8]

    # Create 5 events
    for i in range(5):
        database.event_log.create_event(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="test_pagination",
            artifact_id=str(test_user["id"]),
            event_type=f"pagination_test_{i}_{unique_suffix}",
        )

    # Get first page
    page1 = database.event_log.list_events(
        test_tenant["id"], artifact_type="test_pagination", limit=2, offset=0
    )
    # Get second page
    page2 = database.event_log.list_events(
        test_tenant["id"], artifact_type="test_pagination", limit=2, offset=2
    )

    assert len(page1) == 2
    assert len(page2) == 2
    # Pages should have different events
    page1_ids = {e["id"] for e in page1}
    page2_ids = {e["id"] for e in page2}
    assert page1_ids.isdisjoint(page2_ids)


def test_count_events(test_tenant, test_user):
    """Test counting event logs."""
    import database

    unique_artifact_id = str(uuid4())

    initial_count = database.event_log.count_events(
        test_tenant["id"], artifact_id=unique_artifact_id
    )

    # Create 3 events for this artifact
    for i in range(3):
        database.event_log.create_event(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="user",
            artifact_id=unique_artifact_id,
            event_type=f"test_count_{i}",
        )

    new_count = database.event_log.count_events(test_tenant["id"], artifact_id=unique_artifact_id)

    assert new_count == initial_count + 3


def test_count_events_filter_by_artifact_type(test_tenant, test_user):
    """Test counting events filtered by artifact type."""
    import database

    unique_suffix = uuid4().hex[:8]

    # Create events for different types
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type=f"type_a_{unique_suffix}",
        artifact_id=str(uuid4()),
        event_type="test",
    )
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type=f"type_b_{unique_suffix}",
        artifact_id=str(uuid4()),
        event_type="test",
    )

    count_a = database.event_log.count_events(
        test_tenant["id"], artifact_type=f"type_a_{unique_suffix}"
    )
    count_b = database.event_log.count_events(
        test_tenant["id"], artifact_type=f"type_b_{unique_suffix}"
    )

    assert count_a == 1
    assert count_b == 1


def test_event_metadata_stored_correctly(test_tenant, test_user):
    """Test that metadata is stored and retrieved correctly."""
    import database

    metadata = {
        "role": "admin",
        "email": "test@example.com",
        "changes": {"first_name": {"old": "John", "new": "Jane"}},
    }

    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="metadata_test",
        metadata=metadata,
    )

    events = database.event_log.list_events(test_tenant["id"], event_type="metadata_test")

    assert len(events) >= 1
    event = events[0]
    assert event["metadata"]["role"] == "admin"
    assert event["metadata"]["email"] == "test@example.com"
    assert event["metadata"]["changes"]["first_name"]["old"] == "John"
    assert event["metadata"]["changes"]["first_name"]["new"] == "Jane"


def test_tenant_isolation(test_tenant, test_user):
    """Test that events are tenant-isolated via RLS."""
    import database

    unique_event_type = f"isolated_event_{uuid4().hex[:8]}"

    # Create event in test tenant
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=unique_event_type,
    )

    # Create another tenant
    other_subdomain = f"other-{str(uuid4())[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
        {"subdomain": other_subdomain, "name": "Other Tenant"},
    )
    other_tenant = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": other_subdomain},
    )

    try:
        # Query from other tenant should not see test tenant's events
        events = database.event_log.list_events(other_tenant["id"], event_type=unique_event_type)
        assert len(events) == 0
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other_tenant["id"]},
        )


def test_system_actor_id():
    """Test that SYSTEM_ACTOR_ID is a valid UUID constant."""
    from uuid import UUID

    from services.event_log import SYSTEM_ACTOR_ID

    # Should be parseable as UUID
    uuid_obj = UUID(SYSTEM_ACTOR_ID)
    assert str(uuid_obj) == SYSTEM_ACTOR_ID

    # Should be the all-zeros UUID
    assert SYSTEM_ACTOR_ID == "00000000-0000-0000-0000-000000000000"


def test_create_event_with_system_actor(test_tenant, test_user):
    """Test creating an event with SYSTEM_ACTOR_ID."""
    import database
    from services.event_log import SYSTEM_ACTOR_ID

    result = database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="system_action",
    )

    assert result is not None

    # Verify the event was created with system actor
    events = database.event_log.list_events(test_tenant["id"], actor_user_id=SYSTEM_ACTOR_ID)
    assert len(events) >= 1
    assert str(events[0]["actor_user_id"]) == SYSTEM_ACTOR_ID
