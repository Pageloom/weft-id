"""Tests for database.event_log module."""

from typing import Any
from uuid import uuid4


def _prepare_event_metadata(
    custom_metadata: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    """Helper to prepare combined_metadata and metadata_hash for create_event().

    Args:
        custom_metadata: Optional custom event metadata

    Returns:
        Tuple of (combined_metadata, metadata_hash)
    """
    from utils.request_metadata import compute_metadata_hash

    # Build combined metadata with required request fields (all null for tests)
    combined_metadata: dict[str, Any] = {
        "device": None,
        "remote_address": None,
        "session_id_hash": None,
        "user_agent": None,
    }

    # Merge in custom metadata if provided
    if custom_metadata:
        combined_metadata.update(custom_metadata)

    # Compute hash
    metadata_hash = compute_metadata_hash(combined_metadata)

    return combined_metadata, metadata_hash


def test_create_event(test_tenant, test_user):
    """Test creating an event log entry."""
    import database

    combined_metadata, metadata_hash = _prepare_event_metadata({"role": "member"})

    result = database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_created",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
    )

    assert result is not None
    assert result["id"] is not None
    assert result["created_at"] is not None


def test_create_event_without_metadata(test_tenant, test_user):
    """Test creating an event log entry without metadata."""
    import database

    combined_metadata, metadata_hash = _prepare_event_metadata(None)

    result = database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_deleted",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
    )

    assert result is not None
    assert result["id"] is not None


def test_list_events(test_tenant, test_user):
    """Test listing event logs."""
    import database

    # Create some events
    for i in range(3):
        combined_metadata, metadata_hash = _prepare_event_metadata()
        database.event_log.create_event(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="user",
            artifact_id=str(test_user["id"]),
            event_type=f"test_event_{i}_{uuid4().hex[:8]}",
            combined_metadata=combined_metadata,
            metadata_hash=metadata_hash,
        )

    events = database.event_log.list_events(test_tenant["id"], limit=10)

    assert len(events) >= 3


def test_list_events_filter_by_artifact_type(test_tenant, test_user):
    """Test filtering events by artifact type."""
    import database

    unique_suffix = uuid4().hex[:8]
    other_artifact_id = str(uuid4())

    # Create events for different artifact types
    combined_metadata, metadata_hash = _prepare_event_metadata()
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=f"user_updated_{unique_suffix}",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
    )
    combined_metadata, metadata_hash = _prepare_event_metadata()
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="privileged_domain",
        artifact_id=other_artifact_id,
        event_type=f"privileged_domain_added_{unique_suffix}",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
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
    combined_metadata, metadata_hash = _prepare_event_metadata()
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=event_type,
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
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
    combined_metadata, metadata_hash = _prepare_event_metadata()
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=f"event_by_user_{unique_suffix}",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
    )
    combined_metadata, metadata_hash = _prepare_event_metadata()
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_admin_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=f"event_by_admin_{unique_suffix}",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
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
        combined_metadata, metadata_hash = _prepare_event_metadata()
        database.event_log.create_event(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="test_pagination",
            artifact_id=str(test_user["id"]),
            event_type=f"pagination_test_{i}_{unique_suffix}",
            combined_metadata=combined_metadata,
            metadata_hash=metadata_hash,
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
        combined_metadata, metadata_hash = _prepare_event_metadata()
        database.event_log.create_event(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="user",
            artifact_id=unique_artifact_id,
            event_type=f"test_count_{i}",
            combined_metadata=combined_metadata,
            metadata_hash=metadata_hash,
        )

    new_count = database.event_log.count_events(test_tenant["id"], artifact_id=unique_artifact_id)

    assert new_count == initial_count + 3


def test_count_events_filter_by_artifact_type(test_tenant, test_user):
    """Test counting events filtered by artifact type."""
    import database

    unique_suffix = uuid4().hex[:8]

    # Create events for different types
    combined_metadata, metadata_hash = _prepare_event_metadata()
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type=f"type_a_{unique_suffix}",
        artifact_id=str(uuid4()),
        event_type="test",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
    )
    combined_metadata, metadata_hash = _prepare_event_metadata()
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type=f"type_b_{unique_suffix}",
        artifact_id=str(uuid4()),
        event_type="test",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
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

    combined_metadata, metadata_hash = _prepare_event_metadata(metadata)
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="metadata_test",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
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
    combined_metadata, metadata_hash = _prepare_event_metadata()
    database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type=unique_event_type,
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
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

    combined_metadata, metadata_hash = _prepare_event_metadata()
    result = database.event_log.create_event(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="system_action",
        combined_metadata=combined_metadata,
        metadata_hash=metadata_hash,
    )

    assert result is not None

    # Verify the event was created with system actor
    events = database.event_log.list_events(test_tenant["id"], actor_user_id=SYSTEM_ACTOR_ID)
    assert len(events) >= 1
    assert str(events[0]["actor_user_id"]) == SYSTEM_ACTOR_ID


def test_hash_computation_matches_postgresql():
    """Test that Python hash computation matches PostgreSQL JSONB hash.

    This is a critical regression test for the event logging system.
    Python and PostgreSQL must compute identical hashes for the same metadata
    to avoid foreign key constraint violations when inserting events.

    Bug history: Migration 00015 used PostgreSQL's md5(jsonb::text) which produces
    JSON with spaces after colons. Python's json.dumps(separators=(',', ':'))
    produces compact JSON without spaces. This mismatch broke ALL event logging.
    """
    import database
    from psycopg.types.json import Json

    # Test metadata (system metadata with all null values)
    metadata = {
        "device": None,
        "remote_address": None,
        "session_id_hash": None,
        "user_agent": None,
    }

    # Compute hash using Python (how the application does it)
    from utils.request_metadata import compute_metadata_hash

    python_hash = compute_metadata_hash(metadata)

    # Compute hash using PostgreSQL (how migration 00015 did it)
    # PostgreSQL's JSONB to text conversion adds spaces after colons
    with database.session(tenant_id=database.UNSCOPED) as cur:
        cur.execute("SELECT md5(%s::jsonb::text) as pg_hash", (Json(metadata),))
        result = cur.fetchone()
        pg_hash = result["pg_hash"]

    # They MUST match
    assert python_hash == pg_hash, (
        f"Hash mismatch! Python={python_hash}, PostgreSQL={pg_hash}. "
        f"This will cause foreign key violations when logging events. "
        f"Check that Python's json.dumps() separator matches PostgreSQL's jsonb::text format."
    )


def test_event_logging_creates_metadata_and_event(test_tenant, test_user):
    """Integration test: Verify event logging creates both metadata and event records.

    This test ensures that log_event() successfully creates records in both
    event_log_metadata and event_logs tables without foreign key violations.
    """
    from unittest.mock import Mock

    import database
    from services.event_log import log_event
    from utils.request_context import set_request_context
    from utils.request_metadata import extract_request_metadata

    # Create a mock request with metadata
    mock_request = Mock()
    mock_request.client.host = "127.0.0.1"
    mock_request.headers = {"user-agent": "Test Browser"}
    mock_request.cookies = {"session": "test-session"}

    # Extract and set request metadata in context (simulating middleware)
    request_metadata = extract_request_metadata(mock_request)
    set_request_context(request_metadata)

    # Get initial counts
    initial_metadata_count = database.fetchone(
        database.UNSCOPED, "SELECT COUNT(*) as count FROM event_log_metadata", None
    )["count"]

    initial_events_count = database.event_log.count_events(test_tenant["id"])

    # Log an event
    event_id = str(uuid4())
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="test_artifact",
        artifact_id=event_id,
        event_type="test_event_with_metadata",
        metadata={"test_key": "test_value"},
    )

    # Verify metadata was created (may be deduplicated, so count >= initial)
    new_metadata_count = database.fetchone(
        database.UNSCOPED, "SELECT COUNT(*) as count FROM event_log_metadata", None
    )["count"]
    assert new_metadata_count >= initial_metadata_count

    # Verify event was created
    new_events_count = database.event_log.count_events(test_tenant["id"])
    assert new_events_count == initial_events_count + 1

    # Verify the event can be retrieved and has correct metadata
    events = database.event_log.list_events(
        test_tenant["id"], artifact_type="test_artifact", artifact_id=event_id
    )
    assert len(events) == 1
    event = events[0]

    # Verify custom metadata was preserved
    assert event["metadata"]["test_key"] == "test_value"

    # Verify request metadata was captured
    assert event["metadata"]["remote_address"] == "127.0.0.1"
    assert "Test Browser" in event["metadata"]["user_agent"]


def test_metadata_hash_with_complex_nested_custom_fields(test_tenant, test_user):
    """Edge case: Test metadata hash computation with complex nested structures."""
    from uuid import uuid4

    from services.event_log import log_event

    # Create metadata with nested dicts, arrays, and special characters
    event_id = str(uuid4())
    complex_metadata = {
        "nested_dict": {
            "level_1": {
                "level_2": {"value": "deep nesting"},
                "array": [1, 2, 3, {"key": "value"}],
            }
        },
        "special_chars": "Test with émojis 🚀 and símbolos",
        "array_of_objects": [
            {"id": 1, "name": "First"},
            {"id": 2, "name": "Second"},
        ],
        "unicode": "日本語テスト",
    }

    # Log event with complex metadata
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="test_artifact",
        artifact_id=event_id,
        event_type="test_complex_metadata",
        metadata=complex_metadata,
    )

    # Verify event was created successfully
    import database

    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="test_artifact",
        artifact_id=event_id,
    )
    assert len(events) == 1

    # Verify nested metadata was preserved
    event = events[0]
    assert event["metadata"]["nested_dict"]["level_1"]["level_2"]["value"] == "deep nesting"
    assert event["metadata"]["special_chars"] == "Test with émojis 🚀 and símbolos"
    assert len(event["metadata"]["array_of_objects"]) == 2


def test_metadata_hash_deterministic_with_same_data(test_tenant, test_user):
    """Edge case: Test that identical metadata produces identical hashes."""
    from uuid import uuid4

    import database
    from services.event_log import log_event

    # Create two events with identical custom metadata
    metadata = {
        "key1": "value1",
        "key2": 12345,
        "key3": {"nested": "data"},
    }

    event_id_1 = str(uuid4())
    event_id_2 = str(uuid4())

    # Log two events with same metadata
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="test_artifact",
        artifact_id=event_id_1,
        event_type="test_deterministic_hash_1",
        metadata=metadata.copy(),
    )

    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="test_artifact",
        artifact_id=event_id_2,
        event_type="test_deterministic_hash_2",
        metadata=metadata.copy(),
    )

    # Fetch both events
    events = database.fetchall(
        test_tenant["id"],
        """
        SELECT metadata_hash FROM event_logs
        WHERE artifact_id IN (:id1, :id2)
        ORDER BY created_at
        """,
        {"id1": event_id_1, "id2": event_id_2},
    )

    # Both events should have the same metadata_hash (deduplication)
    assert len(events) == 2
    assert events[0]["metadata_hash"] == events[1]["metadata_hash"]


def test_metadata_hash_with_boolean_and_null_values(test_tenant, test_user):
    """Edge case: Test metadata hash with boolean true/false and null values."""
    from uuid import uuid4

    import database
    from services.event_log import log_event

    # Create metadata with various value types including null, true, false
    event_id = str(uuid4())
    metadata_with_nulls = {
        "bool_true": True,
        "bool_false": False,
        "null_value": None,
        "zero": 0,
        "empty_string": "",
        "empty_array": [],
        "empty_dict": {},
    }

    # Log event
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="test_artifact",
        artifact_id=event_id,
        event_type="test_null_boolean_values",
        metadata=metadata_with_nulls,
    )

    # Verify event was created and metadata preserved
    events = database.event_log.list_events(
        test_tenant["id"],
        artifact_type="test_artifact",
        artifact_id=event_id,
    )
    assert len(events) == 1

    event = events[0]
    # Verify boolean and null values are correctly stored
    assert event["metadata"]["bool_true"] is True
    assert event["metadata"]["bool_false"] is False
    assert event["metadata"]["null_value"] is None
    assert event["metadata"]["zero"] == 0
    assert event["metadata"]["empty_string"] == ""
    assert event["metadata"]["empty_array"] == []
    assert event["metadata"]["empty_dict"] == {}
