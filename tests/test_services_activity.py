"""Tests for services.activity module."""

from unittest.mock import patch


def test_track_activity_force_always_updates_db(test_tenant, test_user):
    """Test that track_activity with force=True always updates the database."""
    import database
    from services.activity import track_activity

    # Call with force=True
    track_activity(str(test_tenant["id"]), str(test_user["id"]), force=True)

    # Verify activity was recorded
    activity = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    assert activity is not None


def test_track_activity_force_sets_cache(test_tenant, test_user):
    """Test that track_activity with force=True sets the cache."""
    from unittest.mock import MagicMock, patch

    from services.activity import ACTIVITY_CACHE_KEY_PREFIX, track_activity

    cache_key = f"{ACTIVITY_CACHE_KEY_PREFIX}{test_user['id']}"
    mock_client = MagicMock()

    # Mock cache.set to verify it's called with correct arguments
    with patch("services.activity.cache.set") as mock_set:
        mock_set.return_value = True

        # Call with force=True
        track_activity(str(test_tenant["id"]), str(test_user["id"]), force=True)

        # Verify cache.set was called with correct key and TTL
        mock_set.assert_called_once()
        call_args = mock_set.call_args
        assert call_args[0][0] == cache_key  # First arg is the key
        assert call_args[0][1] == b"1"  # Second arg is the value
        # Third arg (ttl) should be the configured TTL
        import settings

        assert call_args[1]["ttl"] == settings.ACTIVITY_CACHE_TTL_SECONDS


def test_track_activity_no_force_respects_cache(test_tenant, test_user):
    """Test that track_activity without force respects cached values."""
    import database
    from services.activity import track_activity

    # First call to set the cache
    track_activity(str(test_tenant["id"]), str(test_user["id"]), force=True)

    # Get the initial activity time
    activity1 = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    initial_time = activity1["last_activity_at"]

    # Mock the cache to return a value (simulating cache hit)
    with patch("services.activity.cache.get", return_value=b"1"):
        # Second call should skip DB update due to cache hit
        track_activity(str(test_tenant["id"]), str(test_user["id"]), force=False)

    # Get the activity time again - should be unchanged
    activity2 = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    assert activity2["last_activity_at"] == initial_time


def test_track_activity_no_force_updates_on_cache_miss(test_tenant, test_user):
    """Test that track_activity without force updates DB on cache miss."""
    import database
    from services.activity import track_activity

    # Ensure no cache entry (mock cache miss)
    with patch("services.activity.cache.get", return_value=None):
        with patch("services.activity.cache.set", return_value=True):
            track_activity(str(test_tenant["id"]), str(test_user["id"]), force=False)

    # Verify activity was recorded
    activity = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    assert activity is not None


def test_track_activity_handles_db_errors_gracefully(test_tenant):
    """Test that track_activity doesn't raise on database errors."""
    from uuid import uuid4

    from services.activity import track_activity

    # Use an invalid user_id that won't violate FK constraint but will cause issues
    # Actually, FK constraint would cause an error, so let's mock the DB call
    with patch("services.activity.database.user_activity.upsert_activity") as mock_upsert:
        mock_upsert.side_effect = Exception("Database connection failed")

        # This should not raise
        track_activity(str(test_tenant["id"]), str(uuid4()), force=True)


def test_track_activity_handles_cache_errors_gracefully(test_tenant, test_user):
    """Test that track_activity works even if cache operations fail."""
    import database
    from services.activity import track_activity

    # Mock cache to always fail
    with patch("services.activity.cache.get", side_effect=Exception("Cache unavailable")):
        with patch("services.activity.cache.set", side_effect=Exception("Cache unavailable")):
            # This should not raise and should still update the DB
            track_activity(str(test_tenant["id"]), str(test_user["id"]), force=True)

    # Verify activity was still recorded in DB
    activity = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    assert activity is not None


def test_log_event_triggers_activity_tracking(test_tenant, test_user):
    """Test that log_event also triggers track_activity."""
    import database
    from services.event_log import log_event

    # Log an event
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="test_event",
    )

    # Verify activity was recorded (because log_event calls track_activity)
    activity = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    assert activity is not None


def test_log_event_skips_activity_for_system_actor(test_tenant, test_user):
    """Test that log_event doesn't track activity for SYSTEM_ACTOR_ID."""
    import database
    from services.event_log import SYSTEM_ACTOR_ID, log_event

    # Log an event with system actor
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="system_event",
    )

    # Verify no activity was recorded for system actor
    activity = database.user_activity.get_activity(test_tenant["id"], SYSTEM_ACTOR_ID)
    assert activity is None


def test_log_event_creates_event_log_entry(test_tenant, test_user):
    """Test that log_event creates an entry in the event_logs table."""
    import database
    from services.event_log import log_event

    # Log an event
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="test_event_created",
        metadata={"test_key": "test_value"},
    )

    # Query event_logs table to verify the entry was created
    events = database.event_log.list_events(
        test_tenant["id"],
        event_type="test_event_created",
        actor_user_id=str(test_user["id"]),
    )

    assert len(events) >= 1
    event = events[0]
    assert event["artifact_type"] == "user"
    assert str(event["artifact_id"]) == str(test_user["id"])
    assert event["event_type"] == "test_event_created"
    assert event["metadata"]["test_key"] == "test_value"


def test_log_event_user_signed_in_event_type(test_tenant, test_user):
    """Test that user_signed_in event is correctly logged with metadata."""
    import database
    from services.event_log import log_event

    # Simulate sign-in event logging (as done in mfa.py after successful verification)
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_signed_in",
        metadata={"mfa_method": "totp"},
    )

    # Verify the sign-in event was logged
    events = database.event_log.list_events(
        test_tenant["id"],
        event_type="user_signed_in",
        actor_user_id=str(test_user["id"]),
    )

    assert len(events) >= 1
    event = events[0]
    assert event["event_type"] == "user_signed_in"
    assert event["artifact_type"] == "user"
    assert event["metadata"]["mfa_method"] == "totp"


def test_sign_in_event_updates_activity(test_tenant, test_user):
    """Test that a user_signed_in event also updates user activity."""
    import database
    from services.event_log import log_event

    # Ensure no existing activity
    initial_activity = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))

    # Log sign-in event (this should trigger activity tracking via log_event)
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_signed_in",
        metadata={"mfa_method": "email"},
    )

    # Verify activity was updated
    activity = database.user_activity.get_activity(test_tenant["id"], str(test_user["id"]))
    assert activity is not None
    assert activity["last_activity_at"] is not None

    # If there was initial activity, verify the timestamp was updated
    if initial_activity:
        assert activity["last_activity_at"] >= initial_activity["last_activity_at"]


def test_track_activity_no_force_sets_cache_on_miss(test_tenant, test_user):
    """Test that track_activity without force sets cache after DB update on cache miss."""
    from unittest.mock import patch

    from services.activity import ACTIVITY_CACHE_KEY_PREFIX, track_activity

    cache_key = f"{ACTIVITY_CACHE_KEY_PREFIX}{test_user['id']}"

    # Mock cache miss, then verify set is called
    with patch("services.activity.cache.get", return_value=None) as mock_get:
        with patch("services.activity.cache.set") as mock_set:
            mock_set.return_value = True

            track_activity(str(test_tenant["id"]), str(test_user["id"]), force=False)

            # Verify cache.get was called to check for existing entry
            mock_get.assert_called_once_with(cache_key)

            # Verify cache.set was called after DB update
            mock_set.assert_called_once()
            call_args = mock_set.call_args
            assert call_args[0][0] == cache_key


def test_activity_cache_ttl_is_3_hours():
    """Test that the activity cache TTL is configured for 3 hours."""
    import settings

    # 3 hours = 3 * 60 * 60 = 10800 seconds
    assert settings.ACTIVITY_CACHE_TTL_SECONDS == 10800
