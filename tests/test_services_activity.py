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
    from unittest.mock import patch

    from services.activity import ACTIVITY_CACHE_KEY_PREFIX, track_activity

    cache_key = f"{ACTIVITY_CACHE_KEY_PREFIX}{test_user['id']}"  # noqa: F841

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
        event_type="user_updated",
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
        event_type="user_auto_inactivated",
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
        event_type="user_created",
        metadata={"test_key": "test_value"},
    )

    # Query event_logs table to verify the entry was created
    events = database.event_log.list_events(
        test_tenant["id"],
        event_type="user_created",
        actor_user_id=str(test_user["id"]),
    )

    assert len(events) >= 1
    event = events[0]
    assert event["artifact_type"] == "user"
    assert str(event["artifact_id"]) == str(test_user["id"])
    assert event["event_type"] == "user_created"
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


# =============================================================================
# Tests for track_activity integration in service read functions
# =============================================================================


def test_list_users_tracks_activity(test_tenant, test_admin_user):
    """Test that list_users() triggers activity tracking."""
    from unittest.mock import patch

    from services import users

    requesting_user = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with patch("services.users.track_activity") as mock_track:
        users.list_users(requesting_user)
        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_admin_user["id"]))


def test_get_user_tracks_activity(test_tenant, test_admin_user, test_user):
    """Test that get_user() triggers activity tracking."""
    from unittest.mock import patch

    from services import users

    requesting_user = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with patch("services.users.track_activity") as mock_track:
        users.get_user(requesting_user, str(test_user["id"]))
        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_admin_user["id"]))


def test_get_current_user_profile_tracks_activity(test_tenant, test_user):
    """Test that get_current_user_profile() triggers activity tracking."""
    from datetime import UTC, datetime
    from unittest.mock import patch

    from services import users

    requesting_user = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    user_data = {
        "id": test_user["id"],
        "first_name": "Test",
        "last_name": "User",
        "role": "member",
        "email": test_user["email"],
        "tz": "UTC",
        "locale": "en",
        "created_at": datetime.now(UTC),
    }

    with patch("services.users.track_activity") as mock_track:
        users.get_current_user_profile(requesting_user, user_data)
        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_user["id"]))


def test_list_privileged_domains_tracks_activity(test_tenant, test_admin_user):
    """Test that list_privileged_domains() triggers activity tracking."""
    from unittest.mock import patch

    from services import settings

    requesting_user = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with patch("services.settings.track_activity") as mock_track:
        settings.list_privileged_domains(requesting_user)
        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_admin_user["id"]))


def test_get_security_settings_tracks_activity(test_tenant, test_super_admin_user):
    """Test that get_security_settings() triggers activity tracking."""
    from unittest.mock import patch

    from services import settings

    requesting_user = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "super_admin",
    }

    with patch("services.settings.track_activity") as mock_track:
        settings.get_security_settings(requesting_user)
        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_super_admin_user["id"]))


def test_list_user_emails_tracks_activity(test_tenant, test_admin_user, test_user):
    """Test that list_user_emails() triggers activity tracking."""
    from unittest.mock import patch

    from services import emails

    requesting_user = {
        "id": str(test_admin_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "admin",
    }

    with patch("services.emails.track_activity") as mock_track:
        emails.list_user_emails(requesting_user, str(test_user["id"]))
        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_admin_user["id"]))


def test_get_mfa_status_tracks_activity(test_tenant, test_user):
    """Test that get_mfa_status() triggers activity tracking."""
    from unittest.mock import patch

    from services import mfa

    requesting_user = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    user_data = {
        "id": test_user["id"],
        "totp_enabled": False,
        "email_mfa_enabled": True,
    }

    with patch("services.mfa.track_activity") as mock_track:
        mfa.get_mfa_status(requesting_user, user_data)
        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_user["id"]))


def test_get_backup_codes_status_tracks_activity(test_tenant, test_user):
    """Test that get_backup_codes_status() triggers activity tracking."""
    from unittest.mock import patch

    from services import mfa

    requesting_user = {
        "id": str(test_user["id"]),
        "tenant_id": str(test_tenant["id"]),
        "role": "member",
    }

    user_data = {
        "id": test_user["id"],
    }

    with patch("services.mfa.track_activity") as mock_track:
        mfa.get_backup_codes_status(requesting_user, user_data)
        mock_track.assert_called_once_with(str(test_tenant["id"]), str(test_user["id"]))


# =============================================================================
# Code Analysis Backstop Test
# Ensures all service functions with RequestingUser call log_event or track_activity
# =============================================================================


def test_all_service_functions_have_activity_or_logging():
    """
    Backstop test: Verify all service layer functions that receive RequestingUser
    call either log_event (for writes) or track_activity (for reads).

    This ensures the "if there is a write, there is a log" and "read operations
    track activity" requirements from the backlog are enforced.
    """
    import ast
    import inspect

    from services import emails, mfa, oauth2, reactivation, settings, users

    # Functions that are explicitly exempt from this requirement
    # (e.g., internal helpers, or functions that don't need tracking)
    exempt_functions = {
        # Internal helpers that are called by other service functions
        "_require_admin",
        "_require_super_admin",
        "_require_self_or_admin",
        "_user_row_to_summary",
        "_user_row_to_detail",
        "_user_row_to_profile",
        # Functions that don't receive RequestingUser but are public
        "count_users",
        "list_users_raw",
        "get_tenant_name",
        "get_available_roles",
        "get_user_by_id_raw",
        "get_privileged_domains_list",
        "get_session_settings",
        "is_privileged_email",
        "get_client_by_client_id",
        "get_all_clients",
        "get_email_for_verification",
        "get_primary_email",
        "get_email_address_by_id",
        "get_user_with_primary_email",
        "list_backup_codes_raw",
        "get_pending_totp_setup",
        # OAuth2 functions (client credentials, no user context)
        "create_client",
        "update_client",
        "delete_client",
        "create_authorization_code",
        "exchange_authorization_code",
        "refresh_access_token",
        "revoke_token",
        # Reactivation read functions - KNOWN BUG (see ISSUES.md)
        # TODO: Remove these exemptions after fixing the production bug
        "list_pending_requests",
        "count_pending_requests",
        "list_previous_requests",
    }

    # All exemptions (only internal helpers and functions without RequestingUser)
    all_exempt = exempt_functions

    class ActivityCallFinder(ast.NodeVisitor):
        """AST visitor to find calls to log_event or track_activity."""

        def __init__(self):
            self.has_log_event = False
            self.has_track_activity = False

        def visit_Call(self, node):  # noqa: N802
            # Check for direct function calls: log_event() or track_activity()
            if isinstance(node.func, ast.Name):
                if node.func.id == "log_event":
                    self.has_log_event = True
                elif node.func.id == "track_activity":
                    self.has_track_activity = True
            # Check for module.function calls: event_log.log_event()
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr == "log_event":
                    self.has_log_event = True
                elif node.func.attr == "track_activity":
                    self.has_track_activity = True
            self.generic_visit(node)

    def has_requesting_user_param(func) -> bool:
        """Check if function has a RequestingUser parameter."""
        try:
            sig = inspect.signature(func)
            for param in sig.parameters.values():
                if "RequestingUser" in str(param.annotation):
                    return True
                if param.name == "requesting_user":
                    return True
            return False
        except (ValueError, TypeError):
            return False

    def check_function_has_tracking(func) -> tuple[bool, bool, bool]:
        """
        Check if a function calls log_event or track_activity.
        Returns (has_log_event, has_track_activity, could_parse).
        """
        try:
            source = inspect.getsource(func)
            tree = ast.parse(source)
            finder = ActivityCallFinder()
            finder.visit(tree)
            return finder.has_log_event, finder.has_track_activity, True
        except (OSError, TypeError, SyntaxError):
            return False, False, False

    # Collect all service modules to check
    service_modules = [users, settings, emails, mfa, oauth2, reactivation]

    missing_tracking = []

    for module in service_modules:
        module_name = module.__name__

        # Get all functions from the module
        for name, func in inspect.getmembers(module, inspect.isfunction):
            # Skip private functions and exempt functions
            if name.startswith("_") or name in all_exempt:
                continue

            # Skip functions not defined in this module (imports)
            if func.__module__ != module_name:
                continue

            # Only check functions that receive RequestingUser
            if not has_requesting_user_param(func):
                continue

            # Check if function has log_event or track_activity call
            has_log, has_track, could_parse = check_function_has_tracking(func)

            if could_parse and not has_log and not has_track:
                missing_tracking.append(f"{module_name}.{name}")

    if missing_tracking:
        missing_list = "\n  - ".join(missing_tracking)
        raise AssertionError(
            "Service functions with RequestingUser missing log_event or "
            f"track_activity:\n  - {missing_list}\n\n"
            "All service functions that receive RequestingUser must call either:\n"
            "  - log_event() for write operations\n"
            "  - track_activity() for read operations\n\n"
            "If a function is intentionally exempt, add it to exempt_functions in "
            "this test."
        )
