"""Tests for utils.auth module."""

from unittest.mock import Mock

import database


def test_verify_login_success(test_user):
    """Test successful login verification."""
    from utils.auth import verify_login

    # Password is "TestPassword123!" from the conftest fixture
    user = verify_login(test_user["tenant_id"], test_user["email"], "TestPassword123!")

    assert user is not None
    assert user["id"] == test_user["id"]
    assert user["first_name"] == test_user["first_name"]
    assert user["last_name"] == test_user["last_name"]


def test_verify_login_wrong_password(test_user):
    """Test login verification with wrong password."""
    from utils.auth import verify_login

    user = verify_login(test_user["tenant_id"], test_user["email"], "WrongPassword123!")

    assert user is None


def test_verify_login_nonexistent_user(test_tenant):
    """Test login verification with nonexistent user."""
    from utils.auth import verify_login

    user = verify_login(test_tenant["id"], "nonexistent@example.com", "SomePassword123!")

    assert user is None


def test_verify_login_updates_last_login(test_user):
    """Test that verify_login updates the last_login timestamp."""
    from utils.auth import verify_login

    # Get initial last_login
    user_before = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    initial_last_login = user_before["last_login"]

    # Login
    user = verify_login(test_user["tenant_id"], test_user["email"], "TestPassword123!")

    assert user is not None
    # last_login should be updated
    assert user["last_login"] is not None
    if initial_last_login:
        assert user["last_login"] >= initial_last_login


def test_get_current_user_authenticated(test_user):
    """Test getting current user from session when authenticated."""
    from utils.auth import get_current_user

    # Create mock request with session
    request = Mock()
    request.session = {"user_id": test_user["id"], "session_start": None}  # No timeout check

    user = get_current_user(request, test_user["tenant_id"])

    assert user is not None
    assert user["id"] == test_user["id"]
    assert user["first_name"] == test_user["first_name"]


def test_get_current_user_not_authenticated():
    """Test getting current user when not authenticated."""
    from utils.auth import get_current_user

    # Create mock request with empty session
    request = Mock()
    request.session = {}

    user = get_current_user(request, "any-tenant-id")

    assert user is None


def test_get_current_user_with_valid_session_timeout(test_user, test_admin_user):
    """Test session timeout check with valid (non-expired) session."""
    import time

    from utils.auth import get_current_user

    # Set up security settings with 3600 second timeout
    database.security.update_security_settings(
        test_user["tenant_id"],
        timeout_seconds=3600,  # 1 hour
        persistent_sessions=False,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_user["tenant_id"],
    )

    # Create mock request with recent session start
    request = Mock()
    request.session = {
        "user_id": test_user["id"],
        "session_start": int(time.time()) - 1800,  # 30 minutes ago
    }

    user = get_current_user(request, test_user["tenant_id"])

    assert user is not None
    assert user["id"] == test_user["id"]


def test_get_current_user_with_expired_session_timeout(test_user, test_admin_user):
    """Test session timeout check with expired session."""
    import time

    from utils.auth import get_current_user

    # Set up security settings with 1800 second timeout
    database.security.update_security_settings(
        test_user["tenant_id"],
        timeout_seconds=1800,  # 30 minutes
        persistent_sessions=False,
        allow_users_edit_profile=True,
        allow_users_add_emails=True,
        updated_by=test_admin_user["id"],
        tenant_id_value=test_user["tenant_id"],
    )

    # Create mock request with expired session
    request = Mock()
    session_dict = {
        "user_id": test_user["id"],
        "session_start": int(time.time()) - 3600,  # 1 hour ago (expired)
    }
    request.session = session_dict

    user = get_current_user(request, test_user["tenant_id"])

    # Session should be expired and cleared
    assert user is None
    # Verify session.clear() was called (session dict should be empty)
    assert len(session_dict) == 0


def test_get_current_user_no_timeout_configured(test_user):
    """Test that sessions work when no timeout is configured."""
    import time

    from utils.auth import get_current_user

    # Create mock request with session start but no timeout configured
    request = Mock()
    request.session = {
        "user_id": test_user["id"],
        "session_start": int(time.time()) - 86400,  # 24 hours ago
    }

    # No timeout configured, so even old sessions should work
    user = get_current_user(request, test_user["tenant_id"])

    assert user is not None
    assert user["id"] == test_user["id"]
