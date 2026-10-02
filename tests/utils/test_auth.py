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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
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


# =============================================================================
# verify_login_with_status Tests
# =============================================================================


def test_verify_login_with_status_success(test_tenant, test_user):
    """Test successful login returns status='success'."""
    from utils.auth import verify_login_with_status

    result = verify_login_with_status(test_tenant["id"], test_user["email"], "TestPassword123!")

    assert result["status"] == "success"
    assert result["user"] is not None
    assert result["user"]["id"] == test_user["id"]


def test_verify_login_with_status_invalid_email(test_tenant):
    """Test that unknown email returns status='invalid_credentials'."""
    from utils.auth import verify_login_with_status

    result = verify_login_with_status(test_tenant["id"], "unknown@example.com", "password")

    assert result["status"] == "invalid_credentials"
    assert result["user"] is None


def test_verify_login_with_status_wrong_password(test_tenant, test_user):
    """Test that wrong password returns status='invalid_credentials'."""
    from utils.auth import verify_login_with_status

    result = verify_login_with_status(test_tenant["id"], test_user["email"], "WrongPassword!")

    assert result["status"] == "invalid_credentials"
    assert result["user"] is None


def test_verify_login_with_status_inactivated(test_tenant, test_user):
    """Test that inactivated user returns status='inactivated' with can_request=True."""
    from utils.auth import verify_login_with_status

    # Inactivate the user
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    result = verify_login_with_status(test_tenant["id"], test_user["email"], "TestPassword123!")

    assert result["status"] == "inactivated"
    assert result["user"] is not None
    assert result["can_request_reactivation"] is True


def test_verify_login_with_status_denied(test_tenant, test_user):
    """Test that denied reactivation returns status='denied' with can_request=False."""
    from utils.auth import verify_login_with_status

    # Inactivate the user and deny reactivation
    database.users.inactivate_user(test_tenant["id"], test_user["id"])
    database.users.set_reactivation_denied(test_tenant["id"], test_user["id"])

    result = verify_login_with_status(test_tenant["id"], test_user["email"], "TestPassword123!")

    assert result["status"] == "denied"
    assert result["user"] is not None
    assert result["can_request_reactivation"] is False


def test_verify_login_with_status_pending(test_tenant, test_user):
    """Test that pending reactivation request returns status='pending' with can_request=False."""
    from utils.auth import verify_login_with_status

    # Inactivate the user and create a pending reactivation request
    database.users.inactivate_user(test_tenant["id"], test_user["id"])
    database.reactivation.create_request(test_tenant["id"], test_tenant["id"], test_user["id"])

    result = verify_login_with_status(test_tenant["id"], test_user["email"], "TestPassword123!")

    assert result["status"] == "pending"
    assert result["user"] is not None
    assert result["can_request_reactivation"] is False


def test_get_current_user_session_timeout(test_tenant, test_user):
    """Test that expired session clears session and returns None."""
    import time

    from utils.auth import get_current_user

    # Set session timeout to 1 second
    database.security.update_security_settings(
        tenant_id=test_tenant["id"],
        timeout_seconds=1,
        persistent_sessions=True,
        allow_users_edit_profile=True,
        inactivity_threshold_days=None,
        max_certificate_lifetime_years=10,
        certificate_rotation_window_days=90,
        minimum_password_length=14,
        minimum_zxcvbn_score=3,
        group_assertion_scope="access_relevant",
        require_email_verification_for_login=False,
        updated_by=test_user["id"],
        tenant_id_value=test_tenant["id"],
    )

    # Create a mock request with an expired session (2 seconds ago)
    request = Mock()
    session_dict = {
        "user_id": str(test_user["id"]),
        "session_start": int(time.time()) - 2,  # Started 2 seconds ago
    }
    request.session = session_dict

    result = get_current_user(request, test_tenant["id"])

    assert result is None
    # Verify session was cleared
    assert len(session_dict) == 0


def test_get_current_user_inactivated_clears_session(test_tenant, test_user):
    """Test that inactivated user mid-session clears session and returns None."""
    import time

    from utils.auth import get_current_user

    # Inactivate the user
    database.users.inactivate_user(test_tenant["id"], test_user["id"])

    # Create a mock request with valid session
    request = Mock()
    session_dict = {
        "user_id": str(test_user["id"]),
        "session_start": int(time.time()),
    }
    request.session = session_dict

    result = get_current_user(request, test_tenant["id"])

    assert result is None
    # Verify session was cleared
    assert len(session_dict) == 0


def test_get_current_user_revoked_session_clears_session(test_tenant, test_user):
    """A session whose sid was revoked server-side is signed out."""
    import time

    from utils.auth import get_current_user
    from utils.session import SESSION_ID_KEY

    tid = str(test_tenant["id"])
    database.revoked_sessions.revoke_session(tid, tid, "revoked-sid")
    request = Mock()
    session_dict = {
        "user_id": str(test_user["id"]),
        "session_start": int(time.time()),
        SESSION_ID_KEY: "revoked-sid",
    }
    request.session = session_dict

    assert get_current_user(request, tid) is None
    assert session_dict == {}


def test_get_current_user_other_sid_revoked_keeps_session(test_tenant, test_user):
    """Only the revoked sid is refused; a session without a sid is never matched."""
    import time

    from utils.auth import get_current_user
    from utils.session import SESSION_ID_KEY

    tid = str(test_tenant["id"])
    database.revoked_sessions.revoke_session(tid, tid, "revoked-sid")
    for extra in ({SESSION_ID_KEY: "live-sid"}, {}):
        request = Mock()
        request.session = {
            "user_id": str(test_user["id"]),
            "session_start": int(time.time()),
            **extra,
        }
        assert get_current_user(request, tid) is not None


def test_get_current_user_mints_sid_for_session_without_one(test_tenant, test_user):
    """A session from before sids existed gets one, so a logout can revoke it."""
    import time

    from utils.auth import get_current_user
    from utils.session import SESSION_ID_KEY

    tid = str(test_tenant["id"])
    request = Mock()
    request.session = {"user_id": str(test_user["id"]), "session_start": int(time.time())}

    assert get_current_user(request, tid) is not None
    sid = request.session[SESSION_ID_KEY]
    assert isinstance(sid, str) and sid

    # The minted sid is stable, and revoking it signs the session out.
    assert get_current_user(request, tid) is not None
    assert request.session[SESSION_ID_KEY] == sid
    database.revoked_sessions.revoke_session(tid, tid, sid)
    assert get_current_user(request, tid) is None


def test_get_current_user_keeps_existing_sid(test_tenant, test_user):
    import time

    from utils.auth import get_current_user
    from utils.session import SESSION_ID_KEY

    request = Mock()
    request.session = {
        "user_id": str(test_user["id"]),
        "session_start": int(time.time()),
        SESSION_ID_KEY: "existing-sid",
    }
    assert get_current_user(request, str(test_tenant["id"])) is not None
    assert request.session[SESSION_ID_KEY] == "existing-sid"


def test_get_current_user_revocation_is_per_tenant(test_tenant, test_user):
    """A sid revoked in another tenant does not sign this session out."""
    import time
    from uuid import uuid4

    from utils.auth import get_current_user
    from utils.session import SESSION_ID_KEY

    other = database.fetchone(
        database.UNSCOPED,
        "insert into tenants (subdomain, name) values (:s, 'Other') returning id",
        {"s": f"other-{uuid4().hex[:8]}"},
    )
    try:
        database.revoked_sessions.revoke_session(str(other["id"]), str(other["id"]), "shared-sid")
        request = Mock()
        request.session = {
            "user_id": str(test_user["id"]),
            "session_start": int(time.time()),
            SESSION_ID_KEY: "shared-sid",
        }
        assert get_current_user(request, str(test_tenant["id"])) is not None
    finally:
        database.execute(
            database.UNSCOPED, "delete from tenants where id = :id", {"id": other["id"]}
        )
