"""Comprehensive tests for the idle user inactivation job.

This test file covers all functions in jobs/inactivate_idle_users.py:
- inactivate_idle_users() - Main job function
- _process_tenant() - Per-tenant processing logic

Tests verify:
- Tenant threshold detection
- Idle user detection and inactivation
- OAuth token revocation
- Event logging with correct metadata
- Error handling at tenant and user levels
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

# =============================================================================
# Helper Functions
# =============================================================================


def _make_tenant(
    tenant_id: str | None = None,
    threshold_days: int = 30,
) -> dict[str, Any]:
    """Create a test tenant dict."""
    return {
        "tenant_id": tenant_id or str(uuid4()),
        "inactivity_threshold_days": threshold_days,
    }


def _make_idle_user(
    user_id: str | None = None,
    first_name: str = "Test",
    last_name: str = "User",
    last_activity_at: datetime | None = None,
) -> dict[str, Any]:
    """Create a test idle user dict."""
    return {
        "user_id": user_id or str(uuid4()),
        "first_name": first_name,
        "last_name": last_name,
        "last_activity_at": last_activity_at,
    }


# =============================================================================
# inactivate_idle_users() Tests
# =============================================================================


@patch("jobs.inactivate_idle_users.database")
def test_no_tenants_with_threshold(mock_database):
    """Test returns early when no tenants have threshold configured."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = []

    result = inactivate_idle_users()

    assert result == {
        "tenants_processed": 0,
        "users_inactivated": 0,
        "details": [],
    }
    mock_database.users.get_idle_users_for_tenant.assert_not_called()
    mock_database.users.inactivate_user.assert_not_called()


@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.session")
@patch("jobs.inactivate_idle_users.database")
def test_single_tenant_no_idle_users(mock_database, mock_session, mock_log_event):
    """Test tenant with threshold but no idle users."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    tenant = _make_tenant()
    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = [tenant]
    mock_database.users.get_idle_users_for_tenant.return_value = []

    # Mock session context manager
    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    result = inactivate_idle_users()

    assert result["tenants_processed"] == 1
    assert result["users_inactivated"] == 0
    assert result["details"] == []  # No inactivations means no details

    mock_database.users.get_idle_users_for_tenant.assert_called_once_with(
        tenant["tenant_id"], tenant["inactivity_threshold_days"]
    )
    mock_database.users.inactivate_user.assert_not_called()
    mock_log_event.assert_not_called()


@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.session")
@patch("jobs.inactivate_idle_users.database")
def test_single_tenant_with_idle_users(mock_database, mock_session, mock_log_event):
    """Test inactivates idle users correctly."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    tenant = _make_tenant(threshold_days=30)
    user1 = _make_idle_user(
        first_name="John",
        last_name="Doe",
        last_activity_at=datetime.now(UTC) - timedelta(days=45),
    )
    user2 = _make_idle_user(
        first_name="Jane",
        last_name="Smith",
        last_activity_at=None,  # Never active
    )

    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = [tenant]
    mock_database.users.get_idle_users_for_tenant.return_value = [user1, user2]

    # Mock session context manager
    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    result = inactivate_idle_users()

    assert result["tenants_processed"] == 1
    assert result["users_inactivated"] == 2
    assert len(result["details"]) == 1
    assert result["details"][0]["tenant_id"] == tenant["tenant_id"]
    assert result["details"][0]["inactivated"] == 2
    assert user1["user_id"] in result["details"][0]["user_ids"]
    assert user2["user_id"] in result["details"][0]["user_ids"]


@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.session")
@patch("jobs.inactivate_idle_users.database")
def test_multiple_tenants(mock_database, mock_session, mock_log_event):
    """Test processes all tenants independently."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    tenant1 = _make_tenant(threshold_days=14)
    tenant2 = _make_tenant(threshold_days=90)
    user1 = _make_idle_user()
    user2 = _make_idle_user()

    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = [
        tenant1,
        tenant2,
    ]

    # Return different users for each tenant
    def get_idle_side_effect(tenant_id, threshold):
        if tenant_id == tenant1["tenant_id"]:
            return [user1]
        elif tenant_id == tenant2["tenant_id"]:
            return [user2]
        return []

    mock_database.users.get_idle_users_for_tenant.side_effect = get_idle_side_effect

    # Mock session context manager
    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    result = inactivate_idle_users()

    assert result["tenants_processed"] == 2
    assert result["users_inactivated"] == 2
    assert len(result["details"]) == 2


@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.session")
@patch("jobs.inactivate_idle_users.database")
def test_user_inactivation_calls(mock_database, mock_session, mock_log_event):
    """Test verifies database.users.inactivate_user is called correctly."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    tenant = _make_tenant()
    user = _make_idle_user()

    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = [tenant]
    mock_database.users.get_idle_users_for_tenant.return_value = [user]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    inactivate_idle_users()

    mock_database.users.inactivate_user.assert_called_once_with(
        tenant["tenant_id"], user["user_id"]
    )


@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.session")
@patch("jobs.inactivate_idle_users.database")
def test_oauth_token_revocation(mock_database, mock_session, mock_log_event):
    """Test verifies OAuth tokens are revoked for inactivated users."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    tenant = _make_tenant()
    user = _make_idle_user()

    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = [tenant]
    mock_database.users.get_idle_users_for_tenant.return_value = [user]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    inactivate_idle_users()

    mock_database.oauth2.revoke_all_user_tokens.assert_called_once_with(
        tenant["tenant_id"], user["user_id"]
    )


@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.session")
@patch("jobs.inactivate_idle_users.database")
def test_event_logging(mock_database, mock_session, mock_log_event):
    """Test verifies log_event is called with correct metadata."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    tenant = _make_tenant(threshold_days=30)
    last_activity = datetime.now(UTC) - timedelta(days=45)
    user = _make_idle_user(last_activity_at=last_activity)

    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = [tenant]
    mock_database.users.get_idle_users_for_tenant.return_value = [user]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    inactivate_idle_users()

    mock_log_event.assert_called_once()
    call_kwargs = mock_log_event.call_args[1]

    assert call_kwargs["tenant_id"] == tenant["tenant_id"]
    assert call_kwargs["actor_user_id"] == "00000000-0000-0000-0000-000000000000"
    assert call_kwargs["artifact_type"] == "user"
    assert call_kwargs["artifact_id"] == user["user_id"]
    assert call_kwargs["event_type"] == "user_auto_inactivated"
    assert call_kwargs["metadata"]["reason"] == "inactivity"
    assert call_kwargs["metadata"]["threshold_days"] == 30
    assert call_kwargs["metadata"]["last_activity_at"] == last_activity.isoformat()


@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.session")
@patch("jobs.inactivate_idle_users.database")
def test_tenant_processing_error_handling(mock_database, mock_session, mock_log_event):
    """Test one tenant failing doesn't stop other tenants from processing."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    tenant1 = _make_tenant()
    tenant2 = _make_tenant()
    user2 = _make_idle_user()

    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = [
        tenant1,
        tenant2,
    ]

    # First tenant raises exception, second succeeds
    call_count = [0]

    def session_side_effect(tenant_id):
        call_count[0] += 1
        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock()
        if tenant_id == tenant1["tenant_id"]:
            mock_cm.__enter__.side_effect = Exception("Tenant 1 DB error")
        mock_cm.__exit__ = MagicMock(return_value=False)
        return mock_cm

    mock_session.side_effect = session_side_effect
    mock_database.users.get_idle_users_for_tenant.return_value = [user2]

    result = inactivate_idle_users()

    assert result["tenants_processed"] == 2
    # Tenant 1 failed, tenant 2 succeeded
    assert result["users_inactivated"] == 1
    # Check that tenant 1 has an error in details
    tenant1_detail = next(
        (d for d in result["details"] if d["tenant_id"] == tenant1["tenant_id"]), None
    )
    assert tenant1_detail is not None
    assert "error" in tenant1_detail


@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.session")
@patch("jobs.inactivate_idle_users.database")
def test_user_inactivation_error_handling(mock_database, mock_session, mock_log_event):
    """Test one user failing doesn't stop other users from being inactivated."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    tenant = _make_tenant()
    user1 = _make_idle_user(first_name="Failing")
    user2 = _make_idle_user(first_name="Succeeding")

    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = [tenant]
    mock_database.users.get_idle_users_for_tenant.return_value = [user1, user2]

    # First user fails, second succeeds
    def inactivate_side_effect(tenant_id, user_id):
        if user_id == user1["user_id"]:
            raise Exception("User 1 inactivation error")

    mock_database.users.inactivate_user.side_effect = inactivate_side_effect

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    result = inactivate_idle_users()

    # Only user 2 should be in the successful list
    assert result["users_inactivated"] == 1
    assert len(result["details"]) == 1
    assert result["details"][0]["inactivated"] == 1
    assert user2["user_id"] in result["details"][0]["user_ids"]
    assert user1["user_id"] not in result["details"][0]["user_ids"]


@patch("jobs.inactivate_idle_users.log_event")
@patch("jobs.inactivate_idle_users.session")
@patch("jobs.inactivate_idle_users.database")
def test_last_activity_at_null_in_metadata(mock_database, mock_session, mock_log_event):
    """Test event metadata includes null for users who never had activity."""
    from jobs.inactivate_idle_users import inactivate_idle_users

    tenant = _make_tenant()
    user = _make_idle_user(last_activity_at=None)  # Never active

    mock_database.security.get_all_tenants_with_inactivity_threshold.return_value = [tenant]
    mock_database.users.get_idle_users_for_tenant.return_value = [user]

    mock_session.return_value.__enter__ = MagicMock()
    mock_session.return_value.__exit__ = MagicMock(return_value=False)

    inactivate_idle_users()

    mock_log_event.assert_called_once()
    call_kwargs = mock_log_event.call_args[1]

    assert call_kwargs["metadata"]["last_activity_at"] is None
