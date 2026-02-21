"""Tests for reactivation request service layer functions."""

from uuid import uuid4

import pytest
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from services.types import RequestingUser


def _make_requesting_user(user: dict, tenant_id: str, role: str = None) -> RequestingUser:
    """Helper to create RequestingUser from test fixture."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role or user.get("role", "member"),
    )


def _inactivate_user(tenant_id: str, user_id: str) -> None:
    """Helper to inactivate a user directly in the database."""
    import database

    database.users.inactivate_user(tenant_id, user_id)


# =============================================================================
# create_request Tests
# =============================================================================


def test_create_request_success(test_tenant, test_user):
    """Test creating a reactivation request for an inactivated user."""
    from services import reactivation as reactivation_service

    # Inactivate the user first
    _inactivate_user(test_tenant["id"], test_user["id"])

    result = reactivation_service.create_request(
        tenant_id=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    assert result.user_id == str(test_user["id"])
    assert result.first_name == "Test"
    assert result.last_name == "User"
    assert result.requested_at is not None
    assert result.decision is None


def test_create_request_with_metadata(test_tenant, test_user):
    """Test creating a reactivation request with request metadata."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])

    request_metadata = {
        "remote_address": "192.168.1.1",
        "user_agent": "Mozilla/5.0",
        "device": "Desktop",
        "session_id_hash": "abc123",
    }

    result = reactivation_service.create_request(
        tenant_id=test_tenant["id"],
        user_id=str(test_user["id"]),
        request_metadata=request_metadata,
    )

    assert result.user_id == str(test_user["id"])
    assert result.decision is None


def test_create_request_user_not_found(test_tenant):
    """Test creating a request for a nonexistent user fails."""
    from services import reactivation as reactivation_service

    with pytest.raises(NotFoundError) as exc_info:
        reactivation_service.create_request(
            tenant_id=test_tenant["id"],
            user_id=str(uuid4()),
        )

    assert exc_info.value.code == "user_not_found"


def test_create_request_user_not_inactivated(test_tenant, test_user):
    """Test creating a request for an active user fails."""
    from services import reactivation as reactivation_service

    with pytest.raises(ValidationError) as exc_info:
        reactivation_service.create_request(
            tenant_id=test_tenant["id"],
            user_id=str(test_user["id"]),
        )

    assert exc_info.value.code == "not_inactivated"


def test_create_request_previously_denied(test_tenant, test_user):
    """Test creating a request when previously denied fails."""
    import database
    from services import reactivation as reactivation_service

    # Inactivate and mark as denied
    _inactivate_user(test_tenant["id"], test_user["id"])
    database.users.set_reactivation_denied(test_tenant["id"], test_user["id"])

    with pytest.raises(ValidationError) as exc_info:
        reactivation_service.create_request(
            tenant_id=test_tenant["id"],
            user_id=str(test_user["id"]),
        )

    assert exc_info.value.code == "previously_denied"


def test_create_request_returns_existing_pending(test_tenant, test_user):
    """Test that creating a request when one exists returns the existing one."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])

    # Create first request
    first = reactivation_service.create_request(
        tenant_id=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    # Try to create another - should return the existing one
    second = reactivation_service.create_request(
        tenant_id=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    assert first.id == second.id
    assert first.user_id == second.user_id


# =============================================================================
# has_pending_request Tests
# =============================================================================


def test_has_pending_request_true(test_tenant, test_user):
    """Test checking for pending request when one exists."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    result = reactivation_service.has_pending_request(test_tenant["id"], str(test_user["id"]))

    assert result is True


def test_has_pending_request_false(test_tenant, test_user):
    """Test checking for pending request when none exists."""
    from services import reactivation as reactivation_service

    result = reactivation_service.has_pending_request(test_tenant["id"], str(test_user["id"]))

    assert result is False


# =============================================================================
# can_request_reactivation Tests
# =============================================================================


def test_can_request_reactivation_yes(test_tenant, test_user):
    """Test eligibility check for a valid candidate."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])

    result = reactivation_service.can_request_reactivation(test_tenant["id"], str(test_user["id"]))

    assert result["can_request"] is True
    assert result["reason"] is None


def test_can_request_reactivation_not_inactivated(test_tenant, test_user):
    """Test eligibility check for an active user."""
    from services import reactivation as reactivation_service

    result = reactivation_service.can_request_reactivation(test_tenant["id"], str(test_user["id"]))

    assert result["can_request"] is False
    assert result["reason"] == "not_inactivated"


def test_can_request_reactivation_user_not_found(test_tenant):
    """Test eligibility check for a nonexistent user."""
    from services import reactivation as reactivation_service

    result = reactivation_service.can_request_reactivation(test_tenant["id"], str(uuid4()))

    assert result["can_request"] is False
    assert result["reason"] == "user_not_found"


def test_can_request_reactivation_previously_denied(test_tenant, test_user):
    """Test eligibility check when previously denied."""
    import database
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    database.users.set_reactivation_denied(test_tenant["id"], test_user["id"])

    result = reactivation_service.can_request_reactivation(test_tenant["id"], str(test_user["id"]))

    assert result["can_request"] is False
    assert result["reason"] == "previously_denied"


def test_can_request_reactivation_already_pending(test_tenant, test_user):
    """Test eligibility check when request already pending."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    result = reactivation_service.can_request_reactivation(test_tenant["id"], str(test_user["id"]))

    assert result["can_request"] is False
    assert result["reason"] == "request_pending"


# =============================================================================
# list_pending_requests Tests
# =============================================================================


def test_list_pending_requests_admin(test_tenant, test_admin_user, test_user):
    """Test listing pending requests as an admin."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    result = reactivation_service.list_pending_requests(requesting_user)

    assert len(result) == 1
    assert result[0].user_id == str(test_user["id"])
    assert result[0].first_name == "Test"
    assert result[0].last_name == "User"


def test_list_pending_requests_super_admin(test_tenant, test_super_admin_user, test_user):
    """Test listing pending requests as a super_admin."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    result = reactivation_service.list_pending_requests(requesting_user)

    assert len(result) == 1


def test_list_pending_requests_member_forbidden(test_tenant, test_user):
    """Test that members cannot list pending requests."""
    from services import reactivation as reactivation_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        reactivation_service.list_pending_requests(requesting_user)

    assert exc_info.value.code == "admin_required"


def test_list_pending_requests_empty(test_tenant, test_admin_user):
    """Test listing pending requests when none exist."""
    from services import reactivation as reactivation_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    result = reactivation_service.list_pending_requests(requesting_user)

    assert len(result) == 0


# =============================================================================
# count_pending_requests Tests
# =============================================================================


def test_count_pending_requests(test_tenant, test_admin_user, test_user):
    """Test counting pending requests."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    count = reactivation_service.count_pending_requests(requesting_user)

    assert count == 1


def test_count_pending_requests_member_forbidden(test_tenant, test_user):
    """Test that members cannot count pending requests."""
    from services import reactivation as reactivation_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError):
        reactivation_service.count_pending_requests(requesting_user)


# =============================================================================
# list_previous_requests Tests
# =============================================================================


def test_list_previous_requests_after_approval(test_tenant, test_admin_user, test_user):
    """Test listing previously decided requests after an approval."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    reactivation_service.approve_request(requesting_user, request.id)

    result = reactivation_service.list_previous_requests(requesting_user)

    assert len(result) == 1
    assert result[0].decision == "approved"
    assert result[0].decided_at is not None
    assert result[0].decided_by_name is not None


def test_list_previous_requests_after_denial(test_tenant, test_admin_user, test_user):
    """Test listing previously decided requests after a denial."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    reactivation_service.deny_request(requesting_user, request.id)

    result = reactivation_service.list_previous_requests(requesting_user)

    assert len(result) == 1
    assert result[0].decision == "denied"


def test_list_previous_requests_member_forbidden(test_tenant, test_user):
    """Test that members cannot list previous requests."""
    from services import reactivation as reactivation_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError):
        reactivation_service.list_previous_requests(requesting_user)


# =============================================================================
# approve_request Tests
# =============================================================================


def test_approve_request_success(test_tenant, test_admin_user, test_user):
    """Test approving a reactivation request."""
    import database
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    result = reactivation_service.approve_request(requesting_user, request.id)

    assert result.decision == "approved"

    # Verify user is reactivated
    user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    assert user["is_inactivated"] is False


def test_approve_request_super_admin(test_tenant, test_super_admin_user, test_user):
    """Test that super_admin can approve requests."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    result = reactivation_service.approve_request(requesting_user, request.id)

    assert result.decision == "approved"


def test_approve_request_member_forbidden(test_tenant, test_user):
    """Test that members cannot approve requests."""
    from services import reactivation as reactivation_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        reactivation_service.approve_request(requesting_user, str(uuid4()))

    assert exc_info.value.code == "admin_required"


def test_approve_request_not_found(test_tenant, test_admin_user):
    """Test approving a nonexistent request fails."""
    from services import reactivation as reactivation_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        reactivation_service.approve_request(requesting_user, str(uuid4()))

    assert exc_info.value.code == "request_not_found"


def test_approve_request_already_decided(test_tenant, test_admin_user, test_user):
    """Test approving an already decided request fails."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # Approve once
    reactivation_service.approve_request(requesting_user, request.id)

    # Try to approve again
    with pytest.raises(ValidationError) as exc_info:
        reactivation_service.approve_request(requesting_user, request.id)

    assert exc_info.value.code == "already_decided"


def test_approve_request_clears_denial_flag(test_tenant, test_admin_user, test_user):
    """Test that approving clears any existing denial flag."""
    import database
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])

    # Set denial flag (simulating a previous denial that was manually reversed)
    database.users.set_reactivation_denied(test_tenant["id"], test_user["id"])

    # Clear the denial flag so we can create a request
    database.users.clear_reactivation_denied(test_tenant["id"], test_user["id"])

    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    reactivation_service.approve_request(requesting_user, request.id)

    # Verify denial flag is cleared
    user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    assert user.get("reactivation_denied_at") is None


# =============================================================================
# deny_request Tests
# =============================================================================


def test_deny_request_success(test_tenant, test_admin_user, test_user):
    """Test denying a reactivation request."""
    import database
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    result = reactivation_service.deny_request(requesting_user, request.id)

    assert result.decision == "denied"

    # Verify user still inactivated and marked as denied
    user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    assert user["is_inactivated"] is True
    assert user["reactivation_denied_at"] is not None


def test_deny_request_super_admin(test_tenant, test_super_admin_user, test_user):
    """Test that super_admin can deny requests."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    result = reactivation_service.deny_request(requesting_user, request.id)

    assert result.decision == "denied"


def test_deny_request_member_forbidden(test_tenant, test_user):
    """Test that members cannot deny requests."""
    from services import reactivation as reactivation_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        reactivation_service.deny_request(requesting_user, str(uuid4()))

    assert exc_info.value.code == "admin_required"


def test_deny_request_not_found(test_tenant, test_admin_user):
    """Test denying a nonexistent request fails."""
    from services import reactivation as reactivation_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(NotFoundError) as exc_info:
        reactivation_service.deny_request(requesting_user, str(uuid4()))

    assert exc_info.value.code == "request_not_found"


def test_deny_request_already_decided(test_tenant, test_admin_user, test_user):
    """Test denying an already decided request fails."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    # Deny once
    reactivation_service.deny_request(requesting_user, request.id)

    # Try to deny again
    with pytest.raises(ValidationError) as exc_info:
        reactivation_service.deny_request(requesting_user, request.id)

    assert exc_info.value.code == "already_decided"


def test_deny_prevents_future_requests(test_tenant, test_admin_user, test_user):
    """Test that a denied user cannot submit future requests."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    reactivation_service.deny_request(requesting_user, request.id)

    # Try to create a new request - should fail
    with pytest.raises(ValidationError) as exc_info:
        reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    assert exc_info.value.code == "previously_denied"


# =============================================================================
# Event Logging Tests
# =============================================================================


def test_create_request_logs_event(test_tenant, test_user):
    """Test that creating a request logs an event."""
    import database
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    # Check for the event log
    events = database.fetchall(
        test_tenant["id"],
        """
        SELECT * FROM event_logs
        WHERE artifact_type = 'reactivation_request'
        AND event_type = 'reactivation_requested'
        """,
        {},
    )

    assert len(events) == 1
    assert events[0]["actor_user_id"] == test_user["id"]


def test_approve_request_logs_events(test_tenant, test_admin_user, test_user):
    """Test that approving a request logs both approval and reactivation events."""
    import database
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    reactivation_service.approve_request(requesting_user, request.id)

    # Check for approval event
    approval_events = database.fetchall(
        test_tenant["id"],
        """
        SELECT * FROM event_logs
        WHERE artifact_type = 'reactivation_request'
        AND event_type = 'reactivation_approved'
        """,
        {},
    )
    assert len(approval_events) == 1
    assert approval_events[0]["actor_user_id"] == test_admin_user["id"]

    # Check for user reactivation event
    user_events = database.fetchall(
        test_tenant["id"],
        """
        SELECT * FROM event_logs
        WHERE artifact_type = 'user'
        AND event_type = 'user_reactivated'
        """,
        {},
    )
    assert len(user_events) == 1
    assert user_events[0]["actor_user_id"] == test_admin_user["id"]
    assert user_events[0]["artifact_id"] == test_user["id"]


def test_deny_request_logs_event(test_tenant, test_admin_user, test_user):
    """Test that denying a request logs an event."""
    import database
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    reactivation_service.deny_request(requesting_user, request.id)

    events = database.fetchall(
        test_tenant["id"],
        """
        SELECT * FROM event_logs
        WHERE artifact_type = 'reactivation_request'
        AND event_type = 'reactivation_denied'
        """,
        {},
    )

    assert len(events) == 1
    assert events[0]["actor_user_id"] == test_admin_user["id"]
