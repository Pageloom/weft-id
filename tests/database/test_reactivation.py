"""Tests for reactivation request database operations."""

from uuid import uuid4


def _inactivate_user(tenant_id: str, user_id: str) -> None:
    """Helper to inactivate a user directly in the database."""
    import database

    database.users.inactivate_user(tenant_id, user_id)


# =============================================================================
# create_request Tests
# =============================================================================


def test_create_request(test_tenant, test_user):
    """Test creating a reactivation request."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    result = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    assert result is not None
    assert result["user_id"] == test_user["id"]
    assert result["tenant_id"] == test_tenant["id"]
    assert result["requested_at"] is not None
    assert result["decision"] is None


def test_create_request_upsert(test_tenant, test_user):
    """Test that creating a request when one exists updates it (upsert)."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    # Create first request
    first = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    # Create again - should upsert and update requested_at
    second = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    # Same request ID due to unique constraint on (tenant_id, user_id)
    assert first["id"] == second["id"]
    # requested_at might be updated (depends on timing)
    assert second["requested_at"] is not None


# =============================================================================
# get_pending_request Tests
# =============================================================================


def test_get_pending_request_exists(test_tenant, test_user):
    """Test getting a pending request that exists."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    result = database.reactivation.get_pending_request(test_tenant["id"], str(test_user["id"]))

    assert result is not None
    assert result["user_id"] == test_user["id"]


def test_get_pending_request_not_exists(test_tenant, test_user):
    """Test getting a pending request that doesn't exist."""
    import database

    result = database.reactivation.get_pending_request(test_tenant["id"], str(test_user["id"]))

    assert result is None


def test_get_pending_request_after_decision(test_tenant, test_user, test_admin_user):
    """Test that get_pending_request returns None after decision."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    # Approve the request
    database.reactivation.approve_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    # Should no longer be pending
    result = database.reactivation.get_pending_request(test_tenant["id"], str(test_user["id"]))

    assert result is None


# =============================================================================
# get_request_by_id Tests
# =============================================================================


def test_get_request_by_id_exists(test_tenant, test_user):
    """Test getting a request by ID that exists."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    created = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    result = database.reactivation.get_request_by_id(test_tenant["id"], str(created["id"]))

    assert result is not None
    assert result["id"] == created["id"]
    assert result["first_name"] == "Test"
    assert result["last_name"] == "User"
    assert result["email"] == test_user["email"]


def test_get_request_by_id_not_exists(test_tenant):
    """Test getting a request by ID that doesn't exist."""
    import database

    result = database.reactivation.get_request_by_id(test_tenant["id"], str(uuid4()))

    assert result is None


# =============================================================================
# list_pending_requests Tests
# =============================================================================


def test_list_pending_requests_empty(test_tenant):
    """Test listing pending requests when none exist."""
    import database

    result = database.reactivation.list_pending_requests(test_tenant["id"])

    assert result == []


def test_list_pending_requests_with_requests(test_tenant, test_user, test_admin_user):
    """Test listing pending requests with multiple users."""
    import database

    # Inactivate both users
    _inactivate_user(test_tenant["id"], test_user["id"])
    _inactivate_user(test_tenant["id"], test_admin_user["id"])

    # Create requests for both
    database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )
    database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_admin_user["id"]),
    )

    result = database.reactivation.list_pending_requests(test_tenant["id"])

    assert len(result) == 2
    # Check that results include user details
    user_ids = [r["user_id"] for r in result]
    assert test_user["id"] in user_ids
    assert test_admin_user["id"] in user_ids


def test_list_pending_requests_excludes_decided(test_tenant, test_user, test_admin_user):
    """Test that decided requests are not included in pending list."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    # Approve the request
    database.reactivation.approve_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    result = database.reactivation.list_pending_requests(test_tenant["id"])

    assert len(result) == 0


# =============================================================================
# approve_request Tests
# =============================================================================


def test_approve_request(test_tenant, test_user, test_admin_user):
    """Test approving a request."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    rows_affected = database.reactivation.approve_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    assert rows_affected == 1

    # Verify the update
    updated = database.reactivation.get_request_by_id(test_tenant["id"], str(request["id"]))
    assert updated["decision"] == "approved"
    assert updated["decided_by"] == test_admin_user["id"]
    assert updated["decided_at"] is not None


def test_approve_request_already_decided(test_tenant, test_user, test_admin_user):
    """Test that approving an already decided request does nothing."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    # Approve once
    database.reactivation.approve_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    # Try to approve again
    rows_affected = database.reactivation.approve_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    # Should not update anything because decision is already set
    assert rows_affected == 0


# =============================================================================
# deny_request Tests
# =============================================================================


def test_deny_request(test_tenant, test_user, test_admin_user):
    """Test denying a request."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    rows_affected = database.reactivation.deny_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    assert rows_affected == 1

    # Verify the update
    updated = database.reactivation.get_request_by_id(test_tenant["id"], str(request["id"]))
    assert updated["decision"] == "denied"
    assert updated["decided_by"] == test_admin_user["id"]


def test_deny_request_already_decided(test_tenant, test_user, test_admin_user):
    """Test that denying an already decided request does nothing."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    # Deny once
    database.reactivation.deny_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    # Try to deny again
    rows_affected = database.reactivation.deny_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    assert rows_affected == 0


# =============================================================================
# delete_request Tests
# =============================================================================


def test_delete_request(test_tenant, test_user):
    """Test deleting a request."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    rows_affected = database.reactivation.delete_request(test_tenant["id"], str(request["id"]))

    assert rows_affected == 1

    # Verify deletion
    result = database.reactivation.get_request_by_id(test_tenant["id"], str(request["id"]))
    assert result is None


def test_delete_request_not_exists(test_tenant):
    """Test deleting a nonexistent request."""
    import database

    rows_affected = database.reactivation.delete_request(test_tenant["id"], str(uuid4()))

    assert rows_affected == 0


# =============================================================================
# count_pending_requests Tests
# =============================================================================


def test_count_pending_requests_zero(test_tenant):
    """Test counting pending requests when none exist."""
    import database

    count = database.reactivation.count_pending_requests(test_tenant["id"])

    assert count == 0


def test_count_pending_requests_multiple(test_tenant, test_user, test_admin_user):
    """Test counting pending requests with multiple."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])
    _inactivate_user(test_tenant["id"], test_admin_user["id"])

    database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )
    database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_admin_user["id"]),
    )

    count = database.reactivation.count_pending_requests(test_tenant["id"])

    assert count == 2


def test_count_pending_requests_excludes_decided(test_tenant, test_user, test_admin_user):
    """Test that count excludes decided requests."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    database.reactivation.approve_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    count = database.reactivation.count_pending_requests(test_tenant["id"])

    assert count == 0


# =============================================================================
# list_decided_requests Tests
# =============================================================================


def test_list_decided_requests_empty(test_tenant):
    """Test listing decided requests when none exist."""
    import database

    result = database.reactivation.list_decided_requests(test_tenant["id"])

    assert result == []


def test_list_decided_requests_approved(test_tenant, test_user, test_admin_user):
    """Test listing decided requests with an approved one."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    database.reactivation.approve_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    result = database.reactivation.list_decided_requests(test_tenant["id"])

    assert len(result) == 1
    assert result[0]["decision"] == "approved"
    assert result[0]["decided_by_first_name"] == "Admin"
    assert result[0]["decided_by_last_name"] == "User"


def test_list_decided_requests_denied(test_tenant, test_user, test_admin_user):
    """Test listing decided requests with a denied one."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    request = database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    database.reactivation.deny_request(
        test_tenant["id"], str(request["id"]), str(test_admin_user["id"])
    )

    result = database.reactivation.list_decided_requests(test_tenant["id"])

    assert len(result) == 1
    assert result[0]["decision"] == "denied"


def test_list_decided_requests_excludes_pending(test_tenant, test_user):
    """Test that pending requests are not in decided list."""
    import database

    _inactivate_user(test_tenant["id"], test_user["id"])

    database.reactivation.create_request(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        user_id=str(test_user["id"]),
    )

    result = database.reactivation.list_decided_requests(test_tenant["id"])

    assert len(result) == 0
