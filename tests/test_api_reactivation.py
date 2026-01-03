"""Tests for reactivation request API endpoints."""

from unittest.mock import patch
from uuid import uuid4


def _inactivate_user(tenant_id: str, user_id: str) -> None:
    """Helper to inactivate a user directly in the database."""
    import database

    database.users.inactivate_user(tenant_id, user_id)


# =============================================================================
# GET /api/v1/reactivation-requests (list pending)
# =============================================================================


def test_list_pending_requests_as_admin(
    client,
    test_tenant,
    test_tenant_host,
    test_admin_user,
    test_user,
    normal_oauth2_client,
    oauth2_admin_authorization_header,
):
    """Test listing pending requests as an admin."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    response = client.get(
        "/api/v1/reactivation-requests",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["user_id"] == str(test_user["id"])
    assert data[0]["first_name"] == "Test"
    assert data[0]["last_name"] == "User"


def test_list_pending_requests_as_member_forbidden(
    client,
    test_tenant,
    test_tenant_host,
    oauth2_authorization_header,
):
    """Test that members cannot list pending requests."""
    response = client.get(
        "/api/v1/reactivation-requests",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 403


def test_list_pending_requests_unauthenticated(
    client,
    test_tenant_host,
):
    """Test that unauthenticated users cannot list pending requests."""
    response = client.get(
        "/api/v1/reactivation-requests",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


def test_list_pending_requests_empty(
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
):
    """Test listing pending requests when none exist."""
    response = client.get(
        "/api/v1/reactivation-requests",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    assert response.json() == []


# =============================================================================
# GET /api/v1/reactivation-requests/history (list decided)
# =============================================================================


def test_list_history_as_admin(
    client,
    test_tenant,
    test_tenant_host,
    test_admin_user,
    test_user,
    oauth2_admin_authorization_header,
):
    """Test listing request history as an admin."""
    from services import reactivation as reactivation_service
    from services.types import RequestingUser

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    # Approve the request
    requesting_user = RequestingUser(
        id=str(test_admin_user["id"]),
        tenant_id=test_tenant["id"],
        role="admin",
    )
    reactivation_service.approve_request(requesting_user, request.id)

    response = client.get(
        "/api/v1/reactivation-requests/history",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["decision"] == "approved"


def test_list_history_as_member_forbidden(
    client,
    test_tenant_host,
    oauth2_authorization_header,
):
    """Test that members cannot list request history."""
    response = client.get(
        "/api/v1/reactivation-requests/history",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 403


# =============================================================================
# POST /api/v1/reactivation-requests/{id}/approve
# =============================================================================


def test_approve_request_as_admin(
    client,
    test_tenant,
    test_tenant_host,
    test_user,
    oauth2_admin_authorization_header,
):
    """Test approving a request as an admin."""
    import database
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    with patch("routers.api.v1.reactivation.send_account_reactivated_notification"):
        response = client.post(
            f"/api/v1/reactivation-requests/{request.id}/approve",
            headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "approved"

    # Verify user is reactivated
    user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    assert user["is_inactivated"] is False


def test_approve_request_sends_email(
    client,
    test_tenant,
    test_tenant_host,
    test_user,
    oauth2_admin_authorization_header,
):
    """Test that approving a request sends email notification."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    with patch("routers.api.v1.reactivation.send_account_reactivated_notification") as mock_send:
        response = client.post(
            f"/api/v1/reactivation-requests/{request.id}/approve",
            headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        )

    assert response.status_code == 200
    mock_send.assert_called_once()
    # First arg is the email
    assert mock_send.call_args[0][0] == test_user["email"]


def test_approve_request_as_member_forbidden(
    client,
    test_tenant_host,
    oauth2_authorization_header,
):
    """Test that members cannot approve requests."""
    response = client.post(
        f"/api/v1/reactivation-requests/{uuid4()}/approve",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 403


def test_approve_request_not_found(
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
):
    """Test approving a nonexistent request returns 404."""
    response = client.post(
        f"/api/v1/reactivation-requests/{uuid4()}/approve",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 404


def test_approve_request_already_decided(
    client,
    test_tenant,
    test_tenant_host,
    test_admin_user,
    test_user,
    oauth2_admin_authorization_header,
):
    """Test that approving an already decided request fails."""
    from services import reactivation as reactivation_service
    from services.types import RequestingUser

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    # Approve first
    requesting_user = RequestingUser(
        id=str(test_admin_user["id"]),
        tenant_id=test_tenant["id"],
        role="admin",
    )
    reactivation_service.approve_request(requesting_user, request.id)

    # Try to approve again via API
    response = client.post(
        f"/api/v1/reactivation-requests/{request.id}/approve",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 400
    assert "already been decided" in response.json()["detail"]


# =============================================================================
# POST /api/v1/reactivation-requests/{id}/deny
# =============================================================================


def test_deny_request_as_admin(
    client,
    test_tenant,
    test_tenant_host,
    test_user,
    oauth2_admin_authorization_header,
):
    """Test denying a request as an admin."""
    import database
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    with patch("routers.api.v1.reactivation.send_reactivation_denied_notification"):
        response = client.post(
            f"/api/v1/reactivation-requests/{request.id}/deny",
            headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "denied"

    # Verify user is still inactivated and marked as denied
    user = database.users.get_user_by_id(test_tenant["id"], test_user["id"])
    assert user["is_inactivated"] is True
    assert user["reactivation_denied_at"] is not None


def test_deny_request_sends_email(
    client,
    test_tenant,
    test_tenant_host,
    test_user,
    oauth2_admin_authorization_header,
):
    """Test that denying a request sends email notification."""
    from services import reactivation as reactivation_service

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    with patch("routers.api.v1.reactivation.send_reactivation_denied_notification") as mock_send:
        response = client.post(
            f"/api/v1/reactivation-requests/{request.id}/deny",
            headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        )

    assert response.status_code == 200
    mock_send.assert_called_once_with(test_user["email"])


def test_deny_request_as_member_forbidden(
    client,
    test_tenant_host,
    oauth2_authorization_header,
):
    """Test that members cannot deny requests."""
    response = client.post(
        f"/api/v1/reactivation-requests/{uuid4()}/deny",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 403


def test_deny_request_not_found(
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
):
    """Test denying a nonexistent request returns 404."""
    response = client.post(
        f"/api/v1/reactivation-requests/{uuid4()}/deny",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 404


def test_deny_request_already_decided(
    client,
    test_tenant,
    test_tenant_host,
    test_admin_user,
    test_user,
    oauth2_admin_authorization_header,
):
    """Test that denying an already decided request fails."""
    from services import reactivation as reactivation_service
    from services.types import RequestingUser

    _inactivate_user(test_tenant["id"], test_user["id"])
    request = reactivation_service.create_request(test_tenant["id"], str(test_user["id"]))

    # Deny first
    requesting_user = RequestingUser(
        id=str(test_admin_user["id"]),
        tenant_id=test_tenant["id"],
        role="admin",
    )
    reactivation_service.deny_request(requesting_user, request.id)

    # Try to deny again via API
    with patch("routers.api.v1.reactivation.send_reactivation_denied_notification"):
        response = client.post(
            f"/api/v1/reactivation-requests/{request.id}/deny",
            headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        )

    assert response.status_code == 400
    assert "already been decided" in response.json()["detail"]


# =============================================================================
# Tenant Isolation Tests
# =============================================================================


def test_cannot_access_other_tenant_requests(
    client,
    test_tenant,
    test_tenant_host,
    test_user,
    oauth2_admin_authorization_header,
):
    """Test that admin from one tenant cannot access another tenant's requests."""
    import database

    # Create another tenant with a request
    other_tenant = database.fetchone(
        database.UNSCOPED,
        """
        INSERT INTO tenants (subdomain, name)
        VALUES (:subdomain, :name)
        RETURNING id, subdomain, name
        """,
        {"subdomain": f"other-{uuid4()}", "name": "Other Tenant"},
    )

    try:
        # Create a user and request in the other tenant
        other_user = database.fetchone(
            other_tenant["id"],
            """
            INSERT INTO users (tenant_id, first_name, last_name, role)
            VALUES (:tenant_id, 'Other', 'User', 'member')
            RETURNING id
            """,
            {"tenant_id": other_tenant["id"]},
        )

        _inactivate_user(other_tenant["id"], other_user["id"])

        other_request = database.reactivation.create_request(
            tenant_id=other_tenant["id"],
            tenant_id_value=other_tenant["id"],
            user_id=str(other_user["id"]),
        )

        # Try to approve from our tenant - should not find it
        response = client.post(
            f"/api/v1/reactivation-requests/{other_request['id']}/approve",
            headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        )

        # Should be 404 because the request doesn't exist in our tenant
        assert response.status_code == 404

    finally:
        # Cleanup
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :tenant_id",
            {"tenant_id": other_tenant["id"]},
        )
