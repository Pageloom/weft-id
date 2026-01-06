"""Tests for Event Log API endpoints."""

from uuid import uuid4

# =============================================================================
# List Events
# =============================================================================


def test_list_events_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Admin can list events."""
    response = client.get(
        "/api/v1/events",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()

    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "limit" in data
    assert data["page"] == 1
    assert data["limit"] == 50  # Default limit


def test_list_events_with_pagination(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test listing events with custom pagination parameters."""
    response = client.get(
        "/api/v1/events?page=1&limit=10",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["page"] == 1
    assert data["limit"] == 10


def test_list_events_page_validation(client, test_tenant_host, oauth2_admin_authorization_header):
    """Page number must be at least 1."""
    response = client.get(
        "/api/v1/events?page=0",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 422  # Validation error


def test_list_events_limit_validation_too_low(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Limit must be at least 1."""
    response = client.get(
        "/api/v1/events?limit=0",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 422  # Validation error


def test_list_events_limit_validation_too_high(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Limit must be at most 100."""
    response = client.get(
        "/api/v1/events?limit=101",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 422  # Validation error


def test_list_events_unauthorized_member(client, test_tenant_host, oauth2_authorization_header):
    """Regular member cannot list events."""
    response = client.get(
        "/api/v1/events",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_list_events_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    response = client.get(
        "/api/v1/events",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


# =============================================================================
# Get Event
# =============================================================================


def test_get_event_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Getting non-existent event returns 404."""
    fake_event_id = str(uuid4())
    response = client.get(
        f"/api/v1/events/{fake_event_id}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404


def test_get_event_unauthorized_member(client, test_tenant_host, oauth2_authorization_header):
    """Regular member cannot get event details."""
    fake_event_id = str(uuid4())
    response = client.get(
        f"/api/v1/events/{fake_event_id}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_get_event_no_auth(client, test_tenant_host):
    """Unauthenticated request is rejected."""
    fake_event_id = str(uuid4())
    response = client.get(
        f"/api/v1/events/{fake_event_id}",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401
