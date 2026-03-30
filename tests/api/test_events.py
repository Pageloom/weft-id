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


def test_list_events_with_tiers_filter(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test listing events with tier filter."""
    response = client.get(
        "/api/v1/events?tiers=security,admin",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


def test_list_events_with_single_tier(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test listing events with a single tier filter."""
    response = client.get(
        "/api/v1/events?tiers=security",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()

    # All returned events should have security tier
    for item in data["items"]:
        assert item["event_tier"] == "security"


def test_list_events_with_invalid_tiers_ignored(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that invalid tier values are silently ignored."""
    response = client.get(
        "/api/v1/events?tiers=invalid,nonsense",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    # Invalid tiers result in None (no filtering), so all events returned
    assert response.status_code == 200


def test_list_events_without_tiers_returns_all(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that omitting tiers returns all events (no filtering)."""
    response = client.get(
        "/api/v1/events",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()

    # Events should include event_tier field
    for item in data["items"]:
        assert "event_tier" in item


def test_list_events_response_includes_event_tier(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that the event_tier field is included in the API response."""
    response = client.get(
        "/api/v1/events?limit=5",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        # event_tier should be one of the valid tiers or None
        assert item["event_tier"] in ("security", "admin", "operational", "system", None)


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
