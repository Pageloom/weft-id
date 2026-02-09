"""Tests for API endpoints."""


def test_root_endpoint_with_valid_tenant(client, test_tenant_host):
    """Test root endpoint with a valid tenant hostname redirects to login."""
    response = client.get("/", headers={"host": test_tenant_host}, follow_redirects=False)

    # Root endpoint redirects to /login when not authenticated
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_root_endpoint_with_invalid_host(client):
    """Test root endpoint with an invalid hostname."""
    response = client.get("/", headers={"host": "invalid.example.com"})

    assert response.status_code == 404
    assert "Unknown host" in response.json()["detail"]


def test_root_endpoint_without_host(client):
    """Test root endpoint without host header."""
    response = client.get("/")

    # Should fail due to missing/invalid host
    assert response.status_code == 404


def test_tenant_root_redirect_to_login_when_not_authenticated(test_tenant):
    """Test that unauthenticated users are redirected to /login."""

    from dependencies import get_current_user, get_tenant_id_from_request
    from fastapi.testclient import TestClient
    from main import app

    # Override dependencies
    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]
    app.dependency_overrides[get_current_user] = lambda: None

    client = TestClient(app)
    response = client.get("/", follow_redirects=False)

    # Cleanup
    app.dependency_overrides.clear()

    # Should redirect to login
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_tenant_root_redirect_to_dashboard_when_authenticated(test_user):
    """Test that authenticated users are redirected to /dashboard."""
    from unittest.mock import patch

    from dependencies import get_tenant_id_from_request
    from fastapi.testclient import TestClient
    from main import app

    # Override tenant ID dependency
    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]

    # Patch get_current_user since it's called directly in the route
    with patch("routers.tenants.get_current_user") as mock_user:
        mock_user.return_value = test_user

        client = TestClient(app)
        response = client.get("/", follow_redirects=False)

    # Cleanup
    app.dependency_overrides.clear()

    # Should redirect to dashboard
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
