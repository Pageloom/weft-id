"""Tests for password API endpoints."""

from uuid import uuid4

from services.exceptions import NotFoundError, RateLimitError, ValidationError


def test_change_password_api_success(test_user, override_api_auth, mocker):
    """Test PUT /api/v1/users/me/password succeeds."""
    from fastapi.testclient import TestClient
    from main import app

    override_api_auth(test_user, level="user")

    mock_change = mocker.patch("routers.api.v1.users.users_service.change_password")

    client = TestClient(app)
    response = client.put(
        "/api/v1/users/me/password",
        json={
            "current_password": "old_password",
            "new_password": "new_strong_password!",
        },
    )

    assert response.status_code == 204
    mock_change.assert_called_once()


def test_change_password_api_wrong_current(test_user, override_api_auth, mocker):
    """Test PUT /api/v1/users/me/password with wrong current password."""
    from fastapi.testclient import TestClient
    from main import app

    override_api_auth(test_user, level="user")

    mocker.patch(
        "routers.api.v1.users.users_service.change_password",
        side_effect=ValidationError(message="Wrong password", code="invalid_current_password"),
    )

    client = TestClient(app)
    response = client.put(
        "/api/v1/users/me/password",
        json={
            "current_password": "wrong",
            "new_password": "new_strong_password!",
        },
    )

    assert response.status_code == 400


def test_force_password_reset_api_success(test_user, override_api_auth, mocker):
    """Test POST /api/v1/users/{id}/force-password-reset succeeds for admin."""
    from fastapi.testclient import TestClient
    from main import app

    test_user["role"] = "admin"
    override_api_auth(test_user, level="admin")

    mock_force = mocker.patch("routers.api.v1.users.users_service.force_password_reset")

    target_id = str(uuid4())
    client = TestClient(app)
    response = client.post(f"/api/v1/users/{target_id}/force-password-reset")

    assert response.status_code == 204
    mock_force.assert_called_once()


def test_force_password_reset_api_not_found(test_user, override_api_auth, mocker):
    """Test POST /api/v1/users/{id}/force-password-reset returns 404."""
    from fastapi.testclient import TestClient
    from main import app

    test_user["role"] = "admin"
    override_api_auth(test_user, level="admin")

    mocker.patch(
        "routers.api.v1.users.users_service.force_password_reset",
        side_effect=NotFoundError(message="User not found", code="user_not_found"),
    )

    client = TestClient(app)
    response = client.post(f"/api/v1/users/{uuid4()}/force-password-reset")

    assert response.status_code == 404


def test_change_password_api_rate_limited(test_user, override_api_auth, mocker):
    """Test PUT /api/v1/users/me/password returns 429 when rate limited."""
    from fastapi.testclient import TestClient
    from main import app

    override_api_auth(test_user, level="user")

    mocker.patch(
        "routers.api.v1.users.password.ratelimit.prevent",
        side_effect=RateLimitError(
            message="Too many requests", code="rate_limit_exceeded", retry_after=3600
        ),
    )

    client = TestClient(app)
    response = client.put(
        "/api/v1/users/me/password",
        json={
            "current_password": "old_password",
            "new_password": "new_strong_password!",
        },
    )

    assert response.status_code == 429
