"""Tests for admin force password reset route."""

from uuid import uuid4

from fastapi.testclient import TestClient
from main import app
from services.exceptions import NotFoundError, ValidationError


def test_force_password_reset_success(test_user, override_auth, mocker):
    """Test admin can force password reset on another user."""
    test_user["role"] = "admin"
    override_auth(test_user)

    mock_force = mocker.patch("services.users.force_password_reset")
    target_id = str(uuid4())

    client = TestClient(app)
    response = client.post(
        f"/users/{target_id}/force-password-reset",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=password_reset_forced" in response.headers["location"]
    mock_force.assert_called_once()


def test_force_password_reset_not_found(test_user, override_auth, mocker):
    """Test force reset returns error when user not found."""
    test_user["role"] = "admin"
    override_auth(test_user)

    mocker.patch(
        "services.users.force_password_reset",
        side_effect=NotFoundError("user_not_found", "User not found"),
    )

    client = TestClient(app)
    response = client.post(
        f"/users/{uuid4()}/force-password-reset",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=user_not_found" in response.headers["location"]


def test_force_password_reset_validation_error(test_user, override_auth, mocker):
    """Test force reset returns error on validation failure."""
    test_user["role"] = "admin"
    override_auth(test_user)

    mocker.patch(
        "services.users.force_password_reset",
        side_effect=ValidationError(message="No password", code="no_password"),
    )

    target_id = str(uuid4())
    client = TestClient(app)
    response = client.post(
        f"/users/{target_id}/force-password-reset",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/users/{target_id}/danger?error=no_password" in response.headers["location"]


def test_force_password_reset_member_denied(test_user, override_auth, mocker):
    """Test member cannot access force reset route."""
    test_user["role"] = "member"
    override_auth(test_user)

    client = TestClient(app)
    response = client.post(
        f"/users/{uuid4()}/force-password-reset",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
