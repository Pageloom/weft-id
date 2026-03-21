"""Tests for account password change routes."""

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app
from services.exceptions import RateLimitError, ValidationError


def test_password_page_renders(test_user, override_auth, mocker):
    """Test password settings page renders for password-authenticated users."""
    override_auth(test_user)

    mocker.patch(
        "services.settings.get_password_policy",
        return_value={"minimum_password_length": 14, "minimum_zxcvbn_score": 3},
    )
    mock_template = mocker.patch("routers.account.templates.TemplateResponse")
    mock_template.return_value = HTMLResponse(content="<html>Password</html>")

    client = TestClient(app)
    response = client.get("/account/password")

    assert response.status_code == 200
    mock_template.assert_called_once()
    _, template_name, context = mock_template.call_args[0]
    assert template_name == "settings_password.html"
    assert context["minimum_password_length"] == 14


def test_password_page_redirects_idp_user(test_user, override_auth, mocker):
    """Test password page redirects IdP-federated users to profile."""
    # Simulate IdP user
    test_user["saml_idp_id"] = "some-idp-id"
    override_auth(test_user)

    client = TestClient(app)
    response = client.get("/account/password", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/account/profile"


def test_change_password_success(test_user, override_auth, mocker):
    """Test successful password change."""
    override_auth(test_user)

    mock_change = mocker.patch("services.users.change_password")

    client = TestClient(app)
    response = client.post(
        "/account/password",
        data={
            "current_password": "old_password",
            "new_password": "new_strong_password!",
            "new_password_confirm": "new_strong_password!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=password_changed" in response.headers["location"]
    mock_change.assert_called_once()


def test_change_password_mismatch(test_user, override_auth, mocker):
    """Test password change with mismatched confirmation."""
    override_auth(test_user)

    client = TestClient(app)
    response = client.post(
        "/account/password",
        data={
            "current_password": "old_password",
            "new_password": "new_password_1",
            "new_password_confirm": "new_password_2",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=passwords_dont_match" in response.headers["location"]


def test_change_password_validation_error(test_user, override_auth, mocker):
    """Test password change with service validation error."""
    override_auth(test_user)

    mocker.patch(
        "services.users.change_password",
        side_effect=ValidationError(message="Wrong password", code="invalid_current_password"),
    )

    client = TestClient(app)
    response = client.post(
        "/account/password",
        data={
            "current_password": "wrong",
            "new_password": "new_password_123!",
            "new_password_confirm": "new_password_123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=invalid_current_password" in response.headers["location"]


def test_change_password_rate_limited(test_user, override_auth, mocker):
    """Test password change returns error when rate limited."""
    override_auth(test_user)

    mocker.patch(
        "routers.account.ratelimit.prevent",
        side_effect=RateLimitError(
            message="Too many requests", code="rate_limit_exceeded", retry_after=3600
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/account/password",
        data={
            "current_password": "old_password",
            "new_password": "new_password_123!",
            "new_password_confirm": "new_password_123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=too_many_attempts" in response.headers["location"]


def test_change_password_rate_limit_skips_service(test_user, override_auth, mocker):
    """Test that rate limited requests don't call the service."""
    override_auth(test_user)

    mocker.patch(
        "routers.account.ratelimit.prevent",
        side_effect=RateLimitError(
            message="Too many requests", code="rate_limit_exceeded", retry_after=3600
        ),
    )
    mock_change = mocker.patch("services.users.change_password")

    client = TestClient(app)
    client.post(
        "/account/password",
        data={
            "current_password": "old_password",
            "new_password": "new_password_123!",
            "new_password_confirm": "new_password_123!",
        },
        follow_redirects=False,
    )

    mock_change.assert_not_called()
