"""Tests for resend invitation web route."""

from uuid import uuid4

from fastapi.testclient import TestClient
from main import app
from services.exceptions import NotFoundError, ValidationError


def test_resend_invitation_success(test_user, override_auth, mocker):
    """Test admin can resend invitation to a user."""
    test_user["role"] = "admin"
    override_auth(test_user)

    target_id = str(uuid4())
    mock_resend = mocker.patch(
        "services.users.resend_invitation",
        return_value={
            "email_id": str(uuid4()),
            "email": "user@example.com",
            "nonce": 2,
            "invitation_type": "set_password",
            "first_name": "Test",
            "last_name": "User",
        },
    )
    mocker.patch("services.users.get_tenant_name", return_value="Test Org")
    mock_send = mocker.patch("routers.users.detail.send_new_user_privileged_domain_notification")

    client = TestClient(app)
    response = client.post(
        f"/users/{target_id}/resend-invitation",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=invitation_resent" in response.headers["location"]
    mock_resend.assert_called_once()
    mock_send.assert_called_once()


def test_resend_invitation_verify_flow(test_user, override_auth, mocker):
    """Test resend invitation sends verification email for unverified emails."""
    test_user["role"] = "admin"
    override_auth(test_user)

    target_id = str(uuid4())
    email_id = str(uuid4())
    mocker.patch(
        "services.users.resend_invitation",
        return_value={
            "email_id": email_id,
            "email": "user@example.com",
            "nonce": 3,
            "invitation_type": "verify",
            "first_name": "Test",
            "last_name": "User",
        },
    )
    mocker.patch("services.users.get_tenant_name", return_value="Test Org")
    mock_send = mocker.patch("routers.users.detail.send_new_user_invitation")

    client = TestClient(app)
    response = client.post(
        f"/users/{target_id}/resend-invitation",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=invitation_resent" in response.headers["location"]
    mock_send.assert_called_once()
    # Check the verification URL contains the email_id and nonce
    call_args = mock_send.call_args
    verification_url = call_args[0][3]
    assert email_id in verification_url
    assert "/3" in verification_url


def test_resend_invitation_not_found(test_user, override_auth, mocker):
    """Test resend returns error when user not found."""
    test_user["role"] = "admin"
    override_auth(test_user)

    mocker.patch(
        "services.users.resend_invitation",
        side_effect=NotFoundError("User not found", "user_not_found"),
    )

    client = TestClient(app)
    response = client.post(
        f"/users/{uuid4()}/resend-invitation",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=user_not_found" in response.headers["location"]


def test_resend_invitation_already_onboarded(test_user, override_auth, mocker):
    """Test resend returns error when user already has a password."""
    test_user["role"] = "admin"
    override_auth(test_user)

    target_id = str(uuid4())
    mocker.patch(
        "services.users.resend_invitation",
        side_effect=ValidationError(message="Already onboarded", code="already_onboarded"),
    )

    client = TestClient(app)
    response = client.post(
        f"/users/{target_id}/resend-invitation",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/users/{target_id}/profile?error=already_onboarded" in response.headers["location"]


def test_resend_invitation_member_denied(test_user, override_auth, mocker):
    """Test member cannot access resend invitation route."""
    test_user["role"] = "member"
    override_auth(test_user)

    client = TestClient(app)
    response = client.post(
        f"/users/{uuid4()}/resend-invitation",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
