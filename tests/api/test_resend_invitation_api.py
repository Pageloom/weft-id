"""Tests for resend invitation API endpoint."""

from unittest.mock import patch
from uuid import uuid4

from main import app
from services.exceptions import NotFoundError, ValidationError
from starlette.testclient import TestClient


def test_resend_invitation_api_set_password(make_user_dict, override_api_auth):
    """Test API resend invitation with set-password flow."""
    admin = make_user_dict(role="admin")
    target_id = str(uuid4())
    email_id = str(uuid4())

    override_api_auth(admin)

    with (
        patch("routers.api.v1.users.users_service") as mock_svc,
        patch("routers.api.v1.users.send_new_user_privileged_domain_notification") as mock_send,
    ):
        mock_svc.resend_invitation.return_value = {
            "email_id": email_id,
            "email": "user@example.com",
            "nonce": 2,
            "invitation_type": "set_password",
            "first_name": "Test",
            "last_name": "User",
        }
        mock_svc.get_tenant_name.return_value = "Test Org"

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{target_id}/resend-invitation")

        assert response.status_code == 204
        mock_svc.resend_invitation.assert_called_once()
        mock_send.assert_called_once()
        # Verify set-password URL is constructed correctly
        call_args = mock_send.call_args
        url = call_args[0][3]
        assert f"email_id={email_id}" in url
        assert "nonce=2" in url


def test_resend_invitation_api_verify_flow(make_user_dict, override_api_auth):
    """Test API resend invitation with verification flow."""
    admin = make_user_dict(role="admin")
    target_id = str(uuid4())
    email_id = str(uuid4())

    override_api_auth(admin)

    with (
        patch("routers.api.v1.users.users_service") as mock_svc,
        patch("routers.api.v1.users.send_new_user_invitation") as mock_send,
    ):
        mock_svc.resend_invitation.return_value = {
            "email_id": email_id,
            "email": "user@example.com",
            "nonce": 3,
            "invitation_type": "verify",
            "first_name": "Test",
            "last_name": "User",
        }
        mock_svc.get_tenant_name.return_value = "Test Org"

        client = TestClient(app)
        response = client.post(f"/api/v1/users/{target_id}/resend-invitation")

        assert response.status_code == 204
        mock_send.assert_called_once()
        # Verify verification URL is constructed correctly
        call_args = mock_send.call_args
        url = call_args[0][3]
        assert f"verify-email/{email_id}/3" in url


def test_resend_invitation_api_already_onboarded(make_user_dict, override_api_auth):
    """Test API returns 400 when user already has a password."""
    admin = make_user_dict(role="admin")
    target_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.resend_invitation.side_effect = ValidationError(
            message="Already onboarded", code="already_onboarded"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{target_id}/resend-invitation")

        assert response.status_code == 400


def test_resend_invitation_api_not_found(make_user_dict, override_api_auth):
    """Test API returns 404 when user not found."""
    admin = make_user_dict(role="admin")

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.resend_invitation.side_effect = NotFoundError(
            message="User not found", code="user_not_found"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{uuid4()}/resend-invitation")

        assert response.status_code == 404


def test_resend_invitation_api_inactivated(make_user_dict, override_api_auth):
    """Test API returns 400 when user is inactivated."""
    admin = make_user_dict(role="admin")
    target_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.users_service") as mock_svc:
        mock_svc.resend_invitation.side_effect = ValidationError(
            message="Cannot resend to inactivated user", code="user_inactivated"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{target_id}/resend-invitation")

        assert response.status_code == 400
