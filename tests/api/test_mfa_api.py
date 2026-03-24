"""Tests for MFA API error handlers and email notification path.

Covers the ServiceError except-handlers on each endpoint in
app/routers/api/v1/users/mfa.py, plus the OTP email send on line 119.
"""

from unittest.mock import patch
from uuid import uuid4

from main import app
from schemas.api import MFAEnableResponse
from services.exceptions import ServiceError, ValidationError
from starlette.testclient import TestClient

# =============================================================================
# /me/mfa - GET MFA status
# =============================================================================


def test_get_mfa_status_service_error(make_user_dict, override_api_auth):
    """ServiceError from get_mfa_status is translated to an HTTP error."""
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.get_mfa_status.side_effect = ServiceError(
            message="Unexpected failure", code="internal_error"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/v1/users/me/mfa")

        assert response.status_code == 500
        assert response.json()["detail"] == "Unexpected failure"


# =============================================================================
# /me/mfa/totp/setup - POST TOTP setup
# =============================================================================


def test_setup_totp_service_error(make_user_dict, override_api_auth):
    """ServiceError from setup_totp is translated to an HTTP error."""
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.setup_totp.side_effect = ValidationError(
            message="TOTP already active", code="totp_already_active"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/users/me/mfa/totp/setup")

        assert response.status_code == 400
        assert response.json()["detail"] == "TOTP already active"


# =============================================================================
# /me/mfa/email/enable - POST enable email MFA
# =============================================================================


def test_enable_email_mfa_service_error(make_user_dict, override_api_auth):
    """ServiceError from enable_email_mfa is translated to an HTTP error."""
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.enable_email_mfa.side_effect = ServiceError(
            message="MFA enable failed", code="mfa_error"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/users/me/mfa/email/enable")

        assert response.status_code == 500
        assert response.json()["detail"] == "MFA enable failed"


def test_enable_email_mfa_sends_otp_email(make_user_dict, override_api_auth):
    """When enable_email_mfa returns notification_info, an OTP email is sent."""
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")

    mock_response = MFAEnableResponse(
        status=None,
        pending_verification=True,
        message="Verification code sent to user@example.com",
    )
    notification_info = {"email": "user@example.com", "code": "123456"}

    with (
        patch("routers.api.v1.users.mfa_service") as mock_svc,
        patch("routers.api.v1.users.send_mfa_code_email") as mock_send,
    ):
        mock_svc.enable_email_mfa.return_value = (mock_response, notification_info)

        client = TestClient(app)
        response = client.post("/api/v1/users/me/mfa/email/enable")

        assert response.status_code == 200
        data = response.json()
        assert data["pending_verification"] is True

        mock_send.assert_called_once()
        args, kwargs = mock_send.call_args
        assert args == ("user@example.com", "123456")
        assert "tenant_id" in kwargs


# =============================================================================
# /me/mfa/email/verify-downgrade - POST verify downgrade
# =============================================================================


def test_verify_mfa_downgrade_service_error(make_user_dict, override_api_auth):
    """ServiceError from verify_mfa_downgrade is translated to an HTTP error."""
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.verify_mfa_downgrade.side_effect = ValidationError(
            message="Invalid OTP code", code="invalid_otp"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/users/me/mfa/email/verify-downgrade",
            json={"code": "000000"},
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid OTP code"


# =============================================================================
# /me/mfa/disable - POST disable MFA
# =============================================================================


def test_disable_mfa_service_error(make_user_dict, override_api_auth):
    """ServiceError from disable_mfa is translated to an HTTP error."""
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.disable_mfa.side_effect = ServiceError(
            message="Cannot disable MFA", code="mfa_required"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/v1/users/me/mfa/disable")

        assert response.status_code == 500
        assert response.json()["detail"] == "Cannot disable MFA"


# =============================================================================
# /me/mfa/backup-codes - GET backup codes status
# =============================================================================


def test_get_backup_codes_status_service_error(make_user_dict, override_api_auth):
    """ServiceError from get_backup_codes_status is translated to an HTTP error."""
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.get_backup_codes_status.side_effect = ServiceError(
            message="Failed to retrieve backup codes", code="internal_error"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/v1/users/me/mfa/backup-codes")

        assert response.status_code == 500
        assert response.json()["detail"] == "Failed to retrieve backup codes"


# =============================================================================
# /{user_id}/mfa/reset - POST admin reset (admin endpoint)
# =============================================================================


def test_reset_user_mfa_service_error(make_user_dict, override_api_auth):
    """ServiceError from reset_user_mfa is translated to an HTTP error."""
    admin = make_user_dict(role="admin")
    user_id = str(uuid4())

    override_api_auth(admin)

    with patch("routers.api.v1.users.mfa_service") as mock_svc:
        mock_svc.reset_user_mfa.side_effect = ServiceError(
            message="MFA reset failed", code="reset_error"
        )

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(f"/api/v1/users/{user_id}/mfa/reset")

        assert response.status_code == 500
        assert response.json()["detail"] == "MFA reset failed"
