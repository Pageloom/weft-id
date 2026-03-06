"""Tests for routers/mfa.py endpoints - redirect behavior tests.

Note: E2E tests for actual MFA verification are in test_mfa_e2e.py.
These tests verify redirect behavior when there's no pending MFA session.
"""

from fastapi.testclient import TestClient
from main import app


def test_mfa_verify_page_no_pending_session(test_tenant):
    """Test MFA verify page redirects without pending MFA session."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.get("/mfa/verify", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_mfa_verify_post_no_pending_session(test_tenant):
    """Test MFA verify POST redirects without pending session."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post("/mfa/verify", data={"code": "123456"}, follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_mfa_send_email_code_no_pending_session(test_tenant):
    """Test send email code redirects without pending session."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post("/mfa/verify/send-email", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# =============================================================================
# MFA Verify Page with Pending Session
# =============================================================================


def test_mfa_verify_page_with_pending_session(test_tenant, mocker):
    """Test MFA verify page renders when there is a pending session."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {
        "pending_mfa_user_id": user_id,
        "pending_mfa_method": "totp",
    }

    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mock_get_user = mocker.patch("routers.mfa.emails_service.get_user_with_primary_email")
    mock_get_user.return_value = {"id": user_id, "email": "user@example.com"}

    mock_template = mocker.patch("routers.mfa.templates.TemplateResponse")
    mock_template.return_value = HTMLResponse(content="<html>MFA</html>")

    client = TestClient(app)
    response = client.get("/mfa/verify")

    assert response.status_code == 200
    mock_template.assert_called_once()
    # Verify template name
    assert mock_template.call_args[0][1] == "mfa_verify.html"


def test_mfa_verify_rate_limit(test_tenant, mocker):
    """Test MFA verify POST returns error page on rate limit."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse
    from services.exceptions import RateLimitError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {
        "pending_mfa_user_id": user_id,
        "pending_mfa_method": "totp",
    }

    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.mfa.ratelimit.prevent",
        side_effect=RateLimitError(message="Too many attempts"),
    )

    mock_get_user = mocker.patch("routers.mfa.emails_service.get_user_with_primary_email")
    mock_get_user.return_value = {"id": user_id, "email": "user@example.com"}

    mock_template = mocker.patch("routers.mfa.templates.TemplateResponse")
    mock_template.return_value = HTMLResponse(content="<html>Rate limited</html>")

    client = TestClient(app)
    response = client.post("/mfa/verify", data={"code": "123456"})

    assert response.status_code == 200
    mock_template.assert_called_once()
    # Verify error message in context
    context = mock_template.call_args[0][2]
    assert "Too many attempts" in context["error"]


def test_mfa_send_email_code_rate_limit(test_tenant, mocker):
    """Test send email code redirects on rate limit."""
    from dependencies import get_tenant_id_from_request
    from services.exceptions import RateLimitError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {
        "pending_mfa_user_id": user_id,
        "pending_mfa_method": "email",
    }

    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.mfa.ratelimit.prevent",
        side_effect=RateLimitError(message="Too many attempts"),
    )

    client = TestClient(app)
    response = client.post("/mfa/verify/send-email", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify?error=too_many_requests"


def test_mfa_send_email_code_totp_user_redirects(test_tenant, mocker):
    """Test TOTP users are redirected when requesting email code."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    session_data = {
        "pending_mfa_user_id": "test-user-id",
        "pending_mfa_method": "totp",
    }

    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    client = TestClient(app)
    response = client.post("/mfa/verify/send-email", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify"


def test_mfa_send_email_code_success(test_tenant, mocker):
    """Test send email code generates OTP and sends email."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {
        "pending_mfa_user_id": user_id,
        "pending_mfa_method": "email",
    }

    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch("routers.mfa.ratelimit.prevent")  # no rate limit
    mock_create = mocker.patch("routers.mfa.create_email_otp", return_value="123456")
    mock_get_email = mocker.patch(
        "routers.mfa.emails_service.get_primary_email",
        return_value="user@example.com",
    )
    mock_send = mocker.patch("routers.mfa.send_mfa_code_email")

    client = TestClient(app)
    response = client.post("/mfa/verify/send-email", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify?email_sent=1"
    mock_create.assert_called_once_with(test_tenant["id"], user_id)
    mock_get_email.assert_called_once()
    mock_send.assert_called_once_with("user@example.com", "123456")


def test_mfa_verify_invalid_code(test_tenant, mocker):
    """Test MFA verify with invalid code shows error."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {
        "pending_mfa_user_id": user_id,
        "pending_mfa_method": "totp",
    }

    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch("routers.mfa.ratelimit.prevent")
    mocker.patch("routers.mfa.get_totp_secret", return_value="secret")
    mocker.patch("routers.mfa.verify_totp_code", return_value=False)
    mocker.patch("routers.mfa.verify_email_otp", return_value=False)
    mocker.patch("routers.mfa.verify_backup_code", return_value=False)
    mock_get_user = mocker.patch("routers.mfa.emails_service.get_user_with_primary_email")
    mock_get_user.return_value = {"id": user_id, "email": "user@example.com"}

    mock_template = mocker.patch("routers.mfa.templates.TemplateResponse")
    mock_template.return_value = HTMLResponse(content="<html>Invalid</html>")

    client = TestClient(app)
    response = client.post("/mfa/verify", data={"code": "000000"})

    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["error"] == "Invalid or expired code"


def test_mfa_verify_success(test_tenant, mocker):
    """Test successful MFA verification completes login."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {
        "pending_mfa_user_id": user_id,
        "pending_mfa_method": "totp",
    }

    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch("routers.mfa.ratelimit.prevent")
    mocker.patch("routers.mfa.get_totp_secret", return_value="secret")
    mocker.patch("routers.mfa.verify_totp_code", return_value=True)
    mocker.patch("services.event_log.log_event")
    mocker.patch("routers.mfa.settings_service.get_session_settings", return_value=None)
    mocker.patch("routers.mfa.regenerate_session")
    mocker.patch(
        "routers.mfa.users_service.get_user_by_id_raw",
        return_value={"tz": None, "locale": None},
    )
    mocker.patch("routers.mfa.users_service.update_last_login")

    # Mock the saml_idp helpers
    mocker.patch("routers.saml_idp._helpers.extract_pending_sso", return_value=None)
    mocker.patch("routers.saml_idp._helpers.get_post_auth_redirect", return_value="/dashboard")

    client = TestClient(app)
    response = client.post(
        "/mfa/verify",
        data={"code": "123456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
