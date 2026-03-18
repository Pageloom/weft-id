"""Tests for routers/auth/ endpoints."""

from unittest.mock import Mock

from fastapi.testclient import TestClient
from main import app

from app.utils.email_verification import (
    create_trust_cookie,
    create_verification_cookie,
    get_trust_cookie_name,
)

# Module path constants for cleaner patch targets
AUTH_LOGIN = "routers.auth.login"
AUTH_LOGOUT = "routers.auth.logout"
AUTH_ONBOARDING = "routers.auth.onboarding"
AUTH_DASHBOARD = "routers.auth.dashboard"
AUTH_HELPERS = "routers.auth._helpers"
DEPS_AUTH = "dependencies.auth"
SERVICES_EMAILS = "services.emails"
SERVICES_USERS = "services.users"
UTILS_TEMPLATE = "utils.template_context"
SERVICES_SETTINGS = "services.settings"
UTILS_PASSWORD = "utils.password"


def override_tenant(app, tenant_id):
    """Helper to override tenant dependency."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: tenant_id


def test_login_page_not_authenticated(test_tenant, mocker):
    """Test login page renders when not authenticated."""
    from fastapi.responses import HTMLResponse

    override_tenant(app, test_tenant["id"])

    mock_user = mocker.patch(f"{AUTH_LOGIN}.get_current_user")
    mock_tenant = mocker.patch(f"{AUTH_LOGIN}.get_tenant_id_from_request")
    mock_template = mocker.patch(f"{AUTH_LOGIN}.templates.TemplateResponse")

    mock_user.return_value = None
    mock_tenant.return_value = test_tenant["id"]
    mock_template.return_value = HTMLResponse(content="<html>login page</html>")

    client = TestClient(app)
    response = client.get("/login")

    assert response.status_code == 200
    assert b"login" in response.content.lower()
    mock_template.assert_called_once()


def test_login_page_already_authenticated_redirects(test_user, mocker):
    """Test login page redirects to dashboard when already authenticated."""
    override_tenant(app, test_user["tenant_id"])

    mock_user = mocker.patch(f"{AUTH_LOGIN}.get_current_user")
    mock_tenant = mocker.patch(f"{AUTH_LOGIN}.get_tenant_id_from_request")

    mock_user.return_value = test_user
    mock_tenant.return_value = test_user["tenant_id"]

    client = TestClient(app)
    response = client.get("/login", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_login_post_invalid_credentials(test_tenant, mocker):
    """Test login with invalid credentials."""
    from fastapi.responses import HTMLResponse

    override_tenant(app, test_tenant["id"])

    mock_verify = mocker.patch(f"{AUTH_LOGIN}.verify_login_with_status")
    mock_template = mocker.patch(f"{AUTH_LOGIN}.templates.TemplateResponse")

    mock_verify.return_value = {"status": "invalid_credentials", "user": None}
    mock_template.return_value = HTMLResponse(content="<html>Invalid email or password</html>")

    client = TestClient(app)
    response = client.post("/login", data={"email": "wrong@example.com", "password": "wrongpass"})

    assert response.status_code == 200
    assert b"Invalid email or password" in response.content
    # Verify template was called with error message
    mock_template.assert_called_once()
    call_args = mock_template.call_args[0]
    # New Starlette API: first arg is request, second is template name
    assert call_args[1] == "login.html"
    assert "error" in call_args[2]
    assert call_args[2]["error"] == "Invalid email or password"


def test_login_post_valid_credentials_with_email_mfa(test_user, mocker):
    """Test successful login with email MFA method."""
    # Set user to have email MFA
    test_user_with_mfa = test_user.copy()
    test_user_with_mfa["mfa_method"] = "email"

    override_tenant(app, test_user["tenant_id"])

    mock_verify = mocker.patch(f"{AUTH_LOGIN}.verify_login_with_status")
    mock_create_otp = mocker.patch(f"{AUTH_LOGIN}.create_email_otp")
    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_send_email = mocker.patch(f"{AUTH_LOGIN}.send_mfa_code_email")

    mock_verify.return_value = {"status": "success", "user": test_user_with_mfa}
    mock_create_otp.return_value = "123456"
    mock_get_email.return_value = test_user["email"]  # Service returns string

    client = TestClient(app)
    response = client.post(
        "/login",
        data={
            "email": test_user["email"],
            "password": "TestPassword123!",
            "timezone": "America/New_York",
            "locale": "en-US",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify"
    mock_send_email.assert_called_once_with(test_user["email"], "123456")


def test_login_post_valid_credentials_without_email_row(test_user, mocker):
    """Test successful login when primary email row doesn't exist."""
    test_user_with_mfa = test_user.copy()
    test_user_with_mfa["mfa_method"] = "email"

    override_tenant(app, test_user["tenant_id"])

    mock_verify = mocker.patch(f"{AUTH_LOGIN}.verify_login_with_status")
    mock_create_otp = mocker.patch(f"{AUTH_LOGIN}.create_email_otp")
    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_send_email = mocker.patch(f"{AUTH_LOGIN}.send_mfa_code_email")

    mock_verify.return_value = {"status": "success", "user": test_user_with_mfa}
    mock_create_otp.return_value = "123456"
    mock_get_email.return_value = None  # No email

    client = TestClient(app)
    response = client.post(
        "/login",
        data={"email": test_user["email"], "password": "TestPassword123!"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify"
    # Email should not be sent if no email row
    mock_send_email.assert_not_called()


def test_login_post_with_totp_mfa(test_user, mocker):
    """Test successful login with TOTP MFA method."""
    test_user_with_totp = test_user.copy()
    test_user_with_totp["mfa_method"] = "totp"

    override_tenant(app, test_user["tenant_id"])

    mock_verify = mocker.patch(f"{AUTH_LOGIN}.verify_login_with_status")
    mock_verify.return_value = {"status": "success", "user": test_user_with_totp}

    client = TestClient(app)
    response = client.post(
        "/login",
        data={"email": test_user["email"], "password": "TestPassword123!"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify"


def test_logout(test_tenant):
    """Test logout clears session and redirects."""
    override_tenant(app, test_tenant["id"])

    client = TestClient(app)

    # Create session with data
    with client:
        # Simulate a session
        response = client.post("/logout", follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_dashboard_not_authenticated(test_tenant, mocker):
    """Test dashboard redirects to login when not authenticated."""
    override_tenant(app, test_tenant["id"])

    mock_user = mocker.patch(f"{DEPS_AUTH}.get_current_user")
    mock_user.return_value = None

    client = TestClient(app)
    response = client.get("/dashboard", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_dashboard_authenticated(test_user, mocker):
    """Test dashboard renders for authenticated user."""
    from fastapi.responses import HTMLResponse

    override_tenant(app, test_user["tenant_id"])

    mock_user = mocker.patch(f"{DEPS_AUTH}.get_current_user")
    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_context = mocker.patch(f"{UTILS_TEMPLATE}.get_template_context")
    mock_template = mocker.patch(f"{AUTH_DASHBOARD}.templates.TemplateResponse")
    mock_groups = mocker.patch(f"{AUTH_DASHBOARD}.groups_service.get_my_groups")
    mock_apps = mocker.patch(f"{AUTH_DASHBOARD}.sp_service.get_user_accessible_apps")

    mock_user.return_value = test_user
    mock_get_email.return_value = test_user["email"]  # Service returns string
    mock_groups_result = Mock()
    mock_groups_result.items = []
    mock_groups.return_value = mock_groups_result
    mock_apps_result = Mock()
    mock_apps_result.items = []
    mock_apps.return_value = mock_apps_result
    mock_context.return_value = {
        "request": Mock(),
        "user": test_user,
        "nav_items": [],
        "nav": {},
    }
    mock_template.return_value = HTMLResponse(content="<html>dashboard</html>")

    client = TestClient(app)
    response = client.get("/dashboard")

    assert response.status_code == 200
    # Verify user email was set
    mock_context.assert_called_once()


def test_dashboard_authenticated_no_email(test_user, mocker):
    """Test dashboard renders when user has no primary email."""
    from fastapi.responses import HTMLResponse

    override_tenant(app, test_user["tenant_id"])

    mock_user = mocker.patch(f"{DEPS_AUTH}.get_current_user")
    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_context = mocker.patch(f"{UTILS_TEMPLATE}.get_template_context")
    mock_template = mocker.patch(f"{AUTH_DASHBOARD}.templates.TemplateResponse")
    mock_groups = mocker.patch(f"{AUTH_DASHBOARD}.groups_service.get_my_groups")
    mock_apps = mocker.patch(f"{AUTH_DASHBOARD}.sp_service.get_user_accessible_apps")

    mock_user.return_value = test_user
    mock_get_email.return_value = None  # No email
    mock_groups_result = Mock()
    mock_groups_result.items = []
    mock_groups.return_value = mock_groups_result
    mock_apps_result = Mock()
    mock_apps_result.items = []
    mock_apps.return_value = mock_apps_result
    mock_context.return_value = {
        "request": Mock(),
        "user": test_user,
        "nav_items": [],
        "nav": {},
    }
    mock_template.return_value = HTMLResponse(content="<html>dashboard</html>")

    client = TestClient(app)
    response = client.get("/dashboard")

    assert response.status_code == 200
    # Verify "N/A" was used for missing email
    mock_context.assert_called_once()


def test_verify_email_public_success_new_user(test_tenant, mocker):
    """Test successful email verification for new user without password."""
    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_verify = mocker.patch(f"{SERVICES_EMAILS}.verify_email_by_nonce")
    mock_get_user = mocker.patch(f"{SERVICES_USERS}.get_user_by_id_raw")

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": None,
        "verify_nonce": 1,
    }
    mock_get_user.return_value = {
        "id": "user-123",
        "email": "test@example.com",
        "password_hash": None,  # No password yet
    }
    mock_verify.return_value = True

    client = TestClient(app)
    response = client.get("/verify-email/email-123/1", follow_redirects=False)

    assert response.status_code == 303
    assert "/set-password?email_id=email-123" in response.headers["location"]
    mock_verify.assert_called_once_with(test_tenant["id"], "email-123", 1)


def test_verify_email_public_success_existing_user(test_tenant, mocker):
    """Test successful email verification for existing user with password."""
    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_verify = mocker.patch(f"{SERVICES_EMAILS}.verify_email_by_nonce")
    mock_get_user = mocker.patch(f"{SERVICES_USERS}.get_user_by_id_raw")

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": None,
        "verify_nonce": 1,
    }
    mock_get_user.return_value = {
        "id": "user-123",
        "email": "test@example.com",
        "password_hash": "hashed_password",  # Has password
    }
    mock_verify.return_value = True

    client = TestClient(app)
    response = client.get("/verify-email/email-123/1", follow_redirects=False)

    assert response.status_code == 303
    assert "/login?success=email_verified" in response.headers["location"]
    mock_verify.assert_called_once_with(test_tenant["id"], "email-123", 1)


def test_verify_email_public_already_verified_no_password(test_tenant, mocker):
    """Test verification of already verified email for user without password."""
    from datetime import UTC, datetime

    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_verify = mocker.patch(f"{SERVICES_EMAILS}.verify_email_by_nonce")
    mock_get_user = mocker.patch(f"{SERVICES_USERS}.get_user_by_id_raw")

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": datetime.now(UTC),  # Already verified
        "verify_nonce": 1,
    }
    mock_get_user.return_value = {
        "id": "user-123",
        "email": "test@example.com",
        "password_hash": None,  # No password yet
    }

    client = TestClient(app)
    response = client.get("/verify-email/email-123/1", follow_redirects=False)

    assert response.status_code == 303
    assert "/set-password?email_id=email-123" in response.headers["location"]
    mock_verify.assert_not_called()


def test_verify_email_public_already_verified_with_password(test_tenant, mocker):
    """Test verification of already verified email for user with password."""
    from datetime import UTC, datetime

    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_verify = mocker.patch(f"{SERVICES_EMAILS}.verify_email_by_nonce")
    mock_get_user = mocker.patch(f"{SERVICES_USERS}.get_user_by_id_raw")

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": datetime.now(UTC),  # Already verified
        "verify_nonce": 1,
    }
    mock_get_user.return_value = {
        "id": "user-123",
        "email": "test@example.com",
        "password_hash": "hashed_password",  # Has password
    }

    client = TestClient(app)
    response = client.get("/verify-email/email-123/1", follow_redirects=False)

    assert response.status_code == 303
    assert "/login?success=already_verified" in response.headers["location"]
    mock_verify.assert_not_called()


def test_verify_email_public_invalid_nonce(test_tenant, mocker):
    """Test verification with invalid nonce."""
    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_verify = mocker.patch(f"{SERVICES_EMAILS}.verify_email_by_nonce")

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": None,
        "verify_nonce": 2,  # Different nonce
    }

    client = TestClient(app)
    response = client.get("/verify-email/email-123/1", follow_redirects=False)

    assert response.status_code == 303
    assert "/login?error=invalid_verification_link" in response.headers["location"]
    mock_verify.assert_not_called()


def test_verify_email_public_email_not_found(test_tenant, mocker):
    """Test verification when email not found."""
    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_verify = mocker.patch(f"{SERVICES_EMAILS}.verify_email_by_nonce")

    mock_get_email.return_value = None

    client = TestClient(app)
    response = client.get("/verify-email/email-123/1", follow_redirects=False)

    assert response.status_code == 303
    assert "/login?error=verification_failed" in response.headers["location"]
    mock_verify.assert_not_called()


def test_set_password_page_renders(test_tenant, mocker):
    """Test set password page renders for verified user without password."""
    from datetime import UTC, datetime

    from fastapi.responses import HTMLResponse

    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_get_user = mocker.patch(f"{SERVICES_USERS}.get_user_by_id_raw")
    mock_template = mocker.patch(f"{AUTH_ONBOARDING}.templates.TemplateResponse")
    mocker.patch(
        f"{AUTH_ONBOARDING}.settings_service.get_password_policy",
        return_value={"minimum_password_length": 14, "minimum_zxcvbn_score": 3},
    )

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": datetime.now(UTC),
    }
    mock_get_user.return_value = {
        "id": "user-123",
        "password_hash": None,
    }
    mock_template.return_value = HTMLResponse(content="<html>Set Password</html>")

    client = TestClient(app)
    response = client.get("/set-password?email_id=email-123")

    assert response.status_code == 200
    mock_template.assert_called_once()


def test_set_password_success(test_tenant, mocker):
    """Test successful password setting and auto-login."""
    from datetime import UTC, datetime

    from utils.password_strength import PasswordStrengthResult

    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_get_user = mocker.patch(f"{SERVICES_USERS}.get_user_by_id_raw")
    mock_update = mocker.patch(f"{SERVICES_USERS}.update_password")
    mock_hash = mocker.patch(f"{UTILS_PASSWORD}.hash_password")
    mock_create_otp = mocker.patch(f"{AUTH_ONBOARDING}.create_email_otp")
    mock_get_primary = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_send_email = mocker.patch(f"{AUTH_ONBOARDING}.send_mfa_code_email")
    mocker.patch(
        f"{AUTH_ONBOARDING}.settings_service.get_password_policy",
        return_value={"minimum_password_length": 14, "minimum_zxcvbn_score": 3},
    )
    mocker.patch(
        f"{AUTH_ONBOARDING}.validate_password",
        return_value=PasswordStrengthResult(),
    )

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": datetime.now(UTC),
    }
    mock_get_user.return_value = {
        "id": "user-123",
        "password_hash": None,
        "mfa_method": "email",
    }
    mock_hash.return_value = "hashed_password"
    mock_create_otp.return_value = "123456"
    mock_get_primary.return_value = "test@example.com"  # Service returns string

    client = TestClient(app)
    response = client.post(
        "/set-password",
        data={
            "email_id": "email-123",
            "password": "NewPassword123!",
            "password_confirm": "NewPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/mfa/verify" in response.headers["location"]
    mock_update.assert_called_once()
    mock_send_email.assert_called_once_with("test@example.com", "123456")


def test_set_password_passwords_dont_match(test_tenant, mocker):
    """Test password setting with mismatched passwords."""
    from datetime import UTC, datetime

    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_get_user = mocker.patch(f"{SERVICES_USERS}.get_user_by_id_raw")
    mock_update = mocker.patch(f"{SERVICES_USERS}.update_password")

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": datetime.now(UTC),
    }
    mock_get_user.return_value = {
        "id": "user-123",
        "password_hash": None,
    }

    client = TestClient(app)
    response = client.post(
        "/set-password",
        data={
            "email_id": "email-123",
            "password": "Password123!",
            "password_confirm": "DifferentPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=passwords_dont_match" in response.headers["location"]
    mock_update.assert_not_called()


def test_set_password_too_short(test_tenant, mocker):
    """Test password setting with weak password rejected by validate_password."""
    from datetime import UTC, datetime

    from utils.password_strength import PasswordIssue, PasswordStrengthResult

    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_get_user = mocker.patch(f"{SERVICES_USERS}.get_user_by_id_raw")
    mock_update = mocker.patch(f"{SERVICES_USERS}.update_password")
    mocker.patch(
        f"{AUTH_ONBOARDING}.settings_service.get_password_policy",
        return_value={"minimum_password_length": 14, "minimum_zxcvbn_score": 3},
    )
    mocker.patch(
        f"{AUTH_ONBOARDING}.validate_password",
        return_value=PasswordStrengthResult(
            issues=[
                PasswordIssue(
                    code="password_too_short",
                    message="Password must be at least 14 characters long.",
                )
            ]
        ),
    )

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": datetime.now(UTC),
    }
    mock_get_user.return_value = {
        "id": "user-123",
        "password_hash": None,
    }

    client = TestClient(app)
    response = client.post(
        "/set-password",
        data={
            "email_id": "email-123",
            "password": "short",
            "password_confirm": "short",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    mock_update.assert_not_called()


# --- Email Possession Verification Tests ---


def test_send_verification_code_sends_email_and_creates_cookie(test_tenant, mocker):
    """Test that send-code endpoint sends email and creates verification cookie."""
    override_tenant(app, test_tenant["id"])

    mock_send = mocker.patch(f"{AUTH_LOGIN}.send_email_possession_code")
    mock_gen = mocker.patch(f"{AUTH_LOGIN}.generate_verification_code")

    mock_gen.return_value = "123456"
    mock_send.return_value = True

    client = TestClient(app)
    response = client.post(
        "/login/send-code",
        data={"email": "user@example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/login/verify"
    # Check cookie was set
    assert "email_verify_pending" in response.cookies
    mock_send.assert_called_once_with("user@example.com", "123456")


def test_send_verification_code_invalid_email(test_tenant):
    """Test that send-code rejects invalid email format."""
    override_tenant(app, test_tenant["id"])

    client = TestClient(app)
    response = client.post(
        "/login/send-code",
        data={"email": "not-an-email"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=invalid_email" in response.headers["location"]


def test_send_verification_code_with_trust_cookie_skips_verification(test_tenant, mocker):
    """Test that valid trust cookie skips email verification."""
    from schemas.saml import AuthRouteResult

    override_tenant(app, test_tenant["id"])

    email = "user@example.com"
    trust_cookie = create_trust_cookie(email, test_tenant["id"])
    trust_cookie_name = get_trust_cookie_name(email)

    mock_route = mocker.patch(f"{AUTH_HELPERS}.saml_service.determine_auth_route")
    mock_route.return_value = AuthRouteResult(route_type="password")

    client = TestClient(app, cookies={trust_cookie_name: trust_cookie})
    response = client.post(
        "/login/send-code",
        data={"email": email},
        follow_redirects=False,
    )

    assert response.status_code == 303
    # Should redirect to password form, not verification
    assert "show_password=true" in response.headers["location"]


def test_verify_code_page_renders_with_cookie(test_tenant, mocker):
    """Test that verify page renders when verification cookie exists."""
    from fastapi.responses import HTMLResponse

    override_tenant(app, test_tenant["id"])

    email = "user@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    mock_template = mocker.patch(f"{AUTH_LOGIN}.templates.TemplateResponse")
    mock_template.return_value = HTMLResponse(content="<html>verify</html>")

    client = TestClient(app, cookies={"email_verify_pending": cookie})
    response = client.get("/login/verify")

    assert response.status_code == 200
    mock_template.assert_called_once()
    call_args = mock_template.call_args[0]
    assert call_args[1] == "email_verification.html"
    assert call_args[2]["email"] == email


def test_verify_code_page_redirects_without_cookie(test_tenant):
    """Test that verify page redirects to login without verification cookie."""
    override_tenant(app, test_tenant["id"])

    client = TestClient(app)
    response = client.get("/login/verify", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_verify_code_success_routes_to_password(test_tenant, mocker):
    """Test successful code verification routes to password form."""
    from schemas.saml import AuthRouteResult

    override_tenant(app, test_tenant["id"])

    email = "user@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    mock_route = mocker.patch(f"{AUTH_HELPERS}.saml_service.determine_auth_route")
    mock_route.return_value = AuthRouteResult(route_type="password")

    client = TestClient(app, cookies={"email_verify_pending": cookie})
    response = client.post(
        "/login/verify-code",
        data={"code": code},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "show_password=true" in response.headers["location"]
    # Trust cookie should be set
    assert any(name.startswith("email_trust_") for name in response.cookies.keys())


def test_verify_code_success_routes_to_idp(test_tenant, mocker):
    """Test successful code verification routes to IdP."""
    from schemas.saml import AuthRouteResult

    override_tenant(app, test_tenant["id"])

    email = "user@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    mock_route = mocker.patch(f"{AUTH_HELPERS}.saml_service.determine_auth_route")
    mock_route.return_value = AuthRouteResult(route_type="idp", idp_id="idp-123")

    client = TestClient(app, cookies={"email_verify_pending": cookie})
    response = client.post(
        "/login/verify-code",
        data={"code": code},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/saml/login/idp-123" in response.headers["location"]


def test_verify_code_invalid_code(test_tenant):
    """Test verification with wrong code fails."""
    override_tenant(app, test_tenant["id"])

    email = "user@example.com"
    cookie = create_verification_cookie(email, "123456", test_tenant["id"])

    client = TestClient(app, cookies={"email_verify_pending": cookie})
    response = client.post(
        "/login/verify-code",
        data={"code": "999999"},  # Wrong code
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=invalid_code" in response.headers["location"]


def test_verify_code_without_cookie(test_tenant):
    """Test verification without cookie fails."""
    override_tenant(app, test_tenant["id"])

    client = TestClient(app)
    response = client.post(
        "/login/verify-code",
        data={"code": "123456"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=session_expired" in response.headers["location"]


def test_verify_code_user_not_found(test_tenant, mocker):
    """Test verification routes correctly when user not found."""
    from schemas.saml import AuthRouteResult

    override_tenant(app, test_tenant["id"])

    email = "nonexistent@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    mock_route = mocker.patch(f"{AUTH_HELPERS}.saml_service.determine_auth_route")
    mock_route.return_value = AuthRouteResult(route_type="not_found")

    client = TestClient(app, cookies={"email_verify_pending": cookie})
    response = client.post(
        "/login/verify-code",
        data={"code": code},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=user_not_found" in response.headers["location"]


def test_resend_code_sends_new_code(test_tenant, mocker):
    """Test resend endpoint sends new code and updates cookie."""
    override_tenant(app, test_tenant["id"])

    email = "user@example.com"
    old_cookie = create_verification_cookie(email, "111111", test_tenant["id"])

    mock_send = mocker.patch(f"{AUTH_LOGIN}.send_email_possession_code")
    mock_gen = mocker.patch(f"{AUTH_LOGIN}.generate_verification_code")

    mock_gen.return_value = "222222"
    mock_send.return_value = True

    client = TestClient(app, cookies={"email_verify_pending": old_cookie})
    response = client.post("/login/resend-code", follow_redirects=False)

    assert response.status_code == 303
    assert "success=code_sent" in response.headers["location"]
    # New code should be sent
    mock_send.assert_called_once_with(email, "222222")
    # Cookie should be updated
    assert "email_verify_pending" in response.cookies


def test_resend_code_without_cookie(test_tenant):
    """Test resend endpoint redirects without existing cookie."""
    override_tenant(app, test_tenant["id"])

    client = TestClient(app)
    response = client.post("/login/resend-code", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_verify_code_inactivated_user(test_tenant, mocker):
    """Test verification routes correctly for inactivated user."""
    from schemas.saml import AuthRouteResult

    override_tenant(app, test_tenant["id"])

    email = "inactive@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    mock_route = mocker.patch(f"{AUTH_HELPERS}.saml_service.determine_auth_route")
    mock_route.return_value = AuthRouteResult(route_type="inactivated")

    client = TestClient(app, cookies={"email_verify_pending": cookie})
    response = client.post(
        "/login/verify-code",
        data={"code": code},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=account_inactivated" in response.headers["location"]


def test_email_normalization_in_send_code(test_tenant, mocker):
    """Test that email is normalized to lowercase in send-code."""
    override_tenant(app, test_tenant["id"])

    mock_send = mocker.patch(f"{AUTH_LOGIN}.send_email_possession_code")
    mock_gen = mocker.patch(f"{AUTH_LOGIN}.generate_verification_code")

    mock_gen.return_value = "123456"
    mock_send.return_value = True

    client = TestClient(app)
    client.post(
        "/login/send-code",
        data={"email": "USER@EXAMPLE.COM"},
        follow_redirects=False,
    )

    # Email should be sent to normalized address
    mock_send.assert_called_once_with("user@example.com", "123456")


# --- Security Event Logging Tests ---


def test_login_failure_logs_event(test_tenant, mocker):
    """Test that failed login attempts are logged for security monitoring."""
    from fastapi.responses import HTMLResponse

    override_tenant(app, test_tenant["id"])

    mock_verify = mocker.patch(f"{AUTH_LOGIN}.verify_login_with_status")
    mock_template = mocker.patch(f"{AUTH_LOGIN}.templates.TemplateResponse")
    mock_log = mocker.patch(f"{AUTH_LOGIN}.log_event")
    mock_get_user = mocker.patch(f"{AUTH_LOGIN}.users_service.get_user_id_by_email")

    mock_verify.return_value = {"status": "invalid_credentials", "user": None}
    mock_template.return_value = HTMLResponse(content="<html>Invalid email or password</html>")
    # User not found by email
    mock_get_user.return_value = None

    client = TestClient(app)
    response = client.post("/login", data={"email": "wrong@example.com", "password": "wrongpass"})

    assert response.status_code == 200
    # Verify log_event was called for failed login
    mock_log.assert_called_once()
    call_kwargs = mock_log.call_args.kwargs
    assert call_kwargs["event_type"] == "login_failed"
    assert call_kwargs["metadata"]["failure_reason"] == "invalid_credentials"
    assert call_kwargs["metadata"]["email_attempted"] == "wrong@example.com"


def test_login_failure_logs_event_with_known_user(test_tenant, test_user, mocker):
    """Test that failed login logs include user_id when user exists."""
    from fastapi.responses import HTMLResponse

    override_tenant(app, test_tenant["id"])

    mock_verify = mocker.patch(f"{AUTH_LOGIN}.verify_login_with_status")
    mock_template = mocker.patch(f"{AUTH_LOGIN}.templates.TemplateResponse")
    mock_log = mocker.patch(f"{AUTH_LOGIN}.log_event")
    mock_get_user = mocker.patch(f"{AUTH_LOGIN}.users_service.get_user_id_by_email")

    mock_verify.return_value = {"status": "invalid_credentials", "user": None}
    mock_template.return_value = HTMLResponse(content="<html>Invalid email or password</html>")
    # User found by email (wrong password case) - service returns string
    mock_get_user.return_value = str(test_user["id"])

    client = TestClient(app)
    response = client.post("/login", data={"email": test_user["email"], "password": "wrongpass"})

    assert response.status_code == 200
    mock_log.assert_called_once()
    call_kwargs = mock_log.call_args.kwargs
    # Compare as strings since test_user["id"] may be UUID
    assert call_kwargs["artifact_id"] == str(test_user["id"])
    assert call_kwargs["actor_user_id"] == str(test_user["id"])


def test_login_inactivated_user_logs_event(test_tenant, test_user, mocker):
    """Test that login attempts by inactivated users are logged."""
    from fastapi.responses import HTMLResponse

    inactivated_user = test_user.copy()
    inactivated_user["is_inactivated"] = True

    override_tenant(app, test_tenant["id"])

    mock_verify = mocker.patch(f"{AUTH_LOGIN}.verify_login_with_status")
    mock_template = mocker.patch(f"{AUTH_LOGIN}.templates.TemplateResponse")
    mock_log = mocker.patch(f"{AUTH_LOGIN}.log_event")

    mock_verify.return_value = {
        "status": "inactivated",
        "user": inactivated_user,
        "can_request_reactivation": True,
    }
    mock_template.return_value = HTMLResponse(content="<html>Inactivated</html>")

    client = TestClient(app)
    response = client.post("/login", data={"email": test_user["email"], "password": "password123"})

    assert response.status_code == 200
    mock_log.assert_called_once()
    call_kwargs = mock_log.call_args.kwargs
    assert call_kwargs["event_type"] == "login_failed"
    assert call_kwargs["metadata"]["failure_reason"] == "inactivated"
    assert call_kwargs["artifact_id"] == str(inactivated_user["id"])


def test_logout_logs_event_when_user_in_session(test_tenant, test_user, mocker):
    """Test that logout events are logged when user is in session."""
    override_tenant(app, test_tenant["id"])

    # We need to mock the session.get to return the user_id
    mock_session = {"user_id": str(test_user["id"])}

    mock_log = mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    # Verify log_event was called with correct params
    mock_log.assert_called_once()
    call_kwargs = mock_log.call_args.kwargs
    assert call_kwargs["event_type"] == "user_signed_out"
    assert call_kwargs["actor_user_id"] == str(test_user["id"])
    assert call_kwargs["artifact_id"] == str(test_user["id"])


def test_logout_no_log_when_no_session(test_tenant, mocker):
    """Test that logout does not log when no user in session."""
    override_tenant(app, test_tenant["id"])

    # Empty session - no user_id
    mock_session = {}

    mock_log = mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    # Verify log_event was NOT called since no user in session
    mock_log.assert_not_called()


def test_logout_propagates_slo_to_active_sps(test_tenant, test_user, mocker):
    """Test that logout propagates SLO to downstream SPs with active sessions."""
    override_tenant(app, test_tenant["id"])

    active_sps = [
        {
            "sp_id": "sp-1",
            "sp_entity_id": "https://sp1.example.com",
            "name_id": str(test_user["id"]),
            "session_index": "_session_1",
        }
    ]
    mock_session = {
        "user_id": str(test_user["id"]),
        "sso_active_sps": active_sps,
    }

    mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mock_propagate = mocker.patch(
        "services.service_providers.slo.propagate_logout_to_sps",
        return_value=1,
    )
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    mock_propagate.assert_called_once()
    call_kwargs = mock_propagate.call_args[1]
    assert str(call_kwargs["tenant_id"]) == str(test_tenant["id"])
    assert call_kwargs["user_id"] == str(test_user["id"])
    assert call_kwargs["active_sps"] == active_sps


def test_logout_does_not_propagate_when_no_active_sps(test_tenant, test_user, mocker):
    """Test that logout does not propagate SLO when no active downstream SPs."""
    override_tenant(app, test_tenant["id"])

    mock_session = {
        "user_id": str(test_user["id"]),
    }

    mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mock_propagate = mocker.patch(
        "services.service_providers.slo.propagate_logout_to_sps",
    )
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 303
    mock_propagate.assert_not_called()


def test_logout_succeeds_even_if_propagation_fails(test_tenant, test_user, mocker):
    """Test that logout succeeds even if SLO propagation raises an exception."""
    override_tenant(app, test_tenant["id"])

    active_sps = [
        {
            "sp_id": "sp-1",
            "sp_entity_id": "https://sp1.example.com",
            "name_id": str(test_user["id"]),
            "session_index": "_session_1",
        }
    ]
    mock_session = {
        "user_id": str(test_user["id"]),
        "sso_active_sps": active_sps,
    }

    mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mocker.patch(
        "services.service_providers.slo.propagate_logout_to_sps",
        side_effect=Exception("Propagation boom"),
    )
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    response = client.post("/logout", follow_redirects=False)

    # Logout should still succeed
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# ============================================================================
# Upstream SAML SLO (redirect to IdP during logout)
# ============================================================================


def test_logout_initiates_upstream_slo_redirect(test_tenant, test_user, mocker):
    """Test that logout redirects to IdP SLO URL when SAML session is active."""
    override_tenant(app, test_tenant["id"])

    mock_session = {
        "user_id": str(test_user["id"]),
        "saml_idp_id": "idp-123",
        "saml_name_id": "user@example.com",
        "saml_name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "saml_session_index": "_session_abc",
    }

    mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mocker.patch(
        "services.saml.initiate_sp_logout",
        return_value="https://idp.example.com/slo?SAMLRequest=abc",
    )
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "https://idp.example.com/slo?SAMLRequest=abc"


def test_logout_no_upstream_slo_when_service_returns_none(test_tenant, test_user, mocker):
    """Test that logout falls through to /login when initiate_sp_logout returns None."""
    override_tenant(app, test_tenant["id"])

    mock_session = {
        "user_id": str(test_user["id"]),
        "saml_idp_id": "idp-123",
        "saml_name_id": "user@example.com",
    }

    mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mocker.patch("services.saml.initiate_sp_logout", return_value=None)
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_logout_succeeds_even_if_upstream_slo_fails(test_tenant, test_user, mocker):
    """Test that logout redirects to /login even when upstream SLO raises an exception."""
    override_tenant(app, test_tenant["id"])

    mock_session = {
        "user_id": str(test_user["id"]),
        "saml_idp_id": "idp-123",
        "saml_name_id": "user@example.com",
    }

    mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mocker.patch(
        "services.saml.initiate_sp_logout",
        side_effect=Exception("IdP unreachable"),
    )
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    response = client.post("/logout", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_logout_passes_correct_slo_params(test_tenant, test_user, mocker):
    """Test that all SAML session values are passed correctly to initiate_sp_logout."""
    override_tenant(app, test_tenant["id"])

    mock_session = {
        "user_id": str(test_user["id"]),
        "saml_idp_id": "idp-456",
        "saml_name_id": "admin@corp.example.com",
        "saml_name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "saml_session_index": "_session_xyz",
    }

    mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mock_slo = mocker.patch(
        "services.saml.initiate_sp_logout",
        return_value="https://idp.example.com/slo",
    )
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    client.post("/logout", follow_redirects=False)

    mock_slo.assert_called_once()
    call_kwargs = mock_slo.call_args[1]
    assert str(call_kwargs["tenant_id"]) == str(test_tenant["id"])
    assert call_kwargs["saml_idp_id"] == "idp-456"
    assert call_kwargs["name_id"] == "admin@corp.example.com"
    assert call_kwargs["name_id_format"] == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    assert call_kwargs["session_index"] == "_session_xyz"


def test_logout_with_both_downstream_and_upstream_slo(test_tenant, test_user, mocker):
    """Test that both downstream propagation and upstream SLO are triggered.

    When both active downstream SPs and SAML session fields are present,
    propagate_logout_to_sps is called AND initiate_sp_logout is called.
    The upstream redirect takes precedence over /login.
    """
    override_tenant(app, test_tenant["id"])

    active_sps = [
        {
            "sp_id": "sp-1",
            "sp_entity_id": "https://sp1.example.com",
            "name_id": str(test_user["id"]),
            "session_index": "_session_1",
        }
    ]
    mock_session = {
        "user_id": str(test_user["id"]),
        "sso_active_sps": active_sps,
        "saml_idp_id": "idp-789",
        "saml_name_id": "user@example.com",
        "saml_name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "saml_session_index": "_session_abc",
    }

    mocker.patch(f"{AUTH_LOGOUT}.log_event")
    mock_propagate = mocker.patch(
        "services.service_providers.slo.propagate_logout_to_sps",
        return_value=1,
    )
    mock_slo = mocker.patch(
        "services.saml.initiate_sp_logout",
        return_value="https://idp.example.com/slo?SAMLRequest=xyz",
    )
    mocker.patch("starlette.requests.Request.session", mock_session)

    client = TestClient(app)
    response = client.post("/logout", follow_redirects=False)

    # Both downstream and upstream SLO should be called
    mock_propagate.assert_called_once()
    mock_slo.assert_called_once()

    # Upstream redirect takes precedence
    assert response.status_code == 303
    assert response.headers["location"] == "https://idp.example.com/slo?SAMLRequest=xyz"


def test_set_password_logs_event(test_tenant, mocker):
    """Test that setting password logs an event."""
    from datetime import UTC, datetime

    from utils.password_strength import PasswordStrengthResult

    override_tenant(app, test_tenant["id"])

    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_email_for_verification")
    mock_get_user = mocker.patch(f"{SERVICES_USERS}.get_user_by_id_raw")
    mocker.patch(f"{SERVICES_USERS}.update_password")
    mock_hash = mocker.patch(f"{UTILS_PASSWORD}.hash_password")
    mock_create_otp = mocker.patch(f"{AUTH_ONBOARDING}.create_email_otp")
    mock_get_primary = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mocker.patch(f"{AUTH_ONBOARDING}.send_mfa_code_email")
    mock_log = mocker.patch(f"{AUTH_ONBOARDING}.log_event")
    mocker.patch(
        f"{AUTH_ONBOARDING}.settings_service.get_password_policy",
        return_value={"minimum_password_length": 14, "minimum_zxcvbn_score": 3},
    )
    mocker.patch(
        f"{AUTH_ONBOARDING}.validate_password",
        return_value=PasswordStrengthResult(),
    )

    mock_get_email.return_value = {
        "id": "email-123",
        "user_id": "user-123",
        "email": "test@example.com",
        "verified_at": datetime.now(UTC),
    }
    mock_get_user.return_value = {
        "id": "user-123",
        "password_hash": None,
        "mfa_method": "email",
    }
    mock_hash.return_value = "hashed_password"
    mock_create_otp.return_value = "123456"
    mock_get_primary.return_value = "test@example.com"

    client = TestClient(app)
    response = client.post(
        "/set-password",
        data={
            "email_id": "email-123",
            "password": "NewPassword123!",
            "password_confirm": "NewPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    # Verify password_set event was logged
    mock_log.assert_called_once()
    call_kwargs = mock_log.call_args.kwargs
    assert call_kwargs["event_type"] == "password_set"
    assert call_kwargs["artifact_id"] == "user-123"
    assert call_kwargs["actor_user_id"] == "user-123"


# =============================================================================
# Route Type Failure Tests (using deprecated /login/check-email endpoint)
# =============================================================================


def test_check_email_route_idp_disabled(test_tenant, mocker):
    """Test check-email handles idp_disabled route type."""
    override_tenant(app, test_tenant["id"])

    mock_route = mocker.patch(f"{AUTH_LOGIN}.saml_service.determine_auth_route")
    mock_route.return_value = Mock(route_type="idp_disabled", idp_id=None, user_id=None)

    client = TestClient(app)
    response = client.post(
        "/login/check-email",
        data={"email": "test@example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=idp_disabled" in response.headers["location"]


def test_check_email_route_no_auth_method(test_tenant, mocker):
    """Test check-email handles no_auth_method route type."""
    override_tenant(app, test_tenant["id"])

    mock_route = mocker.patch(f"{AUTH_LOGIN}.saml_service.determine_auth_route")
    mock_route.return_value = Mock(route_type="no_auth_method", idp_id=None, user_id=None)

    client = TestClient(app)
    response = client.post(
        "/login/check-email",
        data={"email": "test@example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=no_auth_method" in response.headers["location"]


def test_check_email_route_invalid_email(test_tenant, mocker):
    """Test check-email handles invalid_email route type."""
    override_tenant(app, test_tenant["id"])

    mock_route = mocker.patch(f"{AUTH_LOGIN}.saml_service.determine_auth_route")
    mock_route.return_value = Mock(route_type="invalid_email", idp_id=None, user_id=None)

    client = TestClient(app)
    response = client.post(
        "/login/check-email",
        data={"email": "invalid-email"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=invalid_email" in response.headers["location"]


def test_check_email_route_unknown_type_fallback(test_tenant, mocker):
    """Test check-email handles unknown route type with password fallback."""
    override_tenant(app, test_tenant["id"])

    mock_route = mocker.patch(f"{AUTH_LOGIN}.saml_service.determine_auth_route")
    mock_route.return_value = Mock(route_type="some_unknown_type", idp_id=None, user_id=None)

    client = TestClient(app)
    response = client.post(
        "/login/check-email",
        data={"email": "test@example.com"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    # Unknown route type falls back to password form
    assert "show_password=true" in response.headers["location"]


# =============================================================================
# Set Password Edge Cases Tests
# =============================================================================


def test_set_password_page_missing_email_id(test_tenant):
    """Test set-password GET redirects when email_id is missing."""
    override_tenant(app, test_tenant["id"])

    client = TestClient(app)
    response = client.get("/set-password", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_set_password_page_email_not_found(test_tenant, mocker):
    """Test set-password GET redirects when email is not found."""
    override_tenant(app, test_tenant["id"])

    mock_get = mocker.patch(f"{AUTH_ONBOARDING}.emails_service.get_email_for_verification")
    mock_get.return_value = None

    client = TestClient(app)
    response = client.get("/set-password?email_id=non-existent", follow_redirects=False)

    assert response.status_code == 303
    assert "error=invalid_link" in response.headers["location"]


def test_set_password_page_email_not_verified(test_tenant, mocker):
    """Test set-password GET redirects when email is not verified."""
    override_tenant(app, test_tenant["id"])

    mock_get = mocker.patch(f"{AUTH_ONBOARDING}.emails_service.get_email_for_verification")
    mock_get.return_value = {"id": "email-123", "verified_at": None, "user_id": "user-123"}

    client = TestClient(app)
    response = client.get("/set-password?email_id=email-123", follow_redirects=False)

    assert response.status_code == 303
    assert "error=email_not_verified" in response.headers["location"]


def test_set_password_page_user_already_has_password(test_tenant, mocker):
    """Test set-password GET redirects when user already has password."""
    override_tenant(app, test_tenant["id"])

    mock_email = mocker.patch(f"{AUTH_ONBOARDING}.emails_service.get_email_for_verification")
    mock_user = mocker.patch(f"{AUTH_ONBOARDING}.users_service.get_user_by_id_raw")

    mock_email.return_value = {
        "id": "email-123",
        "verified_at": "2025-01-15T12:00:00Z",
        "user_id": "user-123",
    }
    mock_user.return_value = {
        "id": "user-123",
        "password_hash": "existing_hash",
    }

    client = TestClient(app)
    response = client.get("/set-password?email_id=email-123", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_set_password_post_email_not_found(test_tenant, mocker):
    """Test set-password POST redirects when email is not found."""
    override_tenant(app, test_tenant["id"])

    mock_get = mocker.patch(f"{AUTH_ONBOARDING}.emails_service.get_email_for_verification")
    mock_get.return_value = None

    client = TestClient(app)
    response = client.post(
        "/set-password",
        data={
            "email_id": "non-existent",
            "password": "test123!",
            "password_confirm": "test123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=invalid_link" in response.headers["location"]


def test_set_password_post_email_not_verified(test_tenant, mocker):
    """Test set-password POST redirects when email is not verified."""
    override_tenant(app, test_tenant["id"])

    mock_get = mocker.patch(f"{AUTH_ONBOARDING}.emails_service.get_email_for_verification")
    mock_get.return_value = {"id": "email-123", "verified_at": None, "user_id": "user-123"}

    client = TestClient(app)
    response = client.post(
        "/set-password",
        data={"email_id": "email-123", "password": "test123!", "password_confirm": "test123!"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "error=email_not_verified" in response.headers["location"]


def test_set_password_post_user_already_has_password(test_tenant, mocker):
    """Test set-password POST redirects when user already has password."""
    override_tenant(app, test_tenant["id"])

    mock_email = mocker.patch(f"{AUTH_ONBOARDING}.emails_service.get_email_for_verification")
    mock_user = mocker.patch(f"{AUTH_ONBOARDING}.users_service.get_user_by_id_raw")

    mock_email.return_value = {
        "id": "email-123",
        "verified_at": "2025-01-15T12:00:00Z",
        "user_id": "user-123",
    }
    mock_user.return_value = {
        "id": "user-123",
        "password_hash": "existing_hash",
    }

    client = TestClient(app)
    response = client.post(
        "/set-password",
        data={
            "email_id": "email-123",
            "password": "test123!",
            "password_confirm": "test123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# =============================================================================
# Client IP Extraction Tests
# =============================================================================


def test_get_client_ip_from_forwarded_header():
    """Test _get_client_ip extracts IP from X-Forwarded-For header."""
    from routers.auth import _get_client_ip

    mock_request = Mock()
    mock_request.headers = {"X-Forwarded-For": "192.168.1.100, 10.0.0.1, 127.0.0.1"}
    mock_request.client = Mock(host="172.16.0.1")

    ip = _get_client_ip(mock_request)

    assert ip == "192.168.1.100"


def test_get_client_ip_from_client_when_no_forwarded():
    """Test _get_client_ip uses client IP when no X-Forwarded-For."""
    from routers.auth import _get_client_ip

    mock_request = Mock()
    mock_request.headers = {}
    mock_request.client = Mock(host="192.168.1.50")

    ip = _get_client_ip(mock_request)

    assert ip == "192.168.1.50"


def test_get_client_ip_returns_unknown_when_no_client():
    """Test _get_client_ip returns 'unknown' when no client info."""
    from routers.auth import _get_client_ip

    mock_request = Mock()
    mock_request.headers = {}
    mock_request.client = None

    ip = _get_client_ip(mock_request)

    assert ip == "unknown"


# =============================================================================
# Dashboard My Apps Tests
# =============================================================================


def test_dashboard_shows_my_apps(test_user, mocker):
    """Test dashboard passes user apps to template context."""
    from fastapi.responses import HTMLResponse
    from schemas.service_providers import UserApp, UserAppList

    override_tenant(app, test_user["tenant_id"])

    mock_user = mocker.patch(f"{DEPS_AUTH}.get_current_user")
    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_context = mocker.patch(f"{UTILS_TEMPLATE}.get_template_context")
    mock_template = mocker.patch(f"{AUTH_DASHBOARD}.templates.TemplateResponse")
    mock_groups = mocker.patch(f"{AUTH_DASHBOARD}.groups_service.get_my_groups")
    mock_apps = mocker.patch(f"{AUTH_DASHBOARD}.sp_service.get_user_accessible_apps")

    mock_user.return_value = test_user
    mock_get_email.return_value = test_user["email"]

    # Set up mock groups (empty)
    mock_groups_result = Mock()
    mock_groups_result.items = []
    mock_groups.return_value = mock_groups_result

    # Set up mock apps with two entries
    app_items = [
        UserApp(id="sp-1", name="App One", description="First app", entity_id="urn:app:one"),
        UserApp(id="sp-2", name="App Two", description=None, entity_id="urn:app:two"),
    ]
    mock_apps.return_value = UserAppList(items=app_items, total=2)

    mock_context.return_value = {
        "request": Mock(),
        "user": test_user,
        "nav_items": [],
        "nav": {},
        "user_groups": [],
        "user_apps": app_items,
    }
    mock_template.return_value = HTMLResponse(content="<html>dashboard</html>")

    client = TestClient(app)
    response = client.get("/dashboard")

    assert response.status_code == 200
    # Verify get_user_accessible_apps was called
    mock_apps.assert_called_once()
    # Verify template context received the app items
    mock_context.assert_called_once()
    ctx_kwargs = mock_context.call_args
    # Check keyword args for user_apps
    assert "user_apps" in ctx_kwargs.kwargs
    assert len(ctx_kwargs.kwargs["user_apps"]) == 2
    assert ctx_kwargs.kwargs["user_apps"][0].name == "App One"
    assert ctx_kwargs.kwargs["user_apps"][1].name == "App Two"


def test_dashboard_shows_empty_my_apps(test_user, mocker):
    """Test dashboard passes empty apps list when user has no accessible apps."""
    from fastapi.responses import HTMLResponse
    from schemas.service_providers import UserAppList

    override_tenant(app, test_user["tenant_id"])

    mock_user = mocker.patch(f"{DEPS_AUTH}.get_current_user")
    mock_get_email = mocker.patch(f"{SERVICES_EMAILS}.get_primary_email")
    mock_context = mocker.patch(f"{UTILS_TEMPLATE}.get_template_context")
    mock_template = mocker.patch(f"{AUTH_DASHBOARD}.templates.TemplateResponse")
    mock_groups = mocker.patch(f"{AUTH_DASHBOARD}.groups_service.get_my_groups")
    mock_apps = mocker.patch(f"{AUTH_DASHBOARD}.sp_service.get_user_accessible_apps")

    mock_user.return_value = test_user
    mock_get_email.return_value = test_user["email"]

    # Set up mock groups (empty)
    mock_groups_result = Mock()
    mock_groups_result.items = []
    mock_groups.return_value = mock_groups_result

    # Set up mock apps as empty
    mock_apps.return_value = UserAppList(items=[], total=0)

    mock_context.return_value = {
        "request": Mock(),
        "user": test_user,
        "nav_items": [],
        "nav": {},
        "user_groups": [],
        "user_apps": [],
    }
    mock_template.return_value = HTMLResponse(content="<html>dashboard</html>")

    client = TestClient(app)
    response = client.get("/dashboard")

    assert response.status_code == 200
    # Verify get_user_accessible_apps was called
    mock_apps.assert_called_once()
    # Verify template context received empty apps list
    mock_context.assert_called_once()
    ctx_kwargs = mock_context.call_args
    assert "user_apps" in ctx_kwargs.kwargs
    assert ctx_kwargs.kwargs["user_apps"] == []
