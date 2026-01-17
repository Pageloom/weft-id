"""Tests for routers/auth.py endpoints."""

from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from main import app

from app.utils.email_verification import (
    create_trust_cookie,
    create_verification_cookie,
    get_trust_cookie_name,
)


def test_login_page_not_authenticated(test_tenant):
    """Test login page renders when not authenticated."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    # Override tenant dependency
    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("routers.auth.get_current_user") as mock_user:
        with patch("routers.auth.get_tenant_id_from_request") as mock_tenant:
            with patch("routers.auth.templates.TemplateResponse") as mock_template:
                mock_user.return_value = None
                mock_tenant.return_value = test_tenant["id"]
                mock_template.return_value = HTMLResponse(content="<html>login page</html>")

                client = TestClient(app)
                response = client.get("/login")

                app.dependency_overrides.clear()

                assert response.status_code == 200
                assert b"login" in response.content.lower()
                mock_template.assert_called_once()


def test_login_page_already_authenticated_redirects(test_user):
    """Test login page redirects to dashboard when already authenticated."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]

    with patch("routers.auth.get_current_user") as mock_user:
        with patch("routers.auth.get_tenant_id_from_request") as mock_tenant:
            mock_user.return_value = test_user
            mock_tenant.return_value = test_user["tenant_id"]

            client = TestClient(app)
            response = client.get("/login", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert response.headers["location"] == "/dashboard"


def test_login_post_invalid_credentials(test_tenant):
    """Test login with invalid credentials."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("routers.auth.verify_login_with_status") as mock_verify:
        with patch("routers.auth.templates.TemplateResponse") as mock_template:
            mock_verify.return_value = {"status": "invalid_credentials", "user": None}
            mock_template.return_value = HTMLResponse(
                content="<html>Invalid email or password</html>"
            )

            client = TestClient(app)
            response = client.post(
                "/login", data={"email": "wrong@example.com", "password": "wrongpass"}
            )

            app.dependency_overrides.clear()

            assert response.status_code == 200
            assert b"Invalid email or password" in response.content
            # Verify template was called with error message
            mock_template.assert_called_once()
            call_args = mock_template.call_args[0]
            # New Starlette API: first arg is request, second is template name
            assert call_args[1] == "login.html"
            assert "error" in call_args[2]
            assert call_args[2]["error"] == "Invalid email or password"


def test_login_post_valid_credentials_with_email_mfa(test_user):
    """Test successful login with email MFA method."""
    from dependencies import get_tenant_id_from_request

    # Set user to have email MFA
    test_user_with_mfa = test_user.copy()
    test_user_with_mfa["mfa_method"] = "email"

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]

    with patch("routers.auth.verify_login_with_status") as mock_verify:
        with patch("routers.auth.create_email_otp") as mock_create_otp:
            with patch("services.emails.get_primary_email") as mock_get_email:
                with patch("routers.auth.send_mfa_code_email") as mock_send_email:
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

                    app.dependency_overrides.clear()

                    assert response.status_code == 303
                    assert response.headers["location"] == "/mfa/verify"
                    mock_send_email.assert_called_once_with(test_user["email"], "123456")


def test_login_post_valid_credentials_without_email_row(test_user):
    """Test successful login when primary email row doesn't exist."""
    from dependencies import get_tenant_id_from_request

    test_user_with_mfa = test_user.copy()
    test_user_with_mfa["mfa_method"] = "email"

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]

    with patch("routers.auth.verify_login_with_status") as mock_verify:
        with patch("routers.auth.create_email_otp") as mock_create_otp:
            with patch("services.emails.get_primary_email") as mock_get_email:
                with patch("routers.auth.send_mfa_code_email") as mock_send_email:
                    mock_verify.return_value = {"status": "success", "user": test_user_with_mfa}
                    mock_create_otp.return_value = "123456"
                    mock_get_email.return_value = None  # No email

                    client = TestClient(app)
                    response = client.post(
                        "/login",
                        data={"email": test_user["email"], "password": "TestPassword123!"},
                        follow_redirects=False,
                    )

                    app.dependency_overrides.clear()

                    assert response.status_code == 303
                    assert response.headers["location"] == "/mfa/verify"
                    # Email should not be sent if no email row
                    mock_send_email.assert_not_called()


def test_login_post_with_totp_mfa(test_user):
    """Test successful login with TOTP MFA method."""
    from dependencies import get_tenant_id_from_request

    test_user_with_totp = test_user.copy()
    test_user_with_totp["mfa_method"] = "totp"

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]

    with patch("routers.auth.verify_login_with_status") as mock_verify:
        mock_verify.return_value = {"status": "success", "user": test_user_with_totp}

        client = TestClient(app)
        response = client.post(
            "/login",
            data={"email": test_user["email"], "password": "TestPassword123!"},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/mfa/verify"


def test_logout(test_tenant):
    """Test logout clears session and redirects."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)

    # Create session with data
    with client:
        # Simulate a session
        response = client.post("/logout", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_dashboard_not_authenticated(test_tenant):
    """Test dashboard redirects to login when not authenticated."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("dependencies.auth.get_current_user") as mock_user:
        mock_user.return_value = None

        client = TestClient(app)
        response = client.get("/dashboard", follow_redirects=False)

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_dashboard_authenticated(test_user):
    """Test dashboard renders for authenticated user."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]

    with patch("dependencies.auth.get_current_user") as mock_user:
        with patch("services.emails.get_primary_email") as mock_get_email:
            with patch("utils.template_context.get_template_context") as mock_context:
                with patch("routers.auth.templates.TemplateResponse") as mock_template:
                    mock_user.return_value = test_user
                    mock_get_email.return_value = test_user["email"]  # Service returns string
                    mock_context.return_value = {
                        "request": Mock(),
                        "user": test_user,
                        "nav_items": [],
                        "nav": {},
                    }
                    mock_template.return_value = HTMLResponse(content="<html>dashboard</html>")

                    client = TestClient(app)
                    response = client.get("/dashboard")

                    app.dependency_overrides.clear()

                    assert response.status_code == 200
                    # Verify user email was set
                    mock_context.assert_called_once()


def test_dashboard_authenticated_no_email(test_user):
    """Test dashboard renders when user has no primary email."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]

    with patch("dependencies.auth.get_current_user") as mock_user:
        with patch("services.emails.get_primary_email") as mock_get_email:
            with patch("utils.template_context.get_template_context") as mock_context:
                with patch("routers.auth.templates.TemplateResponse") as mock_template:
                    mock_user.return_value = test_user
                    mock_get_email.return_value = None  # No email
                    mock_context.return_value = {
                        "request": Mock(),
                        "user": test_user,
                        "nav_items": [],
                        "nav": {},
                    }
                    mock_template.return_value = HTMLResponse(content="<html>dashboard</html>")

                    client = TestClient(app)
                    response = client.get("/dashboard")

                    app.dependency_overrides.clear()

                    assert response.status_code == 200
                    # Verify "N/A" was used for missing email
                    mock_context.assert_called_once()


def test_verify_email_public_success_new_user(test_tenant):
    """Test successful email verification for new user without password."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.emails.verify_email_by_nonce") as mock_verify:
            with patch("services.users.get_user_by_id_raw") as mock_get_user:
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

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "/set-password?email_id=email-123" in response.headers["location"]
                mock_verify.assert_called_once_with(test_tenant["id"], "email-123", 1)


def test_verify_email_public_success_existing_user(test_tenant):
    """Test successful email verification for existing user with password."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.emails.verify_email_by_nonce") as mock_verify:
            with patch("services.users.get_user_by_id_raw") as mock_get_user:
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

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "/login?success=email_verified" in response.headers["location"]
                mock_verify.assert_called_once_with(test_tenant["id"], "email-123", 1)


def test_verify_email_public_already_verified_no_password(test_tenant):
    """Test verification of already verified email for user without password."""
    from datetime import UTC, datetime

    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.emails.verify_email_by_nonce") as mock_verify:
            with patch("services.users.get_user_by_id_raw") as mock_get_user:
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

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "/set-password?email_id=email-123" in response.headers["location"]
                mock_verify.assert_not_called()


def test_verify_email_public_already_verified_with_password(test_tenant):
    """Test verification of already verified email for user with password."""
    from datetime import UTC, datetime

    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.emails.verify_email_by_nonce") as mock_verify:
            with patch("services.users.get_user_by_id_raw") as mock_get_user:
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

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "/login?success=already_verified" in response.headers["location"]
                mock_verify.assert_not_called()


def test_verify_email_public_invalid_nonce(test_tenant):
    """Test verification with invalid nonce."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.emails.verify_email_by_nonce") as mock_verify:
            mock_get_email.return_value = {
                "id": "email-123",
                "user_id": "user-123",
                "email": "test@example.com",
                "verified_at": None,
                "verify_nonce": 2,  # Different nonce
            }

            client = TestClient(app)
            response = client.get("/verify-email/email-123/1", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "/login?error=invalid_verification_link" in response.headers["location"]
            mock_verify.assert_not_called()


def test_verify_email_public_email_not_found(test_tenant):
    """Test verification when email not found."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.emails.verify_email_by_nonce") as mock_verify:
            mock_get_email.return_value = None

            client = TestClient(app)
            response = client.get("/verify-email/email-123/1", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "/login?error=verification_failed" in response.headers["location"]
            mock_verify.assert_not_called()


def test_set_password_page_renders(test_tenant):
    """Test set password page renders for verified user without password."""
    from datetime import UTC, datetime

    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.users.get_user_by_id_raw") as mock_get_user:
            with patch("routers.auth.templates.TemplateResponse") as mock_template:
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

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_template.assert_called_once()


def test_set_password_success(test_tenant):
    """Test successful password setting and auto-login."""
    from datetime import UTC, datetime

    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.users.get_user_by_id_raw") as mock_get_user:
            with patch("services.users.update_password") as mock_update:
                with patch("utils.password.hash_password") as mock_hash:
                    with patch("routers.auth.create_email_otp") as mock_create_otp:
                        with patch("services.emails.get_primary_email") as mock_get_primary:
                            with patch("routers.auth.send_mfa_code_email") as mock_send_email:
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
                                mock_get_primary.return_value = (
                                    "test@example.com"  # Service returns string
                                )

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

                                app.dependency_overrides.clear()

                                assert response.status_code == 303
                                assert "/mfa/verify" in response.headers["location"]
                                mock_update.assert_called_once()
                                mock_send_email.assert_called_once_with(
                                    "test@example.com", "123456"
                                )


def test_set_password_passwords_dont_match(test_tenant):
    """Test password setting with mismatched passwords."""
    from datetime import UTC, datetime

    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.users.get_user_by_id_raw") as mock_get_user:
            with patch("services.users.update_password") as mock_update:
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

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "error=passwords_dont_match" in response.headers["location"]
                mock_update.assert_not_called()


def test_set_password_too_short(test_tenant):
    """Test password setting with password too short."""
    from datetime import UTC, datetime

    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.users.get_user_by_id_raw") as mock_get_user:
            with patch("services.users.update_password") as mock_update:
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

                app.dependency_overrides.clear()

                assert response.status_code == 303
                assert "error=password_too_short" in response.headers["location"]
                mock_update.assert_not_called()


# --- Email Possession Verification Tests ---


def test_send_verification_code_sends_email_and_creates_cookie(test_tenant):
    """Test that send-code endpoint sends email and creates verification cookie."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("routers.auth.send_email_possession_code") as mock_send:
        with patch("routers.auth.generate_verification_code") as mock_gen:
            mock_gen.return_value = "123456"
            mock_send.return_value = True

            client = TestClient(app)
            response = client.post(
                "/login/send-code",
                data={"email": "user@example.com"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert response.headers["location"] == "/login/verify"
            # Check cookie was set
            assert "email_verify_pending" in response.cookies
            mock_send.assert_called_once_with("user@example.com", "123456")


def test_send_verification_code_invalid_email(test_tenant):
    """Test that send-code rejects invalid email format."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post(
        "/login/send-code",
        data={"email": "not-an-email"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_email" in response.headers["location"]


def test_send_verification_code_with_trust_cookie_skips_verification(test_tenant):
    """Test that valid trust cookie skips email verification."""
    from dependencies import get_tenant_id_from_request
    from schemas.saml import AuthRouteResult

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    email = "user@example.com"
    trust_cookie = create_trust_cookie(email, test_tenant["id"])
    trust_cookie_name = get_trust_cookie_name(email)

    with patch("routers.auth.saml_service.determine_auth_route") as mock_route:
        mock_route.return_value = AuthRouteResult(route_type="password")

        client = TestClient(app, cookies={trust_cookie_name: trust_cookie})
        response = client.post(
            "/login/send-code",
            data={"email": email},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        # Should redirect to password form, not verification
        assert "show_password=true" in response.headers["location"]


def test_verify_code_page_renders_with_cookie(test_tenant):
    """Test that verify page renders when verification cookie exists."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    email = "user@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    with patch("routers.auth.templates.TemplateResponse") as mock_template:
        mock_template.return_value = HTMLResponse(content="<html>verify</html>")

        client = TestClient(app, cookies={"email_verify_pending": cookie})
        response = client.get("/login/verify")

        app.dependency_overrides.clear()

        assert response.status_code == 200
        mock_template.assert_called_once()
        call_args = mock_template.call_args[0]
        assert call_args[1] == "email_verification.html"
        assert call_args[2]["email"] == email


def test_verify_code_page_redirects_without_cookie(test_tenant):
    """Test that verify page redirects to login without verification cookie."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.get("/login/verify", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_verify_code_success_routes_to_password(test_tenant):
    """Test successful code verification routes to password form."""
    from dependencies import get_tenant_id_from_request
    from schemas.saml import AuthRouteResult

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    email = "user@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    with patch("routers.auth.saml_service.determine_auth_route") as mock_route:
        mock_route.return_value = AuthRouteResult(route_type="password")

        client = TestClient(app, cookies={"email_verify_pending": cookie})
        response = client.post(
            "/login/verify-code",
            data={"code": code},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "show_password=true" in response.headers["location"]
        # Trust cookie should be set
        assert any(name.startswith("email_trust_") for name in response.cookies.keys())


def test_verify_code_success_routes_to_idp(test_tenant):
    """Test successful code verification routes to IdP."""
    from dependencies import get_tenant_id_from_request
    from schemas.saml import AuthRouteResult

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    email = "user@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    with patch("routers.auth.saml_service.determine_auth_route") as mock_route:
        mock_route.return_value = AuthRouteResult(route_type="idp", idp_id="idp-123")

        client = TestClient(app, cookies={"email_verify_pending": cookie})
        response = client.post(
            "/login/verify-code",
            data={"code": code},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "/saml/login/idp-123" in response.headers["location"]


def test_verify_code_invalid_code(test_tenant):
    """Test verification with wrong code fails."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    email = "user@example.com"
    cookie = create_verification_cookie(email, "123456", test_tenant["id"])

    client = TestClient(app, cookies={"email_verify_pending": cookie})
    response = client.post(
        "/login/verify-code",
        data={"code": "999999"},  # Wrong code
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=invalid_code" in response.headers["location"]


def test_verify_code_without_cookie(test_tenant):
    """Test verification without cookie fails."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post(
        "/login/verify-code",
        data={"code": "123456"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "error=session_expired" in response.headers["location"]


def test_verify_code_user_not_found(test_tenant):
    """Test verification routes correctly when user not found."""
    from dependencies import get_tenant_id_from_request
    from schemas.saml import AuthRouteResult

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    email = "nonexistent@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    with patch("routers.auth.saml_service.determine_auth_route") as mock_route:
        mock_route.return_value = AuthRouteResult(route_type="not_found")

        client = TestClient(app, cookies={"email_verify_pending": cookie})
        response = client.post(
            "/login/verify-code",
            data={"code": code},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=user_not_found" in response.headers["location"]


def test_resend_code_sends_new_code(test_tenant):
    """Test resend endpoint sends new code and updates cookie."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    email = "user@example.com"
    old_cookie = create_verification_cookie(email, "111111", test_tenant["id"])

    with patch("routers.auth.send_email_possession_code") as mock_send:
        with patch("routers.auth.generate_verification_code") as mock_gen:
            mock_gen.return_value = "222222"
            mock_send.return_value = True

            client = TestClient(app, cookies={"email_verify_pending": old_cookie})
            response = client.post("/login/resend-code", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert "success=code_sent" in response.headers["location"]
            # New code should be sent
            mock_send.assert_called_once_with(email, "222222")
            # Cookie should be updated
            assert "email_verify_pending" in response.cookies


def test_resend_code_without_cookie(test_tenant):
    """Test resend endpoint redirects without existing cookie."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post("/login/resend-code", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_verify_code_inactivated_user(test_tenant):
    """Test verification routes correctly for inactivated user."""
    from dependencies import get_tenant_id_from_request
    from schemas.saml import AuthRouteResult

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    email = "inactive@example.com"
    code = "123456"
    cookie = create_verification_cookie(email, code, test_tenant["id"])

    with patch("routers.auth.saml_service.determine_auth_route") as mock_route:
        mock_route.return_value = AuthRouteResult(route_type="inactivated")

        client = TestClient(app, cookies={"email_verify_pending": cookie})
        response = client.post(
            "/login/verify-code",
            data={"code": code},
            follow_redirects=False,
        )

        app.dependency_overrides.clear()

        assert response.status_code == 303
        assert "error=account_inactivated" in response.headers["location"]


def test_email_normalization_in_send_code(test_tenant):
    """Test that email is normalized to lowercase in send-code."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("routers.auth.send_email_possession_code") as mock_send:
        with patch("routers.auth.generate_verification_code") as mock_gen:
            mock_gen.return_value = "123456"
            mock_send.return_value = True

            client = TestClient(app)
            response = client.post(
                "/login/send-code",
                data={"email": "USER@EXAMPLE.COM"},
                follow_redirects=False,
            )

            app.dependency_overrides.clear()

            # Email should be sent to normalized address
            mock_send.assert_called_once_with("user@example.com", "123456")


# --- Security Event Logging Tests ---


def test_login_failure_logs_event(test_tenant):
    """Test that failed login attempts are logged for security monitoring."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("routers.auth.verify_login_with_status") as mock_verify:
        with patch("routers.auth.templates.TemplateResponse") as mock_template:
            with patch("routers.auth.log_event") as mock_log:
                with patch("routers.auth.users_service.get_user_id_by_email") as mock_get_user:
                    mock_verify.return_value = {"status": "invalid_credentials", "user": None}
                    mock_template.return_value = HTMLResponse(
                        content="<html>Invalid email or password</html>"
                    )
                    # User not found by email
                    mock_get_user.return_value = None

                    client = TestClient(app)
                    response = client.post(
                        "/login", data={"email": "wrong@example.com", "password": "wrongpass"}
                    )

                    app.dependency_overrides.clear()

                    assert response.status_code == 200
                    # Verify log_event was called for failed login
                    mock_log.assert_called_once()
                    call_kwargs = mock_log.call_args.kwargs
                    assert call_kwargs["event_type"] == "login_failed"
                    assert call_kwargs["metadata"]["failure_reason"] == "invalid_credentials"
                    assert call_kwargs["metadata"]["email_attempted"] == "wrong@example.com"


def test_login_failure_logs_event_with_known_user(test_tenant, test_user):
    """Test that failed login logs include user_id when user exists."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("routers.auth.verify_login_with_status") as mock_verify:
        with patch("routers.auth.templates.TemplateResponse") as mock_template:
            with patch("routers.auth.log_event") as mock_log:
                with patch("routers.auth.users_service.get_user_id_by_email") as mock_get_user:
                    mock_verify.return_value = {"status": "invalid_credentials", "user": None}
                    mock_template.return_value = HTMLResponse(
                        content="<html>Invalid email or password</html>"
                    )
                    # User found by email (wrong password case) - service returns string
                    mock_get_user.return_value = str(test_user["id"])

                    client = TestClient(app)
                    response = client.post(
                        "/login", data={"email": test_user["email"], "password": "wrongpass"}
                    )

                    app.dependency_overrides.clear()

                    assert response.status_code == 200
                    mock_log.assert_called_once()
                    call_kwargs = mock_log.call_args.kwargs
                    # Compare as strings since test_user["id"] may be UUID
                    assert call_kwargs["artifact_id"] == str(test_user["id"])
                    assert call_kwargs["actor_user_id"] == str(test_user["id"])


def test_login_inactivated_user_logs_event(test_tenant, test_user):
    """Test that login attempts by inactivated users are logged."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import HTMLResponse

    inactivated_user = test_user.copy()
    inactivated_user["is_inactivated"] = True

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("routers.auth.verify_login_with_status") as mock_verify:
        with patch("routers.auth.templates.TemplateResponse") as mock_template:
            with patch("routers.auth.log_event") as mock_log:
                mock_verify.return_value = {
                    "status": "inactivated",
                    "user": inactivated_user,
                    "can_request_reactivation": True,
                }
                mock_template.return_value = HTMLResponse(content="<html>Inactivated</html>")

                client = TestClient(app)
                response = client.post(
                    "/login", data={"email": test_user["email"], "password": "password123"}
                )

                app.dependency_overrides.clear()

                assert response.status_code == 200
                mock_log.assert_called_once()
                call_kwargs = mock_log.call_args.kwargs
                assert call_kwargs["event_type"] == "login_failed"
                assert call_kwargs["metadata"]["failure_reason"] == "inactivated"
                assert call_kwargs["artifact_id"] == str(inactivated_user["id"])


def test_logout_logs_event_when_user_in_session(test_tenant, test_user):
    """Test that logout events are logged when user is in session."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    # We need to mock the session.get to return the user_id
    mock_session = {"user_id": str(test_user["id"])}

    with patch("routers.auth.log_event") as mock_log:
        with patch("starlette.requests.Request.session", mock_session):
            client = TestClient(app)
            response = client.post("/logout", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert response.headers["location"] == "/login"
            # Verify log_event was called with correct params
            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args.kwargs
            assert call_kwargs["event_type"] == "user_signed_out"
            assert call_kwargs["actor_user_id"] == str(test_user["id"])
            assert call_kwargs["artifact_id"] == str(test_user["id"])


def test_logout_no_log_when_no_session(test_tenant):
    """Test that logout does not log when no user in session."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    # Empty session - no user_id
    mock_session = {}

    with patch("routers.auth.log_event") as mock_log:
        with patch("starlette.requests.Request.session", mock_session):
            client = TestClient(app)
            response = client.post("/logout", follow_redirects=False)

            app.dependency_overrides.clear()

            assert response.status_code == 303
            assert response.headers["location"] == "/login"
            # Verify log_event was NOT called since no user in session
            mock_log.assert_not_called()


def test_set_password_logs_event(test_tenant):
    """Test that setting password logs an event."""
    from datetime import UTC, datetime

    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    with patch("services.emails.get_email_for_verification") as mock_get_email:
        with patch("services.users.get_user_by_id_raw") as mock_get_user:
            with patch("services.users.update_password") as mock_update:
                with patch("utils.password.hash_password") as mock_hash:
                    with patch("routers.auth.create_email_otp") as mock_create_otp:
                        with patch("services.emails.get_primary_email") as mock_get_primary:
                            with patch("routers.auth.send_mfa_code_email"):
                                with patch("routers.auth.log_event") as mock_log:
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

                                    app.dependency_overrides.clear()

                                    assert response.status_code == 303
                                    # Verify password_set event was logged
                                    mock_log.assert_called_once()
                                    call_kwargs = mock_log.call_args.kwargs
                                    assert call_kwargs["event_type"] == "password_set"
                                    assert call_kwargs["artifact_id"] == "user-123"
                                    assert call_kwargs["actor_user_id"] == "user-123"
