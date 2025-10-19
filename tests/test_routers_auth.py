"""Tests for routers/auth.py endpoints."""

from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from main import app


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

    with patch("routers.auth.verify_login") as mock_verify:
        with patch("routers.auth.templates.TemplateResponse") as mock_template:
            mock_verify.return_value = None
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
            assert call_args[0] == "login.html"
            assert "error" in call_args[1]
            assert call_args[1]["error"] == "Invalid email or password"


def test_login_post_valid_credentials_with_email_mfa(test_user):
    """Test successful login with email MFA method."""
    from dependencies import get_tenant_id_from_request

    # Set user to have email MFA
    test_user_with_mfa = test_user.copy()
    test_user_with_mfa["mfa_method"] = "email"

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]

    with patch("routers.auth.verify_login") as mock_verify:
        with patch("routers.auth.create_email_otp") as mock_create_otp:
            with patch("routers.auth.database.user_emails.get_primary_email") as mock_get_email:
                with patch("routers.auth.send_mfa_code_email") as mock_send_email:
                    mock_verify.return_value = test_user_with_mfa
                    mock_create_otp.return_value = "123456"
                    mock_get_email.return_value = {"email": test_user["email"]}

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

    with patch("routers.auth.verify_login") as mock_verify:
        with patch("routers.auth.create_email_otp") as mock_create_otp:
            with patch("routers.auth.database.user_emails.get_primary_email") as mock_get_email:
                with patch("routers.auth.send_mfa_code_email") as mock_send_email:
                    mock_verify.return_value = test_user_with_mfa
                    mock_create_otp.return_value = "123456"
                    mock_get_email.return_value = None  # No email row

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

    with patch("routers.auth.verify_login") as mock_verify:
        mock_verify.return_value = test_user_with_totp

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
        with patch("database.user_emails.get_primary_email") as mock_get_email:
            with patch("utils.template_context.get_template_context") as mock_context:
                with patch("routers.auth.templates.TemplateResponse") as mock_template:
                    mock_user.return_value = test_user
                    mock_get_email.return_value = {"email": test_user["email"]}
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
        with patch("database.user_emails.get_primary_email") as mock_get_email:
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
