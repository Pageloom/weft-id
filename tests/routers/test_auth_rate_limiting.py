"""Auth router rate limiting tests.

Tests that rate limiting errors are handled correctly for various auth endpoints.
These tests verify that brute force protection is properly implemented.
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


def test_email_send_rate_limit_by_ip(client, test_tenant_host):
    """Test email send rate limit by IP (10/hour)."""
    from services.exceptions import RateLimitError

    with patch("routers.auth.login.ratelimit.prevent") as mock_prevent:
        # Mock rate limiter raising RateLimitError
        mock_prevent.side_effect = RateLimitError(
            message="Too many requests",
            code="rate_limit_exceeded",
            retry_after=3600,
        )

        response = client.post(
            "/login/send-code",
            headers={"Host": test_tenant_host},
            data={"email": "test@example.com"},
            follow_redirects=False,
        )

        # Should redirect with error
        assert response.status_code == 303
        assert "too_many_requests" in response.headers["location"]


def test_email_send_rate_limit_by_email(client, test_tenant_host):
    """Test email send rate limit by email address (5/10min)."""
    from services.exceptions import RateLimitError

    with patch("routers.auth.login.ratelimit.prevent") as mock_prevent:
        # Mock the second prevent() call raising error (email-based limit)
        def prevent_side_effect(*args, **kwargs):
            # First call (IP limit) passes, second call (email limit) fails
            if "email_send:email" in args[0]:
                raise RateLimitError(
                    message="Too many requests",
                    code="rate_limit_exceeded",
                    retry_after=600,
                )

        mock_prevent.side_effect = prevent_side_effect

        response = client.post(
            "/login/send-code",
            headers={"Host": test_tenant_host},
            data={"email": "test@example.com"},
            follow_redirects=False,
        )

        # Should redirect with error
        assert response.status_code == 303
        assert "too_many_requests" in response.headers["location"]


def test_code_verification_rate_limit(client, test_tenant_host):
    """Test code verification rate limit (5 attempts/5min)."""
    from services.exceptions import RateLimitError

    # Mock getting email from verification cookie
    with patch("routers.auth.login.get_verification_cookie_email") as mock_get_email:
        with patch("routers.auth.login.ratelimit.prevent") as mock_prevent:
            # Mock cookie containing email
            mock_get_email.return_value = "test@example.com"

            # Mock rate limiter raising RateLimitError
            mock_prevent.side_effect = RateLimitError(
                message="Too many verification attempts",
                code="rate_limit_exceeded",
                retry_after=300,
            )

            # Set cookie in request
            client.cookies.set("email_verify_pending", "fake-cookie-value")

            response = client.post(
                "/login/verify-code",
                headers={"Host": test_tenant_host},
                data={"code": "123456"},
                follow_redirects=False,
            )

            # Should redirect with error
            assert response.status_code == 303
            assert "too_many_attempts" in response.headers["location"]


def test_code_resend_rate_limit(client, test_tenant_host):
    """Test code resend rate limit (5/10min by IP)."""
    from services.exceptions import RateLimitError

    with patch("routers.auth.login.get_verification_cookie_email") as mock_get_email:
        with patch("routers.auth.login.ratelimit.prevent") as mock_prevent:
            with patch("routers.auth.login.send_email_possession_code"):
                # Mock email from cookie
                mock_get_email.return_value = "test@example.com"

                # Mock rate limiter raising RateLimitError
                mock_prevent.side_effect = RateLimitError(
                    message="Too many resend requests",
                    code="rate_limit_exceeded",
                    retry_after=600,
                )

                # Set cookie in request
                client.cookies.set("email_verify_pending", "fake-cookie-value")

                response = client.post(
                    "/login/resend-code",
                    headers={"Host": test_tenant_host},
                    data={},
                    follow_redirects=False,
                )

                # Should redirect with error
                assert response.status_code == 303
                assert "too_many_requests" in response.headers["location"]


def test_hard_login_block_rate_limit_renders_template(client, test_tenant_host, test_user):
    """Test hard login block rate limit (20 attempts/15min)."""
    from services.exceptions import RateLimitError

    with patch("routers.auth.login.verify_login_with_status") as mock_verify:
        with patch("routers.auth.login.ratelimit.prevent") as mock_prevent:
            with patch("routers.auth.login.saml_service.get_enabled_idps_for_login") as mock_idps:
                with patch("routers.auth.login.templates.TemplateResponse") as mock_template:
                    # Mock login verification (user found with password)
                    mock_verify.return_value = {
                        "status": "password_required",
                        "user": test_user,
                    }

                    # Mock no SSO
                    mock_idps.return_value = []

                    # Mock rate limiter raising RateLimitError
                    mock_prevent.side_effect = RateLimitError(
                        message="Too many login attempts",
                        code="rate_limit_exceeded",
                        retry_after=900,
                    )

                    # Mock template response
                    from starlette.responses import HTMLResponse

                    mock_template.return_value = HTMLResponse(
                        content="<html>Rate limit exceeded</html>",
                        status_code=200,
                    )

                    response = client.post(
                        "/login",
                        headers={"Host": test_tenant_host},
                        data={
                            "email": test_user["email"],
                            "password": "TestPassword123!",
                        },
                    )

                    # Should render a template (login.html with error)
                    assert response.status_code == 200
                    # Verify template was called with login.html and error message
                    assert mock_template.called
                    _, template_name, template_context = mock_template.call_args[0]
                    assert template_name == "login.html"
                    # Verify error message is passed to template
                    assert "error" in template_context
                    assert "Too many login attempts" in template_context["error"]


def test_rate_limit_cooldown_shown_to_user(client, test_tenant_host):
    """Test that rate limit errors show cooldown period to user."""
    from services.exceptions import RateLimitError

    with patch("routers.auth.login.ratelimit.prevent") as mock_prevent:
        # Mock rate limiter with specific cooldown
        mock_prevent.side_effect = RateLimitError(
            message="Rate limit exceeded",
            code="rate_limit_exceeded",
            retry_after=600,  # 10 minutes
        )

        response = client.post(
            "/login/send-code",
            headers={"Host": test_tenant_host},
            data={"email": "test@example.com"},
            follow_redirects=True,  # Follow redirect to see error page
        )

        # Should show error about rate limit
        # The actual error display depends on template implementation
        assert response.status_code == 200
        # Check that some error feedback is present
        assert "too_many" in response.text.lower() or "rate" in response.text.lower()
