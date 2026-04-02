"""Tests for utils.email module."""

import smtplib
from unittest.mock import MagicMock, patch


def test_send_email_success():
    """Test successful email sending."""
    from utils.email import send_email

    with patch("smtplib.SMTP") as mock_smtp:
        # Mock the SMTP server context manager
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = send_email(
            to_email="test@example.com",
            subject="Test Subject",
            html_body="<p>Test HTML</p>",
            text_body="Test Text",
        )

        assert result is True
        # Verify SMTP was called correctly
        mock_smtp.assert_called_once()
        mock_server.send_message.assert_called_once()


def test_send_email_without_text_body():
    """Test sending email with only HTML body."""
    from utils.email import send_email

    with patch("smtplib.SMTP") as mock_smtp:
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = send_email(
            to_email="test@example.com",
            subject="Test Subject",
            html_body="<p>Test HTML</p>",
            # No text_body
        )

        assert result is True
        mock_server.send_message.assert_called_once()


def test_send_email_with_authentication(mocker):
    """Test email sending with SMTP authentication."""
    # Reset the cached backend to pick up new settings
    import utils.email_backends

    utils.email_backends._backend_instance = None

    mocker.patch("settings.SMTP_HOST", "smtp.example.com")
    mocker.patch("settings.SMTP_PORT", 587)
    mocker.patch("settings.SMTP_USER", "user@example.com")
    mocker.patch("settings.SMTP_PASS", "password123")
    mocker.patch("settings.SMTP_TLS", True)
    mock_smtp = mocker.patch("smtplib.SMTP")

    mock_server = MagicMock()
    mock_smtp.return_value.__enter__.return_value = mock_server

    from utils.email import send_email

    result = send_email(
        to_email="test@example.com",
        subject="Test Subject",
        html_body="<p>Test HTML</p>",
        text_body="Test Text",
    )

    assert result is True
    # Verify STARTTLS and login were called
    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once_with("user@example.com", "password123")

    # Clean up
    utils.email_backends._backend_instance = None


def test_send_email_failure():
    """Test email sending failure handling."""
    from utils.email import send_email

    with patch("smtplib.SMTP") as mock_smtp:
        # Simulate SMTP connection error
        mock_smtp.side_effect = smtplib.SMTPException("Connection failed")

        result = send_email(
            to_email="test@example.com", subject="Test Subject", html_body="<p>Test HTML</p>"
        )

        assert result is False


def test_send_email_with_send_message_exception():
    """Test handling of send_message exceptions."""
    from utils.email import send_email

    with patch("smtplib.SMTP") as mock_smtp:
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        # Simulate send_message failure
        mock_server.send_message.side_effect = Exception("Send failed")

        result = send_email(
            to_email="test@example.com", subject="Test Subject", html_body="<p>Test HTML</p>"
        )

        assert result is False


def test_send_mfa_code_email():
    """Test sending MFA verification code email."""
    from utils.email import send_mfa_code_email

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_mfa_code_email(to_email="test@example.com", code="123456")

        assert result is True
        # Verify send_email was called with correct parameters
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        # Arguments are positional: to_email, subject, html_body, text_body
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "test@example.com"
        assert subject == "Your verification code"
        assert "123456" in html_body
        assert "123456" in text_body
        assert "10 minutes" in html_body


def test_send_mfa_code_email_failure():
    """Test MFA code email sending failure."""
    from utils.email import send_mfa_code_email

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_mfa_code_email(to_email="test@example.com", code="654321")

        assert result is False


def test_send_email_verification():
    """Test sending email verification link."""
    from utils.email import send_email_verification

    verification_url = "https://example.com/verify?token=abc123"

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_email_verification(
            to_email="test@example.com", verification_url=verification_url
        )

        assert result is True
        # Verify send_email was called with correct parameters
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        # Arguments are positional: to_email, subject, html_body, text_body
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "test@example.com"
        assert subject == "Verify your email address"
        assert verification_url in html_body
        assert verification_url in text_body


def test_send_email_verification_failure():
    """Test email verification sending failure."""
    from utils.email import send_email_verification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_email_verification(
            to_email="test@example.com", verification_url="https://example.com/verify?token=xyz"
        )

        assert result is False


def test_send_email_uses_settings(mocker):
    """Test that send_email uses settings for configuration."""
    # Reset the cached backend to pick up new settings
    import utils.email_backends

    utils.email_backends._backend_instance = None

    custom_host = "custom.smtp.com"
    custom_port = 2525

    mocker.patch("settings.SMTP_HOST", custom_host)
    mocker.patch("settings.SMTP_PORT", custom_port)
    mock_smtp = mocker.patch("smtplib.SMTP")

    mock_server = MagicMock()
    mock_smtp.return_value.__enter__.return_value = mock_server

    from utils.email import send_email

    send_email(to_email="test@example.com", subject="Test", html_body="<p>Test</p>")

    # Verify SMTP was created with custom host and port
    mock_smtp.assert_called_once_with(custom_host, custom_port, timeout=10)

    # Clean up
    utils.email_backends._backend_instance = None


def test_send_secondary_email_added_notification():
    """Test sending notification when admin adds secondary email."""
    from utils.email import send_secondary_email_added_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_secondary_email_added_notification(
            to_email="user@example.com", added_email="new@example.com", admin_name="Admin User"
        )

        assert result is True
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "user@example.com"
        assert subject == "Secondary email address added to your account"
        assert "new@example.com" in html_body
        assert "Admin User" in html_body
        assert "new@example.com" in text_body
        assert "Admin User" in text_body


def test_send_secondary_email_added_notification_failure():
    """Test failure when sending secondary email added notification."""
    from utils.email import send_secondary_email_added_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_secondary_email_added_notification(
            to_email="user@example.com", added_email="new@example.com", admin_name="Admin User"
        )

        assert result is False


def test_send_secondary_email_removed_notification():
    """Test sending notification when admin removes secondary email."""
    from utils.email import send_secondary_email_removed_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_secondary_email_removed_notification(
            to_email="user@example.com", removed_email="old@example.com", admin_name="Admin User"
        )

        assert result is True
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "user@example.com"
        assert subject == "Secondary email address removed from your account"
        assert "old@example.com" in html_body
        assert "Admin User" in html_body
        assert "old@example.com" in text_body
        assert "Admin User" in text_body


def test_send_secondary_email_removed_notification_failure():
    """Test failure when sending secondary email removed notification."""
    from utils.email import send_secondary_email_removed_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_secondary_email_removed_notification(
            to_email="user@example.com", removed_email="old@example.com", admin_name="Admin User"
        )

        assert result is False


def test_send_primary_email_changed_notification():
    """Test sending notification when admin changes primary email."""
    from utils.email import send_primary_email_changed_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_primary_email_changed_notification(
            to_email="old@example.com", new_primary_email="new@example.com", admin_name="Admin User"
        )

        assert result is True
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "old@example.com"
        assert subject == "Your primary email address has been changed"
        assert "new@example.com" in html_body
        assert "Admin User" in html_body
        assert "new@example.com" in text_body
        assert "Admin User" in text_body


def test_send_primary_email_changed_notification_failure():
    """Test failure when sending primary email changed notification."""
    from utils.email import send_primary_email_changed_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_primary_email_changed_notification(
            to_email="old@example.com", new_primary_email="new@example.com", admin_name="Admin User"
        )

        assert result is False


def test_send_account_reactivated_notification():
    """Test sending notification when account is reactivated."""
    from utils.email import send_account_reactivated_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_account_reactivated_notification(
            to_email="user@example.com", login_url="https://example.com/login"
        )

        assert result is True
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "user@example.com"
        assert subject == "Your account has been reactivated"
        assert "https://example.com/login" in html_body
        assert "https://example.com/login" in text_body
        assert "reactivated" in html_body.lower()


def test_send_account_reactivated_notification_failure():
    """Test failure when sending account reactivated notification."""
    from utils.email import send_account_reactivated_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_account_reactivated_notification(
            to_email="user@example.com", login_url="https://example.com/login"
        )

        assert result is False


def test_send_reactivation_denied_notification():
    """Test sending notification when reactivation request is denied."""
    from utils.email import send_reactivation_denied_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_reactivation_denied_notification(to_email="user@example.com")

        assert result is True
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "user@example.com"
        assert subject == "Your reactivation request was denied"
        assert "denied" in html_body.lower()
        assert "denied" in text_body.lower()


def test_send_reactivation_denied_notification_failure():
    """Test failure when sending reactivation denied notification."""
    from utils.email import send_reactivation_denied_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_reactivation_denied_notification(to_email="user@example.com")

        assert result is False


def test_send_reactivation_request_admin_notification():
    """Test sending notification to admin about reactivation request."""
    from utils.email import send_reactivation_request_admin_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_reactivation_request_admin_notification(
            to_email="admin@example.com",
            user_name="John Doe",
            user_email="john@example.com",
            requests_url="https://example.com/admin/reactivation-requests",
        )

        assert result is True
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "admin@example.com"
        assert subject == "Reactivation request received"
        assert "John Doe" in html_body
        assert "john@example.com" in html_body
        assert "https://example.com/admin/reactivation-requests" in html_body
        assert "John Doe" in text_body
        assert "john@example.com" in text_body


def test_send_reactivation_request_admin_notification_failure():
    """Test failure when sending reactivation request admin notification."""
    from utils.email import send_reactivation_request_admin_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_reactivation_request_admin_notification(
            to_email="admin@example.com",
            user_name="John Doe",
            user_email="john@example.com",
            requests_url="https://example.com/admin/reactivation-requests",
        )

        assert result is False


def test_send_provisioning_invitation():
    """Test sending provisioning invitation email."""
    from utils.email import send_provisioning_invitation

    verification_url = "https://acme.example.com/verify-email/eid/nonce"

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_provisioning_invitation(
            to_email="admin@acme.com",
            tenant_name="Acme Corp",
            verification_url=verification_url,
        )

        assert result is True
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "admin@acme.com"
        assert subject == "Set up your organization on WeftID"
        assert "Acme Corp" in html_body
        assert "Acme Corp" in text_body
        assert verification_url in html_body
        assert verification_url in text_body
        assert "founding administrator" in text_body


def test_send_provisioning_invitation_failure():
    """Test provisioning invitation sending failure."""
    from utils.email import send_provisioning_invitation

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_provisioning_invitation(
            to_email="admin@acme.com",
            tenant_name="Acme Corp",
            verification_url="https://example.com/verify",
        )

        assert result is False


def test_send_mfa_reset_notification():
    """Test sending MFA reset notification to user."""
    from utils.email import send_mfa_reset_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_mfa_reset_notification(
            to_email="user@example.com",
            admin_name="Jane Admin",
            reset_timestamp="2026-01-26 12:00 UTC",
        )

        assert result is True
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        to_email, subject, html_body, text_body = call_args[0]

        assert to_email == "user@example.com"
        assert subject == "Your two-step verification was reset"
        assert "Jane Admin" in html_body
        assert "2026-01-26 12:00 UTC" in html_body
        assert "Jane Admin" in text_body
        assert "2026-01-26 12:00 UTC" in text_body
        # Verify no action links in the email
        assert "href=" not in html_body or 'class="button"' not in html_body


def test_send_mfa_reset_notification_failure():
    """Test failure when sending MFA reset notification."""
    from utils.email import send_mfa_reset_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_mfa_reset_notification(
            to_email="user@example.com",
            admin_name="Jane Admin",
            reset_timestamp="2026-01-26 12:00 UTC",
        )

        assert result is False


# =============================================================================
# Email possession code (sign-in anti-enumeration)
# =============================================================================


# =============================================================================
# Branding integration
# =============================================================================


def test_get_branding_exception_returns_none():
    """Test _get_branding returns None when branding fetch throws."""
    from utils.email import _get_branding

    with patch("utils.email_branding.get_email_branding", side_effect=RuntimeError("DB down")):
        result = _get_branding("some-tenant-id")

    assert result is None


def test_get_branding_no_tenant_id_returns_none():
    """Test _get_branding returns None when tenant_id is None."""
    from utils.email import _get_branding

    result = _get_branding(None)
    assert result is None


def test_wrap_html_with_branding():
    """Test _wrap_html includes branded header when branding provided."""
    from utils.email import _wrap_html

    branding = {"tenant_name": "Acme Corp", "logo_data_uri": "data:image/png;base64,ABC"}
    html = _wrap_html("<p>Hello</p>", branding)

    assert "Acme Corp" in html
    assert "data:image/png;base64,ABC" in html
    assert "<p>Hello</p>" in html
    assert "WeftID by Pageloom" in html


def test_wrap_html_without_branding():
    """Test _wrap_html omits header when no branding."""
    from utils.email import _wrap_html

    html = _wrap_html("<p>Hello</p>", None)

    assert "<p>Hello</p>" in html
    assert "WeftID by Pageloom" in html


def test_wrap_text_with_branding():
    """Test _wrap_text includes tenant name header when branding provided."""
    from utils.email import _wrap_text

    branding = {"tenant_name": "Acme Corp", "logo_data_uri": None}
    text = _wrap_text("Hello world", branding)

    assert text.startswith("Acme Corp\n")
    assert "Hello world" in text
    assert "WeftID by Pageloom" in text


def test_wrap_text_without_branding():
    """Test _wrap_text omits header when no branding."""
    from utils.email import _wrap_text

    text = _wrap_text("Hello world", None)

    assert not text.startswith("Acme Corp")
    assert "Hello world" in text
    assert "WeftID by Pageloom" in text


def test_build_header_html_with_logo():
    """Test _build_header_html includes logo img when data URI present."""
    from utils.email import _build_header_html

    branding = {"tenant_name": "Acme Corp", "logo_data_uri": "data:image/png;base64,XYZ"}
    html = _build_header_html(branding)

    assert "<img" in html
    assert "data:image/png;base64,XYZ" in html
    assert "Acme Corp" in html


def test_build_header_html_without_logo():
    """Test _build_header_html uses text-only header when no logo."""
    from utils.email import _build_header_html

    branding = {"tenant_name": "Acme Corp", "logo_data_uri": None}
    html = _build_header_html(branding)

    assert "<img" not in html
    assert "Acme Corp" in html


# =============================================================================
# Email possession code (sign-in anti-enumeration)
# =============================================================================


def test_send_email_possession_code():
    """Test sending email possession verification code."""
    from utils.email import send_email_possession_code

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_email_possession_code(to_email="user@example.com", code="482917")

        assert result is True
        mock_send.assert_called_once()
        to_email, subject, html_body, text_body = mock_send.call_args[0]

        assert to_email == "user@example.com"
        assert subject == "Your sign-in code"
        assert "482917" in html_body
        assert "482917" in text_body
        assert "5 minutes" in html_body
        assert "5 minutes" in text_body


def test_send_email_possession_code_failure():
    """Test email possession code sending failure."""
    from utils.email import send_email_possession_code

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_email_possession_code(to_email="user@example.com", code="123456")

        assert result is False


def test_send_email_possession_code_with_branding():
    """Test that possession code email includes branding when tenant_id provided."""
    from utils.email import send_email_possession_code

    with (
        patch("utils.email.send_email") as mock_send,
        patch("utils.email._get_branding") as mock_branding,
    ):
        mock_branding.return_value = {"tenant_name": "Acme Corp", "logo_data_uri": None}
        mock_send.return_value = True

        result = send_email_possession_code(
            to_email="user@example.com", code="999999", tenant_id="tid-123"
        )

        assert result is True
        mock_branding.assert_called_once_with("tid-123")
        # Branding header should appear in text body
        _, _, _, text_body = mock_send.call_args[0]
        assert "Acme Corp" in text_body


# =============================================================================
# New user invitation emails
# =============================================================================


def test_send_new_user_privileged_domain_notification():
    """Test sending welcome email to new user on a privileged domain."""
    from utils.email import send_new_user_privileged_domain_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_new_user_privileged_domain_notification(
            to_email="jane@acme.com",
            admin_name="Admin User",
            org_name="Acme Corp",
            password_set_url="https://acme.example.com/set-password?email_id=eid&nonce=1",
        )

        assert result is True
        mock_send.assert_called_once()
        to_email, subject, html_body, text_body = mock_send.call_args[0]

        assert to_email == "jane@acme.com"
        assert subject == "Welcome to Acme Corp"
        assert "Admin User" in html_body
        assert "Admin User" in text_body
        assert "trusted email domain" in text_body
        assert "set-password?email_id=eid&amp;nonce=1" in html_body
        assert "set-password?email_id=eid&nonce=1" in text_body
        assert "Set Your Password" in html_body


def test_send_new_user_privileged_domain_notification_failure():
    """Test privileged domain notification sending failure."""
    from utils.email import send_new_user_privileged_domain_notification

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_new_user_privileged_domain_notification(
            to_email="jane@acme.com",
            admin_name="Admin",
            org_name="Acme",
            password_set_url="https://example.com/set-password",
        )

        assert result is False


def test_send_new_user_invitation():
    """Test sending invitation to new user on a non-privileged domain."""
    from utils.email import send_new_user_invitation

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = True

        result = send_new_user_invitation(
            to_email="john@external.com",
            admin_name="Admin User",
            org_name="Acme Corp",
            verification_url="https://acme.example.com/verify-email/eid/42",
        )

        assert result is True
        mock_send.assert_called_once()
        to_email, subject, html_body, text_body = mock_send.call_args[0]

        assert to_email == "john@external.com"
        assert subject == "You've been invited to join Acme Corp"
        assert "Admin User" in html_body
        assert "Admin User" in text_body
        assert "verify-email/eid/42" in html_body
        assert "verify-email/eid/42" in text_body
        assert "Verify Email" in html_body


def test_send_new_user_invitation_failure():
    """Test non-privileged domain invitation sending failure."""
    from utils.email import send_new_user_invitation

    with patch("utils.email.send_email") as mock_send:
        mock_send.return_value = False

        result = send_new_user_invitation(
            to_email="john@external.com",
            admin_name="Admin",
            org_name="Acme",
            verification_url="https://example.com/verify",
        )

        assert result is False


def test_send_new_user_invitation_with_branding():
    """Test that invitation emails include branding when tenant_id provided."""
    from utils.email import send_new_user_invitation

    with (
        patch("utils.email.send_email") as mock_send,
        patch("utils.email._get_branding") as mock_branding,
    ):
        mock_branding.return_value = {"tenant_name": "Acme Corp", "logo_data_uri": None}
        mock_send.return_value = True

        result = send_new_user_invitation(
            to_email="john@external.com",
            admin_name="Admin",
            org_name="Acme Corp",
            verification_url="https://example.com/verify",
            tenant_id="tid-456",
        )

        assert result is True
        mock_branding.assert_called_once_with("tid-456")
        _, _, _, text_body = mock_send.call_args[0]
        assert "Acme Corp" in text_body
