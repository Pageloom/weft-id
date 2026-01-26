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


def test_send_email_with_authentication():
    """Test email sending with SMTP authentication."""
    # Reset the cached backend to pick up new settings
    import utils.email_backends

    utils.email_backends._backend_instance = None

    with patch("settings.SMTP_HOST", "smtp.example.com"):
        with patch("settings.SMTP_PORT", 587):
            with patch("settings.SMTP_USER", "user@example.com"):
                with patch("settings.SMTP_PASS", "password123"):
                    with patch("settings.SMTP_TLS", True):
                        with patch("smtplib.SMTP") as mock_smtp:
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
                            mock_server.login.assert_called_once_with(
                                "user@example.com", "password123"
                            )

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


def test_send_email_uses_settings():
    """Test that send_email uses settings for configuration."""
    # Reset the cached backend to pick up new settings
    import utils.email_backends

    utils.email_backends._backend_instance = None

    custom_host = "custom.smtp.com"
    custom_port = 2525

    with patch("settings.SMTP_HOST", custom_host):
        with patch("settings.SMTP_PORT", custom_port):
            with patch("smtplib.SMTP") as mock_smtp:
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
        assert subject == "Your multi-factor authentication was reset"
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
