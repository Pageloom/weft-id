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
    from utils.email import send_email

    with patch.dict(
        "os.environ",
        {
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@example.com",
            "SMTP_PASS": "password123",
            "SMTP_FROM": "noreply@example.com",
        },
    ):
        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

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


def test_send_email_uses_environment_variables():
    """Test that send_email uses environment variables for configuration."""
    from utils.email import send_email

    custom_host = "custom.smtp.com"
    custom_port = "2525"
    custom_from = "custom@example.com"

    with patch.dict(
        "os.environ", {"SMTP_HOST": custom_host, "SMTP_PORT": custom_port, "SMTP_FROM": custom_from}
    ):
        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            send_email(to_email="test@example.com", subject="Test", html_body="<p>Test</p>")

            # Verify SMTP was created with custom host and port
            mock_smtp.assert_called_once_with(custom_host, 2525)
