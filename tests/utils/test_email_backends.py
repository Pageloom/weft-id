"""Tests for email backends."""

import smtplib
from unittest.mock import MagicMock, patch


class TestSMTPBackend:
    """Tests for SMTP email backend."""

    def test_send_success(self):
        """Test successful email sending via SMTP."""
        from utils.email_backends.smtp import SMTPBackend

        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            backend = SMTPBackend()
            result = backend.send(
                to_email="test@example.com",
                subject="Test Subject",
                html_body="<p>Test HTML</p>",
                text_body="Test Text",
            )

            assert result is True
            mock_smtp.assert_called_once()
            mock_server.send_message.assert_called_once()

    def test_send_without_text_body(self):
        """Test sending email with only HTML body via SMTP."""
        from utils.email_backends.smtp import SMTPBackend

        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            backend = SMTPBackend()
            result = backend.send(
                to_email="test@example.com",
                subject="Test Subject",
                html_body="<p>Test HTML</p>",
            )

            assert result is True
            mock_server.send_message.assert_called_once()

    def test_send_with_tls(self, mocker):
        """Test SMTP sending with TLS enabled."""
        from utils.email_backends.smtp import SMTPBackend

        mocker.patch("settings.SMTP_TLS", True)
        mocker.patch("settings.SMTP_USER", "user@example.com")
        mocker.patch("settings.SMTP_PASS", "password")
        mock_smtp = mocker.patch("smtplib.SMTP")

        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        backend = SMTPBackend()
        result = backend.send(
            to_email="test@example.com",
            subject="Test",
            html_body="<p>Test</p>",
        )

        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once()

    def test_send_failure(self):
        """Test SMTP sending failure handling."""
        from utils.email_backends.smtp import SMTPBackend

        with patch("smtplib.SMTP") as mock_smtp:
            mock_smtp.side_effect = smtplib.SMTPException("Connection failed")

            backend = SMTPBackend()
            result = backend.send(
                to_email="test@example.com",
                subject="Test",
                html_body="<p>Test</p>",
            )

            assert result is False


class TestResendBackend:
    """Tests for Resend email backend."""

    def test_send_success(self):
        """Test successful email sending via Resend."""
        with patch("resend.Emails.send") as mock_send:
            mock_send.return_value = {"id": "email-123"}

            from utils.email_backends.resend_backend import ResendBackend

            backend = ResendBackend()
            result = backend.send(
                to_email="test@example.com",
                subject="Test Subject",
                html_body="<p>Test HTML</p>",
                text_body="Test Text",
            )

            assert result is True
            mock_send.assert_called_once()
            email_params = mock_send.call_args[0][0]
            assert email_params["to"] == "test@example.com"
            assert email_params["subject"] == "Test Subject"
            assert email_params["html"] == "<p>Test HTML</p>"
            assert email_params["text"] == "Test Text"

    def test_send_without_text_body(self):
        """Test sending via Resend without text body."""
        with patch("resend.Emails.send") as mock_send:
            mock_send.return_value = {"id": "email-123"}

            from utils.email_backends.resend_backend import ResendBackend

            backend = ResendBackend()
            result = backend.send(
                to_email="test@example.com",
                subject="Test Subject",
                html_body="<p>Test HTML</p>",
            )

            assert result is True
            email_params = mock_send.call_args[0][0]
            assert "text" not in email_params

    def test_send_failure(self):
        """Test Resend sending failure handling."""
        with patch("resend.Emails.send") as mock_send:
            mock_send.side_effect = Exception("API Error")

            from utils.email_backends.resend_backend import ResendBackend

            backend = ResendBackend()
            result = backend.send(
                to_email="test@example.com",
                subject="Test",
                html_body="<p>Test</p>",
            )

            assert result is False


class TestSendGridBackend:
    """Tests for SendGrid email backend."""

    def test_send_success(self):
        """Test successful email sending via SendGrid."""
        with patch("utils.email_backends.sendgrid_backend.SendGridAPIClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.send.return_value = MagicMock(status_code=202)

            from utils.email_backends.sendgrid_backend import SendGridBackend

            backend = SendGridBackend()
            result = backend.send(
                to_email="test@example.com",
                subject="Test Subject",
                html_body="<p>Test HTML</p>",
                text_body="Test Text",
            )

            assert result is True
            mock_client.send.assert_called_once()

    def test_send_without_text_body(self):
        """Test SendGrid sending without text body."""
        with patch("utils.email_backends.sendgrid_backend.SendGridAPIClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.send.return_value = MagicMock(status_code=202)

            from utils.email_backends.sendgrid_backend import SendGridBackend

            backend = SendGridBackend()
            result = backend.send(
                to_email="test@example.com",
                subject="Test Subject",
                html_body="<p>Test HTML</p>",
            )

            assert result is True
            mock_client.send.assert_called_once()

    def test_send_failure(self):
        """Test SendGrid sending failure handling."""
        with patch("utils.email_backends.sendgrid_backend.SendGridAPIClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.send.side_effect = Exception("API Error")

            from utils.email_backends.sendgrid_backend import SendGridBackend

            backend = SendGridBackend()
            result = backend.send(
                to_email="test@example.com",
                subject="Test",
                html_body="<p>Test</p>",
            )

            assert result is False


class TestBackendSelection:
    """Tests for email backend selection."""

    def test_default_backend_is_smtp(self):
        """Test that default backend is SMTP."""
        with patch("settings.EMAIL_BACKEND", "smtp"):
            # Reset the cached backend
            import utils.email_backends

            utils.email_backends._backend_instance = None

            from utils.email_backends import get_backend
            from utils.email_backends.smtp import SMTPBackend

            backend = get_backend()
            assert isinstance(backend, SMTPBackend)

            # Clean up
            utils.email_backends._backend_instance = None

    def test_resend_backend_selection(self, mocker):
        """Test Resend backend selection."""
        mocker.patch("settings.EMAIL_BACKEND", "resend")
        mocker.patch("resend.api_key", "test-key")

        # Reset the cached backend
        import utils.email_backends

        utils.email_backends._backend_instance = None

        from utils.email_backends import get_backend
        from utils.email_backends.resend_backend import ResendBackend

        backend = get_backend()
        assert isinstance(backend, ResendBackend)

        # Clean up
        utils.email_backends._backend_instance = None

    def test_sendgrid_backend_selection(self, mocker):
        """Test SendGrid backend selection."""
        mocker.patch("settings.EMAIL_BACKEND", "sendgrid")
        mocker.patch("sendgrid.SendGridAPIClient")

        # Reset the cached backend
        import utils.email_backends

        utils.email_backends._backend_instance = None

        from utils.email_backends import get_backend
        from utils.email_backends.sendgrid_backend import SendGridBackend

        backend = get_backend()
        assert isinstance(backend, SendGridBackend)

        # Clean up
        utils.email_backends._backend_instance = None

    def test_unknown_backend_defaults_to_smtp(self):
        """Test that unknown backend type defaults to SMTP."""
        with patch("settings.EMAIL_BACKEND", "unknown_backend"):
            # Reset the cached backend
            import utils.email_backends

            utils.email_backends._backend_instance = None

            from utils.email_backends import get_backend
            from utils.email_backends.smtp import SMTPBackend

            backend = get_backend()
            assert isinstance(backend, SMTPBackend)

            # Clean up
            utils.email_backends._backend_instance = None

    def test_backend_is_cached(self):
        """Test that backend instance is cached."""
        with patch("settings.EMAIL_BACKEND", "smtp"):
            # Reset the cached backend
            import utils.email_backends

            utils.email_backends._backend_instance = None

            from utils.email_backends import get_backend

            backend1 = get_backend()
            backend2 = get_backend()

            assert backend1 is backend2

            # Clean up
            utils.email_backends._backend_instance = None
