"""SendGrid email backend."""

import logging

import settings
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Content, Mail

logger = logging.getLogger(__name__)


class SendGridBackend:
    """Email backend using SendGrid API (HTTPS)."""

    def __init__(self):
        """Initialize SendGrid client with API key."""
        self.client = SendGridAPIClient(settings.SENDGRID_API_KEY)  # outbound-timeout: ok
        self.client.timeout = 10

    def send(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str | None = None,
    ) -> bool:
        """Send an email via SendGrid API."""
        try:
            message = Mail(
                from_email=settings.FROM_EMAIL,
                to_emails=to_email,
                subject=subject,
            )
            message.add_content(Content("text/html", html_body))
            if text_body:
                message.add_content(Content("text/plain", text_body))

            self.client.send(message)
            logger.info(f"Email sent to {to_email}: {subject}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email via SendGrid to {to_email}: {e}")
            return False
