"""Resend email backend."""

import logging

import resend
import settings

logger = logging.getLogger(__name__)


class ResendBackend:
    """Email backend using Resend API (HTTPS)."""

    def __init__(self):
        """Initialize Resend with API key."""
        resend.api_key = settings.RESEND_API_KEY

    def send(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str | None = None,
    ) -> bool:
        """Send an email via Resend API."""
        try:
            params = {
                "from": settings.FROM_EMAIL,
                "to": to_email,
                "subject": subject,
                "html": html_body,
            }
            if text_body:
                params["text"] = text_body

            resend.Emails.send(params)  # type: ignore[arg-type]
            logger.info(f"Email sent to {to_email}: {subject}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email via Resend to {to_email}: {e}")
            return False
