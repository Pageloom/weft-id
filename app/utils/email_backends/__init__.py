"""Email backends package."""

import settings

from .base import EmailBackend
from .smtp import SMTPBackend

__all__ = ["EmailBackend", "get_backend"]

_backend_instance: EmailBackend | None = None


def get_backend() -> EmailBackend:
    """
    Get the configured email backend instance.

    Backend is selected via EMAIL_BACKEND environment variable:
    - "smtp" (default): SMTP backend
    - "resend": Resend API backend
    - "sendgrid": SendGrid API backend
    """
    global _backend_instance

    if _backend_instance is None:
        backend_type = settings.EMAIL_BACKEND.lower()

        if backend_type == "resend":
            from .resend_backend import ResendBackend

            _backend_instance = ResendBackend()
        elif backend_type == "sendgrid":
            from .sendgrid_backend import SendGridBackend

            _backend_instance = SendGridBackend()
        else:
            # Default to SMTP
            _backend_instance = SMTPBackend()

    return _backend_instance
