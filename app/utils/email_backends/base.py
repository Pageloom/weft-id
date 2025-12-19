"""Base email backend protocol."""

from typing import Protocol


class EmailBackend(Protocol):
    """Protocol for email backends."""

    def send(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str | None = None,
    ) -> bool:
        """
        Send an email.

        Args:
            to_email: Recipient email address
            subject: Email subject line
            html_body: HTML content of the email
            text_body: Optional plain text content

        Returns:
            True on success, False on failure
        """
        ...
