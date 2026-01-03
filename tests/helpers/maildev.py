"""Helper module for interacting with maildev in e2e tests.

Maildev provides both an SMTP server (for the app to send emails) and a REST API
(for tests to retrieve sent emails). This module wraps the REST API.

API endpoints (default port 1080):
- GET /email - List all emails
- GET /email/:id - Get specific email
- DELETE /email/all - Clear all emails
"""

import re
import time

import requests

MAILDEV_API = "http://127.0.0.1:1080"


def is_available() -> bool:
    """Check if maildev is running and accessible."""
    try:
        response = requests.get(f"{MAILDEV_API}/email", timeout=1)
        return response.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False


def clear_emails() -> None:
    """Clear all emails from maildev inbox."""
    requests.delete(f"{MAILDEV_API}/email/all", timeout=5)


def get_emails(to: str | None = None) -> list[dict]:
    """Get all emails, optionally filtered by recipient.

    Args:
        to: If provided, filter to emails containing this address in 'to' field

    Returns:
        List of email dictionaries from maildev
    """
    response = requests.get(f"{MAILDEV_API}/email", timeout=5)
    emails = response.json()

    if to:
        # Filter by recipient - maildev stores 'to' as list of address objects
        filtered = []
        for email in emails:
            to_addresses = email.get("to", [])
            for addr in to_addresses:
                if to.lower() in addr.get("address", "").lower():
                    filtered.append(email)
                    break
        return filtered

    return emails


def get_latest_email(to: str, timeout: float = 5.0) -> dict | None:
    """Wait for and return the latest email to a recipient.

    Polls maildev until an email arrives or timeout is reached.

    Args:
        to: Recipient email address to filter by
        timeout: Maximum seconds to wait for email

    Returns:
        The latest email dict, or None if timeout reached
    """
    start = time.time()
    while time.time() - start < timeout:
        emails = get_emails(to)
        if emails:
            # Return most recent (last in list)
            return emails[-1]
        time.sleep(0.2)
    return None


def get_email_count(to: str | None = None) -> int:
    """Get count of emails, optionally filtered by recipient."""
    return len(get_emails(to))


def extract_otp_code(email: dict) -> str | None:
    """Extract 6-digit OTP code from email body.

    Searches both text and HTML body for a 6-digit number.

    Args:
        email: Email dict from maildev

    Returns:
        The 6-digit code as string, or None if not found
    """
    # Try text body first, fall back to HTML
    text = email.get("text", "") or ""
    html = email.get("html", "") or ""
    body = text or html

    # Look for a standalone 6-digit number
    match = re.search(r"\b(\d{6})\b", body)
    return match.group(1) if match else None
