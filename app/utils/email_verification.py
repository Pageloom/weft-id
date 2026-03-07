"""Email possession verification utilities.

Provides cookie-based verification for email possession before revealing
account information (anti-enumeration protection).
"""

import hashlib
import hmac
import json
import secrets
import time

import settings
from cryptography.fernet import Fernet, InvalidToken
from utils.crypto import derive_fernet_key

_cipher = Fernet(derive_fernet_key(b"email-verification"))


def generate_verification_code() -> str:
    """Generate a 6-digit verification code."""
    return str(secrets.randbelow(1000000)).zfill(6)


def _hash_code(code: str) -> str:
    """Hash a verification code using SHA-256."""
    return hashlib.sha256(code.encode()).hexdigest()


def _constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(a, b)


def create_verification_cookie(email: str, code: str, tenant_id: str) -> str:
    """
    Create an encrypted verification cookie payload.

    The cookie contains:
    - Email address
    - Hashed verification code (not plaintext)
    - Tenant ID
    - Expiration timestamp
    - Creation timestamp

    Args:
        email: The email address to verify
        code: The plaintext 6-digit verification code
        tenant_id: The tenant ID

    Returns:
        Encrypted cookie payload as a string
    """
    expires_at = time.time() + settings.VERIFICATION_CODE_EXPIRY_SECONDS
    created_at = time.time()

    payload = {
        "email": email.lower(),
        "code_hash": _hash_code(code),
        "tenant_id": str(tenant_id),  # Ensure string for JSON serialization
        "expires_at": expires_at,
        "created_at": created_at,
    }

    json_payload = json.dumps(payload)
    encrypted = _cipher.encrypt(json_payload.encode())
    return encrypted.decode()


def validate_verification_cookie(
    cookie_value: str, entered_code: str, expected_email: str | None = None
) -> tuple[bool, str | None, str | None]:
    """
    Validate a verification cookie against an entered code.

    Args:
        cookie_value: The encrypted cookie payload
        entered_code: The code entered by the user
        expected_email: Optional email to validate against

    Returns:
        Tuple of (is_valid, email, tenant_id)
        - is_valid: True if code matches and not expired
        - email: The email from the cookie (or None if invalid)
        - tenant_id: The tenant ID from the cookie (or None if invalid)
    """
    try:
        decrypted = _cipher.decrypt(cookie_value.encode())
        payload = json.loads(decrypted.decode())
    except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError):
        return False, None, None

    # Check expiration
    if time.time() > payload.get("expires_at", 0):
        return False, None, None

    # Check email if provided
    email = payload.get("email")
    if expected_email and email != expected_email.lower():
        return False, None, None

    # Bypass mode: accept any valid 6-digit code
    if settings.BYPASS_OTP and len(entered_code) == 6 and entered_code.isdigit():
        return True, email, payload.get("tenant_id")

    # Verify code using constant-time comparison
    stored_hash = payload.get("code_hash", "")
    entered_hash = _hash_code(entered_code)

    if not _constant_time_compare(stored_hash, entered_hash):
        return False, None, None

    return True, email, payload.get("tenant_id")


def get_verification_cookie_email(cookie_value: str) -> str | None:
    """
    Extract the email from a verification cookie without validating the code.

    Useful for displaying which email the code was sent to.

    Args:
        cookie_value: The encrypted cookie payload

    Returns:
        The email address or None if cookie is invalid/expired
    """
    try:
        decrypted = _cipher.decrypt(cookie_value.encode())
        payload = json.loads(decrypted.decode())
    except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError):
        return None

    # Check expiration
    if time.time() > payload.get("expires_at", 0):
        return None

    email = payload.get("email")
    return str(email) if email else None


def _email_to_cookie_name(email: str) -> str:
    """Generate a cookie name suffix from an email address."""
    # Use first 8 chars of SHA-256 hash for uniqueness
    email_hash = hashlib.sha256(email.lower().encode()).hexdigest()[:8]
    return f"email_trust_{email_hash}"


def create_trust_cookie(email: str, tenant_id: str) -> str:
    """
    Create an encrypted trust cookie for a verified email.

    This allows skipping verification for 30 days on the same device.

    Args:
        email: The verified email address
        tenant_id: The tenant ID

    Returns:
        Encrypted cookie payload as a string
    """
    verified_at = time.time()

    payload = {
        "email": email.lower(),
        "tenant_id": str(tenant_id),  # Ensure string for JSON serialization
        "verified_at": verified_at,
    }

    json_payload = json.dumps(payload)
    encrypted = _cipher.encrypt(json_payload.encode())
    return encrypted.decode()


def validate_trust_cookie(cookie_value: str, email: str, tenant_id: str) -> bool:
    """
    Validate a trust cookie for a given email and tenant.

    Args:
        cookie_value: The encrypted cookie payload
        email: The email to check trust for
        tenant_id: The tenant ID

    Returns:
        True if the cookie is valid and matches the email/tenant
    """
    try:
        decrypted = _cipher.decrypt(cookie_value.encode())
        payload = json.loads(decrypted.decode())
    except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError):
        return False

    # Check if cookie belongs to this email and tenant
    if payload.get("email") != email.lower():
        return False
    if payload.get("tenant_id") != str(tenant_id):  # Compare as strings
        return False

    # Check expiration (30 days from verification)
    verified_at = payload.get("verified_at", 0)
    expiry_seconds = settings.TRUST_COOKIE_EXPIRY_DAYS * 24 * 60 * 60
    if time.time() > verified_at + expiry_seconds:
        return False

    return True


def get_trust_cookie_name(email: str) -> str:
    """
    Get the cookie name for a given email's trust cookie.

    Each email has its own trust cookie to support multiple accounts.

    Args:
        email: The email address

    Returns:
        The cookie name to use
    """
    return _email_to_cookie_name(email)
