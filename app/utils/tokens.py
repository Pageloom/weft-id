"""Stateless time-windowed token generation.

Generates deterministic, time-windowed verification codes using HMAC-SHA256.
Codes are derived from a secret key, user identity, purpose, and the current
time window. No database storage is needed. Verification checks the current
window and a configurable number of adjacent windows.

    code = HMAC(derived_key, user_id + purpose + floor(time / step))

Optional state-based invalidation: when a `state` value is included in the
derivation input (e.g. password_changed_at), changing that state automatically
invalidates all outstanding codes without any explicit revocation.

Two token formats are available:

1. **6-digit codes** (`generate_code`/`verify_code`): For codes users type
   manually (MFA email codes).

2. **URL tokens** (`generate_url_token`/`verify_url_token`): For tokens
   embedded in URLs (password reset links). These encode the user_id and
   timestamp inside the token so the server can extract them without a
   database lookup.
"""

import base64
import hashlib
import hmac
import struct
import time

import settings
from utils.crypto import derive_hmac_key

# Purpose constants. Each purpose produces cryptographically independent codes,
# preventing a code generated for one purpose from being accepted for another.
PURPOSE_MFA_EMAIL = "mfa_email"
PURPOSE_PASSWORD_RESET = "password_reset"
PURPOSE_ACCOUNT_RECOVERY = "account_recovery"

# Derived HMAC key for all stateless token operations.
_token_key = derive_hmac_key("token")


def generate_code(
    user_id: str,
    purpose: str,
    step_seconds: int,
    state: str | None = None,
) -> str:
    """Generate a deterministic 6-digit verification code.

    The code is valid for the current time window (step_seconds). The same
    inputs in the same window always produce the same code.

    Args:
        user_id: The user this code is for.
        purpose: Purpose constant (e.g. PURPOSE_MFA_EMAIL).
        step_seconds: Length of each time window in seconds.
        state: Optional mutable state to bind the code to. Changing this
            value (e.g. updating password_changed_at) silently invalidates
            all codes generated with the old state.

    Returns:
        A zero-padded 6-digit numeric string.
    """
    time_step = int(time.time()) // step_seconds
    return _compute_code(user_id, purpose, time_step, state)


def verify_code(
    code: str,
    user_id: str,
    purpose: str,
    step_seconds: int,
    window: int = 3,
    state: str | None = None,
) -> bool:
    """Verify a submitted code against the current and adjacent time windows.

    Args:
        code: The 6-digit code to verify.
        user_id: The user this code should belong to.
        purpose: Purpose constant (must match generation).
        step_seconds: Length of each time window in seconds.
        window: Number of adjacent windows to check in each direction.
            Total codes checked = 2 * window + 1.
        state: Optional mutable state (must match what was used at generation).

    Returns:
        True if the code matches any valid window, False otherwise.
    """
    if settings.BYPASS_OTP and len(code) == 6 and code.isdigit():
        return True

    current_step = int(time.time()) // step_seconds

    for offset in range(-window, window + 1):
        expected = _compute_code(user_id, purpose, current_step + offset, state)
        if hmac.compare_digest(code, expected):
            return True

    return False


def _compute_code(
    user_id: str,
    purpose: str,
    time_step: int,
    state: str | None,
) -> str:
    """Compute a 6-digit code for a specific time step.

    Uses HMAC-SHA256 with dynamic truncation (RFC 4226 HOTP algorithm)
    to produce a 6-digit decimal code.
    """
    message = f"{user_id}:{purpose}:{time_step}"
    if state is not None:
        message = f"{message}:{state}"

    digest = hmac.new(_token_key, message.encode(), hashlib.sha256).digest()

    # Dynamic truncation (RFC 4226 section 5.4)
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF

    return str(truncated % 1_000_000).zfill(6)


# ---------------------------------------------------------------------------
# URL tokens: for links embedded in emails (e.g. password reset)
# ---------------------------------------------------------------------------


def generate_url_token(
    user_id: str,
    purpose: str,
    ttl_seconds: int = 1800,
    state: str | None = None,
) -> str:
    """Generate a URL-safe token embedding user_id and a timestamp.

    The token format is ``base64url(user_id.timestamp.hmac_hex)``.
    The HMAC covers user_id, purpose, timestamp, and optional state,
    so tampering with any field invalidates the token.

    Args:
        user_id: The user this token is for.
        purpose: Purpose constant (e.g. PURPOSE_PASSWORD_RESET).
        ttl_seconds: How long the token is valid (default 30 minutes).
        state: Optional mutable state for automatic invalidation.

    Returns:
        A URL-safe base64-encoded token string.
    """
    timestamp = int(time.time())
    mac = _compute_url_hmac(user_id, purpose, timestamp, state)
    payload = f"{user_id}.{timestamp}.{mac}"
    return base64.urlsafe_b64encode(payload.encode()).decode()


def verify_url_token(
    token: str,
    purpose: str,
    ttl_seconds: int = 1800,
    state: str | None = None,
) -> str | None:
    """Verify a URL token and return the embedded user_id.

    Args:
        token: The base64url-encoded token to verify.
        purpose: Purpose constant (must match generation).
        ttl_seconds: Maximum age in seconds (default 30 minutes).
        state: Optional mutable state (must match what was used at generation).

    Returns:
        The user_id if the token is valid, or None if invalid/expired.
    """
    parts = _decode_url_token(token)
    if parts is None:
        return None

    user_id, timestamp, mac = parts

    # Check expiry
    if int(time.time()) - timestamp > ttl_seconds:
        return None

    # Recompute and compare HMAC
    expected = _compute_url_hmac(user_id, purpose, timestamp, state)
    if not hmac.compare_digest(mac, expected):
        return None

    return user_id


def extract_user_id_from_url_token(token: str) -> str | None:
    """Extract the user_id from a URL token without cryptographic verification.

    This is used to look up user state (e.g. password_changed_at) before
    calling verify_url_token with the state parameter.

    Args:
        token: The base64url-encoded token.

    Returns:
        The user_id string, or None if the token is malformed.
    """
    parts = _decode_url_token(token)
    return parts[0] if parts else None


def _decode_url_token(token: str) -> tuple[str, int, str] | None:
    """Decode a URL token into (user_id, timestamp, hmac_hex).

    Returns None if the token is malformed.
    """
    try:
        # Add padding if needed
        padded = token + "=" * (-len(token) % 4)
        payload = base64.urlsafe_b64decode(padded).decode()
        parts = payload.split(".")
        if len(parts) != 3:
            return None
        user_id, ts_str, mac = parts
        timestamp = int(ts_str)
        return user_id, timestamp, mac
    except (ValueError, UnicodeDecodeError):
        return None


def _compute_url_hmac(
    user_id: str,
    purpose: str,
    timestamp: int,
    state: str | None,
) -> str:
    """Compute the HMAC for a URL token."""
    message = f"{user_id}:{purpose}:{timestamp}"
    if state is not None:
        message = f"{message}:{state}"
    return hmac.new(_token_key, message.encode(), hashlib.sha256).hexdigest()
