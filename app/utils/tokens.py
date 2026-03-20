"""Stateless time-windowed token generation.

Generates deterministic, time-windowed verification codes using HMAC-SHA256.
Codes are derived from a secret key, user identity, purpose, and the current
time window. No database storage is needed. Verification checks the current
window and a configurable number of adjacent windows.

    code = HMAC(derived_key, user_id + purpose + floor(time / step))

Optional state-based invalidation: when a `state` value is included in the
derivation input (e.g. password_changed_at), changing that state automatically
invalidates all outstanding codes without any explicit revocation.
"""

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
