"""Password strength validation using zxcvbn and HIBP.

Provides NIST SP 800-63B-aligned password strength enforcement:
- Configurable minimum length (super_admin always >= 14)
- zxcvbn pattern-based strength scoring
- HIBP k-anonymity breach checking (fail-open on timeout)
"""

import hashlib
import hmac
import logging
from dataclasses import dataclass, field

import httpx
import zxcvbn as zxcvbn_lib  # type: ignore[import-untyped]

log = logging.getLogger(__name__)

HIBP_TIMEOUT_SECONDS = 3.0
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


@dataclass
class PasswordIssue:
    """A single password validation issue."""

    code: str
    message: str


@dataclass
class PasswordStrengthResult:
    """Result of password strength validation."""

    issues: list[PasswordIssue] = field(default_factory=list)
    zxcvbn_score: int = 0
    zxcvbn_crack_time: str = ""
    zxcvbn_feedback: dict = field(default_factory=dict)
    hibp_count: int = 0

    @property
    def is_valid(self) -> bool:
        return len(self.issues) == 0


def check_hibp(password: str) -> int:
    """Check if password appears in Have I Been Pwned database.

    Uses k-anonymity: only the first 5 chars of the SHA-1 hash are sent.

    Args:
        password: The password to check

    Returns:
        Number of times the password has been seen in breaches.
        Returns 0 on timeout or network error (fail-open).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        response = httpx.get(
            f"{HIBP_API_URL}{prefix}",
            timeout=HIBP_TIMEOUT_SECONDS,
            headers={"User-Agent": "WeftID-PasswordCheck"},
        )
        response.raise_for_status()
    except (httpx.HTTPError, httpx.TimeoutException):
        log.warning("HIBP API unreachable, skipping breach check")
        return 0

    for line in response.text.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip() == suffix:
            return int(count.strip())

    return 0


def validate_password(
    password: str,
    minimum_length: int = 14,
    minimum_score: int = 3,
    user_role: str | None = None,
    user_inputs: list[str] | None = None,
) -> PasswordStrengthResult:
    """Validate password strength against policy.

    Three checks are applied:
    1. Length: must meet minimum_length (super_admin always >= 14)
    2. zxcvbn score: must meet minimum_score
    3. HIBP breach check: password must not appear in known breaches

    Args:
        password: The password to validate
        minimum_length: Tenant-configured minimum length
        minimum_score: Tenant-configured minimum zxcvbn score (3 or 4)
        user_role: User's role (super_admin gets stricter length floor)
        user_inputs: Additional inputs for zxcvbn (email, name parts)

    Returns:
        PasswordStrengthResult with issues list and scoring details
    """
    result = PasswordStrengthResult()

    # Super admins always require at least 14 characters
    effective_length = minimum_length
    if user_role == "super_admin" and effective_length < 14:
        effective_length = 14

    # Check 1: Length
    if len(password) < effective_length:
        result.issues.append(
            PasswordIssue(
                code="password_too_short",
                message=f"Password must be at least {effective_length} characters long.",
            )
        )

    # Check 2: zxcvbn score
    zxcvbn_result = zxcvbn_lib.zxcvbn(password, user_inputs=user_inputs or [])
    result.zxcvbn_score = zxcvbn_result["score"]
    result.zxcvbn_crack_time = zxcvbn_result["crack_times_display"][
        "offline_slow_hashing_1e4_per_second"
    ]
    result.zxcvbn_feedback = zxcvbn_result.get("feedback", {})

    if zxcvbn_result["score"] < minimum_score:
        feedback = zxcvbn_result.get("feedback", {})
        suggestion = ""
        if feedback.get("warning"):
            suggestion = f" {feedback['warning']}."
        elif feedback.get("suggestions"):
            suggestion = f" {feedback['suggestions'][0]}"
        result.issues.append(
            PasswordIssue(
                code="password_too_weak",
                message=f"Password is not strong enough.{suggestion}",
            )
        )

    # Check 3: HIBP breach check
    hibp_count = check_hibp(password)
    result.hibp_count = hibp_count
    if hibp_count > 0:
        result.issues.append(
            PasswordIssue(
                code="password_breached",
                message=(
                    "This password has appeared in a known data breach. "
                    "Please choose a different password."
                ),
            )
        )

    return result


def compute_hibp_monitoring_data(password: str, hmac_key: bytes) -> tuple[str, str]:
    """Compute HIBP monitoring data for continuous breach detection.

    Stores two values at password-set time:
    - prefix: first 5 hex chars of SHA-1 (sent to HIBP API)
    - check_hmac: HMAC-SHA256 of the full SHA-1, keyed with an HKDF-derived
      key. The HMAC cannot be reversed even with the key.

    Args:
        password: The plaintext password (before hashing for storage)
        hmac_key: HKDF-derived key for HMAC computation

    Returns:
        Tuple of (prefix, check_hmac_hex)
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    prefix = sha1[:5]
    check_hmac = hmac.new(hmac_key, sha1.encode(), hashlib.sha256).hexdigest()
    return prefix, check_hmac


def check_hibp_suffix_against_hmac(
    prefix: str,
    stored_hmac: str,
    hmac_key: bytes,
    suffixes: list[str],
) -> bool:
    """Check if any HIBP-returned suffix matches the stored HMAC.

    Called by the background job after querying the HIBP API with a prefix.
    Reconstructs the full SHA-1 from prefix + each suffix, computes its HMAC,
    and compares against the stored value.

    Args:
        prefix: The stored 5-char SHA-1 prefix
        stored_hmac: The stored HMAC-SHA256 hex string
        hmac_key: HKDF-derived key for HMAC computation
        suffixes: List of SHA-1 suffixes returned by HIBP API

    Returns:
        True if a match is found (password is breached)
    """
    for suffix in suffixes:
        candidate_sha1 = (prefix + suffix).upper()
        candidate_hmac = hmac.new(hmac_key, candidate_sha1.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(candidate_hmac, stored_hmac):
            return True
    return False
