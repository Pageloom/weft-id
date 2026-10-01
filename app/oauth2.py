"""OAuth2 core utilities for token generation, hashing, and PKCE verification."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import settings
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Argon2 hasher (same as used for passwords)
_hasher = PasswordHasher()

# Token expiry timedeltas
AUTHORIZATION_CODE_EXPIRY = timedelta(seconds=settings.OAUTH2_AUTHORIZATION_CODE_EXPIRY)
ACCESS_TOKEN_EXPIRY = timedelta(seconds=settings.OAUTH2_ACCESS_TOKEN_EXPIRY)
REFRESH_TOKEN_EXPIRY = timedelta(seconds=settings.OAUTH2_REFRESH_TOKEN_EXPIRY)
CLIENT_CREDENTIALS_TOKEN_EXPIRY = timedelta(seconds=settings.OAUTH2_CLIENT_CREDENTIALS_TOKEN_EXPIRY)

# RFC 8628 section 3.4: the device authorization grant's grant_type value.
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

# Device authorization grant (RFC 8628): how long a device code lives and the
# default polling interval the device is told to keep.
DEVICE_CODE_EXPIRY = timedelta(minutes=10)
DEVICE_POLL_INTERVAL_SECONDS = 5

# RFC 8628 section 6.1: a user code alphabet of consonants only (no vowels, so
# no words are spelled; no easily confused characters), 8 characters long,
# shown as two groups of four.
USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"
USER_CODE_LENGTH = 8


def generate_opaque_token(prefix: str = "weft-id") -> str:
    """
    Generate a cryptographically secure random opaque token.

    Args:
        prefix: Optional prefix for the token (default: "weft-id")

    Returns:
        Opaque token string in format "{prefix}_{random_hex}"

    Example:
        "weft-id_3a7f8b2c1d4e5f6a7b8c9d0e1f2a3b4c"
    """
    random_bytes = secrets.token_bytes(32)  # 256 bits of entropy
    random_hex = random_bytes.hex()
    return f"{prefix}_{random_hex}"


def hash_token(token: str) -> str:
    """
    Hash a token using Argon2 (same algorithm as passwords).

    Args:
        token: Plain text token to hash

    Returns:
        Argon2 hash of the token

    Note:
        Tokens are hashed before storage to prevent leakage if database is compromised.
    """
    return _hasher.hash(token)


def token_lookup(token: str) -> str:
    """Compute the indexed lookup digest for an opaque token or authorization code.

    Args:
        token: Plain text opaque token/code (as produced by generate_opaque_token).

    Returns:
        Hex SHA-256 digest, stored in the token_lookup / code_lookup column.

    Note:
        This is a lookup key, NOT a credential store. Each opaque value already
        carries 256 bits of `secrets` entropy, so a fast unkeyed digest is not
        brute-forceable and lets validation resolve exactly one row instead of
        Argon2-verifying every live token in the tenant. The slow Argon2 hash
        (hash_token / verify_token_hash) is still applied to that single
        candidate row, so a database dump cannot be replayed.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def verify_token_hash(token: str, token_hash: str) -> bool:
    """
    Verify a token against its stored hash.

    Args:
        token: Plain text token to verify
        token_hash: Argon2 hash to verify against

    Returns:
        True if token matches hash, False otherwise
    """
    try:
        _hasher.verify(token_hash, token)
        return True
    except VerifyMismatchError:
        return False


def verify_pkce_challenge(code_verifier: str, code_challenge: str, method: str) -> bool:
    """
    Verify PKCE code challenge using the provided method.

    PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks.
    See RFC 7636: https://tools.ietf.org/html/rfc7636

    Args:
        code_verifier: The code verifier submitted during token exchange
        code_challenge: The code challenge submitted during authorization
        method: Challenge method - "S256" (SHA-256) or "plain"

    Returns:
        True if verification succeeds, False otherwise

    Methods:
        - "S256": code_challenge = BASE64URL(SHA256(code_verifier))
        - "plain": code_challenge = code_verifier
    """
    if method == "plain":
        return code_verifier == code_challenge
    elif method == "S256":
        # Compute SHA-256 hash of code_verifier
        verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
        # Base64url encode (without padding)
        import base64

        computed_challenge = base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")
        return computed_challenge == code_challenge
    else:
        # Unknown method
        return False


def generate_client_id(prefix: str = "weft-id_client") -> str:
    """
    Generate a unique client ID for OAuth2 client registration.

    Args:
        prefix: Prefix for client ID (default: "weft-id_client")

    Returns:
        Client ID string in format "{prefix}_{random_hex}"

    Example:
        "weft-id_client_a1b2c3d4e5f6"
    """
    random_bytes = secrets.token_bytes(12)  # 96 bits
    random_hex = random_bytes.hex()
    return f"{prefix}_{random_hex}"


def generate_client_secret() -> str:
    """
    Generate a cryptographically secure client secret.

    Returns:
        Client secret string (64 character hex)

    Note:
        This is returned to the admin ONCE during client creation.
        The hash is stored, not the plain text secret.
    """
    return secrets.token_hex(32)  # 64 character hex string


def generate_user_code() -> str:
    """Generate a device-flow user code (RFC 8628 section 6.1).

    Returns:
        Eight characters from ``USER_CODE_ALPHABET`` without separator. Use
        ``format_user_code`` to display it.
    """
    return "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LENGTH))


def normalize_user_code(value: str) -> str | None:
    """Normalise what a person typed into a stored-form user code.

    Upper-cases and drops separators (dashes and whitespace). Returns None
    when the result is not exactly ``USER_CODE_LENGTH`` characters from the
    alphabet, so a lookup is never attempted for a malformed code.
    """
    cleaned = "".join(ch for ch in value.upper() if ch not in "- \t")
    if len(cleaned) != USER_CODE_LENGTH or any(ch not in USER_CODE_ALPHABET for ch in cleaned):
        return None
    return cleaned


def format_user_code(code: str) -> str:
    """Display form of a user code: ``BCDF-GHJK``."""
    half = len(code) // 2
    return f"{code[:half]}-{code[half:]}"


def calculate_expires_at(expiry_delta: timedelta) -> datetime:
    """
    Calculate expiration timestamp from current time + delta.

    Args:
        expiry_delta: Time delta for expiry

    Returns:
        UTC datetime when the token/code expires

    Note:
        Returns timezone-aware UTC datetime.
    """
    return datetime.now(UTC) + expiry_delta
