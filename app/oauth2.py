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
