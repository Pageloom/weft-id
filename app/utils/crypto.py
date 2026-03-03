"""Centralized key derivation from a single master secret.

All purpose-specific keys are derived from settings.SECRET_KEY using
HKDF-SHA256 with different info parameters. This produces cryptographically
independent keys from a single master secret.
"""

import base64

import settings
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_fernet_key(info: bytes) -> bytes:
    """Derive a Fernet-compatible encryption key from the master secret.

    Uses HKDF-SHA256 with the given info parameter. Different info values
    produce completely independent keys.

    Args:
        info: Purpose identifier (e.g. b"mfa-encryption").

    Returns:
        Base64url-encoded 32-byte key suitable for Fernet.
    """
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    key_bytes = hkdf.derive(settings.SECRET_KEY.encode())
    return base64.urlsafe_b64encode(key_bytes)


def derive_session_key() -> str:
    """Derive a session signing key from the master secret.

    Returns a hex-encoded string suitable for Starlette's SessionMiddleware.
    """
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"session-signing",
    )
    return hkdf.derive(settings.SECRET_KEY.encode()).hex()
