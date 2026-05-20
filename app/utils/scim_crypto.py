"""Outbound SCIM bearer-token encryption.

Mirror of the SAML/MFA secret pattern in `app/utils/saml.py` and
`app/utils/mfa.py`: derive a Fernet key from the master `SECRET_KEY` via
HKDF with a purpose-specific info string, and use module-level cipher
helpers to encrypt/decrypt the plaintext token before/after the database.

The plaintext is only seen at credential creation/rotation (admin UI) and
at outbound push time (worker). Storage is `BYTEA` for portability across
encoding choices.
"""

from cryptography.fernet import Fernet, InvalidToken
from utils.crypto import derive_fernet_key

_cipher = Fernet(derive_fernet_key(b"scim-credential"))


def encrypt_token(plaintext: str) -> bytes:
    """Encrypt a SCIM bearer token for storage.

    Returns the raw Fernet ciphertext bytes (suitable for a BYTEA column).
    """
    return _cipher.encrypt(plaintext.encode("utf-8"))


def decrypt_token(ciphertext: bytes) -> str:
    """Decrypt a stored SCIM bearer token back to plaintext.

    Raises:
        InvalidToken: if the ciphertext is corrupted or was encrypted
            under a different key (most often: the `SECRET_KEY` changed).
    """
    return _cipher.decrypt(ciphertext).decode("utf-8")


# Re-exported so callers can catch the decrypt-failure case without
# importing cryptography directly.
__all__ = ["InvalidToken", "decrypt_token", "encrypt_token"]
