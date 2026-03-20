"""Multi-factor authentication utilities."""

import hashlib
import secrets

import database
import pyotp
import settings
from cryptography.fernet import Fernet
from utils.crypto import derive_fernet_key
from utils.tokens import PURPOSE_MFA_EMAIL, generate_code, verify_code

_cipher = Fernet(derive_fernet_key(b"mfa-encryption"))


def generate_totp_secret() -> str:
    """Generate a random TOTP secret (base32 encoded)."""
    return pyotp.random_base32()


def encrypt_secret(secret: str) -> str:
    """Encrypt a TOTP secret for storage."""
    return _cipher.encrypt(secret.encode()).decode()


def decrypt_secret(encrypted_secret: str) -> str:
    """Decrypt a TOTP secret from storage."""
    return _cipher.decrypt(encrypted_secret.encode()).decode()


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verify a TOTP code against a secret.
    Returns True if valid, False otherwise.
    """
    # Bypass mode: accept any valid 6-digit code
    if settings.BYPASS_OTP and len(code) == 6 and code.isdigit():
        return True

    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # Allow 1 step window (30 sec before/after)


def generate_totp_uri(secret: str, email: str, issuer: str = "PageLoom") -> str:
    """
    Generate otpauth:// URI for TOTP setup.
    Can be used for QR codes or direct password manager import.
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)


def format_secret_for_display(secret: str) -> str:
    """
    Format secret for display (add dashes for readability).
    Example: ABCDEFGHIJKLMNOP -> ABCD-EFGH-IJKL-MNOP
    """
    return "-".join([secret[i : i + 4] for i in range(0, len(secret), 4)])


def generate_backup_codes(count: int = 10) -> list[str]:
    """
    Generate backup codes for account recovery.
    Returns list of human-readable codes.
    """
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric code
        code = secrets.token_hex(4).upper()
        # Format as XXXX-XXXX
        formatted = f"{code[:4]}-{code[4:]}"
        codes.append(formatted)
    return codes


def hash_code(code: str) -> str:
    """
    Hash a backup code for storage.
    Uses SHA-256 (codes are random, not user passwords).
    """
    return hashlib.sha256(code.encode()).hexdigest()


def verify_backup_code(tenant_id: str, user_id: str, code: str) -> bool:
    """
    Verify a backup code and mark it as used.
    Returns True if valid, False otherwise.
    """
    code_hash = hash_code(code.upper().replace("-", ""))
    return database.mfa.verify_backup_code(tenant_id, user_id, code_hash)


def create_email_otp(tenant_id: str, user_id: str, expiry_minutes: int = 10) -> str:
    """Generate a time-windowed email OTP code.

    Uses stateless HMAC-based generation. The code is deterministic for the
    current time window (5 minutes). No database storage is needed.

    Args:
        tenant_id: Tenant ID (retained for API compatibility, not used).
        user_id: User ID to bind the code to.
        expiry_minutes: Retained for API compatibility, not used. The code
            validity is controlled by the time window and verify_code window.

    Returns:
        A 6-digit numeric code to be sent via email.
    """
    return generate_code(user_id, PURPOSE_MFA_EMAIL, step_seconds=300)


def verify_email_otp(tenant_id: str, user_id: str, code: str) -> bool:
    """Verify an email OTP code against the current time window.

    Checks the submitted code against the current window and one adjacent
    window in each direction (total coverage: ~15 minutes with 5-minute steps).

    Args:
        tenant_id: Tenant ID (retained for API compatibility, not used).
        user_id: User ID the code was generated for.
        code: The 6-digit code to verify.

    Returns:
        True if valid, False otherwise.
    """
    return verify_code(code, user_id, PURPOSE_MFA_EMAIL, step_seconds=300, window=1)


def get_totp_secret(tenant_id: str, user_id: str, method: str) -> str | None:
    """
    Get and decrypt the user's TOTP secret for a specific method.
    Returns decrypted secret or None if not found.
    """
    row = database.mfa.get_verified_totp_secret(tenant_id, user_id, method)

    if not row:
        return None

    return decrypt_secret(row["secret_encrypted"])
