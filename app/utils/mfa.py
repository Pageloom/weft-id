"""Multi-factor authentication utilities."""

import base64
import datetime
import hashlib
import secrets

import database
import pyotp
import settings
from cryptography.fernet import Fernet


def _get_encryption_key() -> bytes:
    """Get or generate encryption key from settings."""
    key_str = settings.MFA_ENCRYPTION_KEY
    # Ensure the key is valid base64 and correct length for Fernet
    try:
        key_bytes = base64.urlsafe_b64decode(key_str)
        if len(key_bytes) == 32:
            return base64.urlsafe_b64encode(key_bytes)
    except Exception:
        pass
    # Fallback: derive from the string (not ideal but better than random)
    # Use first 32 bytes of SHA256 hash
    key_hash = hashlib.sha256(key_str.encode()).digest()
    return base64.urlsafe_b64encode(key_hash)


_cipher = Fernet(_get_encryption_key())


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
    Hash a backup code or email OTP for storage.
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


def generate_email_otp() -> str:
    """Generate a 6-digit OTP for email verification."""
    return str(secrets.randbelow(1000000)).zfill(6)


def create_email_otp(tenant_id: str, user_id: str, expiry_minutes: int = 10) -> str:
    """
    Create and store an email OTP code.
    Returns the plaintext code (to be sent via email).
    """
    code = generate_email_otp()
    code_hash = hash_code(code)
    expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=expiry_minutes)

    database.mfa.create_email_otp(tenant_id, user_id, code_hash, expires_at, tenant_id)

    return code


def verify_email_otp(tenant_id: str, user_id: str, code: str) -> bool:
    """
    Verify an email OTP code and mark it as used.
    Returns True if valid and not expired, False otherwise.
    """
    code_hash = hash_code(code)
    return database.mfa.verify_email_otp(tenant_id, user_id, code_hash)


def get_totp_secret(tenant_id: str, user_id: str, method: str) -> str | None:
    """
    Get and decrypt the user's TOTP secret for a specific method.
    Returns decrypted secret or None if not found.
    """
    row = database.mfa.get_verified_totp_secret(tenant_id, user_id, method)

    if not row:
        return None

    return decrypt_secret(row["secret_encrypted"])
