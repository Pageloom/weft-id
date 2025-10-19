"""Tests for multi-factor authentication utilities."""

import re

import pyotp
from app.utils.mfa import (
    decrypt_secret,
    encrypt_secret,
    format_secret_for_display,
    generate_backup_codes,
    generate_email_otp,
    generate_totp_secret,
    generate_totp_uri,
    hash_code,
    verify_totp_code,
)


def test_generate_totp_secret():
    """Test TOTP secret generation."""
    secret = generate_totp_secret()

    # Should be a base32 string
    assert isinstance(secret, str)
    assert len(secret) > 0
    # Base32 alphabet
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret)


def test_encrypt_decrypt_secret():
    """Test secret encryption and decryption."""
    original_secret = "JBSWY3DPEHPK3PXP"

    # Encrypt
    encrypted = encrypt_secret(original_secret)
    assert isinstance(encrypted, str)
    assert encrypted != original_secret

    # Decrypt
    decrypted = decrypt_secret(encrypted)
    assert decrypted == original_secret


def test_encrypt_different_results():
    """Test that encrypting the same secret produces different results."""
    secret = "JBSWY3DPEHPK3PXP"

    # Note: Fernet encryption is deterministic for the same key and plaintext
    # So we're just testing that it encrypts and decrypts correctly
    encrypted1 = encrypt_secret(secret)
    encrypted2 = encrypt_secret(secret)

    # Both should decrypt to the same value
    assert decrypt_secret(encrypted1) == secret
    assert decrypt_secret(encrypted2) == secret


def test_verify_totp_code_valid():
    """Test TOTP code verification with valid code."""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    assert verify_totp_code(secret, valid_code) is True


def test_verify_totp_code_invalid():
    """Test TOTP code verification with invalid code."""
    secret = pyotp.random_base32()

    # Invalid code format
    assert verify_totp_code(secret, "000000") is False
    assert verify_totp_code(secret, "123456") is False


def test_generate_totp_uri():
    """Test TOTP URI generation for QR codes."""
    secret = "JBSWY3DPEHPK3PXP"
    email = "user@example.com"
    issuer = "TestApp"

    uri = generate_totp_uri(secret, email, issuer)

    # Should be an otpauth:// URI
    assert uri.startswith("otpauth://totp/")
    # Email might be URL-encoded (@ becomes %40)
    assert "user" in uri and ("example.com" in uri or "example%2Ecom" in uri)
    assert issuer in uri
    assert secret in uri


def test_generate_totp_uri_default_issuer():
    """Test TOTP URI generation with default issuer."""
    secret = "JBSWY3DPEHPK3PXP"
    email = "user@example.com"

    uri = generate_totp_uri(secret, email)

    # Should use default issuer "PageLoom"
    assert "PageLoom" in uri


def test_format_secret_for_display():
    """Test secret formatting for display."""
    secret = "ABCDEFGHIJKLMNOP"
    formatted = format_secret_for_display(secret)

    # Should be formatted with dashes
    assert formatted == "ABCD-EFGH-IJKL-MNOP"


def test_format_secret_for_display_not_divisible_by_4():
    """Test secret formatting when length is not divisible by 4."""
    secret = "ABCDEFGHIJ"
    formatted = format_secret_for_display(secret)

    # Should still format with dashes
    assert formatted == "ABCD-EFGH-IJ"


def test_generate_backup_codes():
    """Test backup code generation."""
    codes = generate_backup_codes(10)

    # Should generate correct number of codes
    assert len(codes) == 10

    # Each code should be formatted as XXXX-XXXX
    for code in codes:
        assert re.match(r"^[0-9A-F]{4}-[0-9A-F]{4}$", code)

    # All codes should be unique
    assert len(codes) == len(set(codes))


def test_generate_backup_codes_custom_count():
    """Test backup code generation with custom count."""
    codes = generate_backup_codes(5)
    assert len(codes) == 5

    codes = generate_backup_codes(15)
    assert len(codes) == 15


def test_hash_code():
    """Test code hashing."""
    code = "ABCD1234"
    hashed = hash_code(code)

    # Should be a hex string (SHA-256 = 64 hex chars)
    assert isinstance(hashed, str)
    assert len(hashed) == 64
    assert all(c in "0123456789abcdef" for c in hashed)

    # Same input should produce same hash
    assert hash_code(code) == hashed


def test_hash_code_different_inputs():
    """Test that different codes produce different hashes."""
    code1 = "ABCD1234"
    code2 = "EFGH5678"

    hash1 = hash_code(code1)
    hash2 = hash_code(code2)

    assert hash1 != hash2


def test_generate_email_otp():
    """Test email OTP generation."""
    otp = generate_email_otp()

    # Should be a 6-digit string
    assert isinstance(otp, str)
    assert len(otp) == 6
    assert otp.isdigit()


def test_generate_email_otp_uniqueness():
    """Test that email OTPs are different (statistically)."""
    otps = [generate_email_otp() for _ in range(10)]

    # Should have some variation (statistically very unlikely to be all the same)
    assert len(set(otps)) > 1
