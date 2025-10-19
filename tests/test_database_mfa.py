"""Tests for database.mfa module."""

from datetime import datetime, timedelta
import hashlib

import pytest


def test_set_mfa_method(test_user):
    """Test setting MFA method for a user."""
    import database

    # Set MFA method to email (default)
    database.mfa.set_mfa_method(
        test_user["tenant_id"],
        test_user["id"],
        "email"
    )

    # Verify it was set by checking user record
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["mfa_method"] == "email"


def test_enable_mfa(test_user):
    """Test enabling MFA for a user."""
    import database

    # Enable MFA with email method
    database.mfa.enable_mfa(
        test_user["tenant_id"],
        test_user["id"],
        "email"
    )

    # Verify MFA was enabled
    user = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert user["mfa_enabled"] is True
    assert user["mfa_method"] == "email"


# TOTP tests


def test_create_and_get_totp_secret(test_user):
    """Test creating and retrieving TOTP secret."""
    import database

    secret = "encrypted_totp_secret_123"

    # Create TOTP secret
    database.mfa.create_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        secret,
        test_user["tenant_id"]
    )

    # Retrieve TOTP secret
    totp_record = database.mfa.get_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "totp"
    )

    assert totp_record is not None
    assert totp_record["secret_encrypted"] == secret


def test_get_totp_secret_not_found(test_user):
    """Test retrieving non-existent TOTP secret returns None."""
    import database

    totp_record = database.mfa.get_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "totp"
    )

    assert totp_record is None


def test_get_verified_totp_secret_unverified(test_user):
    """Test that unverified TOTP secret is not returned."""
    import database

    secret = "encrypted_totp_secret_456"

    # Create unverified TOTP secret
    database.mfa.create_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        secret,
        test_user["tenant_id"]
    )

    # Should return None because not verified
    totp_record = database.mfa.get_verified_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "totp"
    )

    assert totp_record is None


def test_verify_totp_secret(test_user):
    """Test verifying TOTP secret."""
    import database

    secret = "encrypted_totp_secret_789"

    # Create TOTP secret
    database.mfa.create_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        secret,
        test_user["tenant_id"]
    )

    # Verify it
    database.mfa.verify_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "totp"
    )

    # Now it should be retrievable as verified
    totp_record = database.mfa.get_verified_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "totp"
    )

    assert totp_record is not None
    assert totp_record["secret_encrypted"] == secret


def test_delete_totp_secrets(test_user):
    """Test deleting TOTP secrets."""
    import database

    # Create TOTP secret
    database.mfa.create_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "secret_to_delete",
        test_user["tenant_id"]
    )

    # Delete it
    database.mfa.delete_totp_secrets(
        test_user["tenant_id"],
        test_user["id"]
    )

    # Verify it's gone
    totp_record = database.mfa.get_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "totp"
    )

    assert totp_record is None


def test_create_totp_secret_replaces_existing(test_user):
    """Test that creating a new TOTP secret replaces existing one and resets verification."""
    import database

    # Create first secret and verify it
    database.mfa.create_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "first_secret",
        test_user["tenant_id"]
    )
    database.mfa.verify_totp_secret(test_user["tenant_id"], test_user["id"], "totp")

    # Create second secret (should replace and reset verification)
    database.mfa.create_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "second_secret",
        test_user["tenant_id"]
    )

    # New secret should exist
    totp_record = database.mfa.get_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "totp"
    )
    assert totp_record["secret_encrypted"] == "second_secret"

    # But should not be verified
    verified_record = database.mfa.get_verified_totp_secret(
        test_user["tenant_id"],
        test_user["id"],
        "totp"
    )
    assert verified_record is None


# Email OTP tests


def test_create_and_verify_email_otp(test_user):
    """Test creating and verifying email OTP code."""
    import database

    code = "123456"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    expires_at = datetime.now() + timedelta(minutes=10)

    # Create email OTP
    database.mfa.create_email_otp(
        test_user["tenant_id"],
        test_user["id"],
        code_hash,
        expires_at,
        test_user["tenant_id"]
    )

    # Verify the OTP
    is_valid = database.mfa.verify_email_otp(
        test_user["tenant_id"],
        test_user["id"],
        code_hash
    )

    assert is_valid is True


def test_verify_invalid_email_otp(test_user):
    """Test verifying invalid email OTP returns False."""
    import database

    wrong_code_hash = hashlib.sha256(b"wrong_code").hexdigest()

    is_valid = database.mfa.verify_email_otp(
        test_user["tenant_id"],
        test_user["id"],
        wrong_code_hash
    )

    assert is_valid is False


def test_verify_expired_email_otp(test_user):
    """Test that expired OTP cannot be verified."""
    import database
    from datetime import timezone

    code = "123456"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    # Set expiry to a time well in the past to ensure it's expired
    expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    # Create expired email OTP
    database.mfa.create_email_otp(
        test_user["tenant_id"],
        test_user["id"],
        code_hash,
        expires_at,
        test_user["tenant_id"]
    )

    # Should not verify
    is_valid = database.mfa.verify_email_otp(
        test_user["tenant_id"],
        test_user["id"],
        code_hash
    )

    assert is_valid is False


def test_email_otp_cannot_be_reused(test_user):
    """Test that email OTP can only be used once."""
    import database

    code = "654321"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    expires_at = datetime.now() + timedelta(minutes=10)

    # Create and verify OTP
    database.mfa.create_email_otp(
        test_user["tenant_id"],
        test_user["id"],
        code_hash,
        expires_at,
        test_user["tenant_id"]
    )

    # First verification should succeed
    assert database.mfa.verify_email_otp(
        test_user["tenant_id"],
        test_user["id"],
        code_hash
    ) is True

    # Second verification should fail (already used)
    assert database.mfa.verify_email_otp(
        test_user["tenant_id"],
        test_user["id"],
        code_hash
    ) is False


# Backup code tests


def test_create_and_list_backup_codes(test_user):
    """Test creating and listing backup codes."""
    import database

    code_hash1 = hashlib.sha256(b"backup_code_1").hexdigest()
    code_hash2 = hashlib.sha256(b"backup_code_2").hexdigest()

    # Create backup codes
    database.mfa.create_backup_code(
        test_user["tenant_id"],
        test_user["id"],
        code_hash1,
        test_user["tenant_id"]
    )
    database.mfa.create_backup_code(
        test_user["tenant_id"],
        test_user["id"],
        code_hash2,
        test_user["tenant_id"]
    )

    # List backup codes
    codes = database.mfa.list_backup_codes(
        test_user["tenant_id"],
        test_user["id"]
    )

    assert len(codes) == 2
    assert any(c["code_hash"] == code_hash1 for c in codes)
    assert any(c["code_hash"] == code_hash2 for c in codes)


def test_verify_backup_code(test_user):
    """Test verifying a backup code."""
    import database

    code = "backup_code_123"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    # Create backup code
    database.mfa.create_backup_code(
        test_user["tenant_id"],
        test_user["id"],
        code_hash,
        test_user["tenant_id"]
    )

    # Verify it
    is_valid = database.mfa.verify_backup_code(
        test_user["tenant_id"],
        test_user["id"],
        code_hash
    )

    assert is_valid is True


def test_verify_invalid_backup_code(test_user):
    """Test verifying invalid backup code returns False."""
    import database

    wrong_code_hash = hashlib.sha256(b"wrong_backup_code").hexdigest()

    is_valid = database.mfa.verify_backup_code(
        test_user["tenant_id"],
        test_user["id"],
        wrong_code_hash
    )

    assert is_valid is False


def test_backup_code_cannot_be_reused(test_user):
    """Test that backup code can only be used once."""
    import database

    code = "backup_code_456"
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    # Create backup code
    database.mfa.create_backup_code(
        test_user["tenant_id"],
        test_user["id"],
        code_hash,
        test_user["tenant_id"]
    )

    # First verification should succeed
    assert database.mfa.verify_backup_code(
        test_user["tenant_id"],
        test_user["id"],
        code_hash
    ) is True

    # Second verification should fail (already used)
    assert database.mfa.verify_backup_code(
        test_user["tenant_id"],
        test_user["id"],
        code_hash
    ) is False


def test_delete_backup_codes(test_user):
    """Test deleting all backup codes."""
    import database

    # Create multiple backup codes
    for i in range(3):
        code_hash = hashlib.sha256(f"backup_code_{i}".encode()).hexdigest()
        database.mfa.create_backup_code(
            test_user["tenant_id"],
            test_user["id"],
            code_hash,
            test_user["tenant_id"]
        )

    # Verify codes exist
    codes = database.mfa.list_backup_codes(test_user["tenant_id"], test_user["id"])
    assert len(codes) == 3

    # Delete all codes
    database.mfa.delete_backup_codes(
        test_user["tenant_id"],
        test_user["id"]
    )

    # Verify they're gone
    codes = database.mfa.list_backup_codes(test_user["tenant_id"], test_user["id"])
    assert len(codes) == 0
