"""Tests for password hashing and verification utilities."""

from app.utils.password import hash_password, verify_password


def test_hash_password():
    """Test that password hashing produces a hash."""
    password = "test_password_123"
    hashed = hash_password(password)

    # Should return a string
    assert isinstance(hashed, str)
    # Should not be the same as the original password
    assert hashed != password
    # Argon2 hashes start with $argon2
    assert hashed.startswith("$argon2")


def test_verify_password_success():
    """Test that correct password verification returns True."""
    password = "my_secure_password"
    hashed = hash_password(password)

    # Should verify successfully
    assert verify_password(hashed, password) is True


def test_verify_password_failure():
    """Test that incorrect password verification returns False."""
    password = "correct_password"
    wrong_password = "wrong_password"
    hashed = hash_password(password)

    # Should fail verification
    assert verify_password(hashed, wrong_password) is False


def test_verify_password_case_sensitive():
    """Test that password verification is case-sensitive."""
    password = "Password123"
    hashed = hash_password(password)

    # Different case should fail
    assert verify_password(hashed, "password123") is False
    assert verify_password(hashed, "PASSWORD123") is False


def test_hash_password_different_hashes():
    """Test that same password produces different hashes (due to salt)."""
    password = "same_password"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    # Hashes should be different due to different salts
    assert hash1 != hash2
    # But both should verify successfully
    assert verify_password(hash1, password) is True
    assert verify_password(hash2, password) is True


def test_verify_password_empty_password():
    """Test handling of empty password."""
    hashed = hash_password("nonempty")
    assert verify_password(hashed, "") is False


def test_hash_empty_password():
    """Test that empty password can be hashed."""
    hashed = hash_password("")
    assert isinstance(hashed, str)
    assert verify_password(hashed, "") is True
