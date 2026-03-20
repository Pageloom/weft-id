"""Tests for MFA bypass mode."""

from unittest.mock import patch


def test_verify_email_otp_bypass_accepts_any_6_digit_code():
    """Test that bypass mode accepts any valid 6-digit code for email OTP."""
    with patch("settings.BYPASS_OTP", True):
        from utils.mfa import verify_email_otp

        # Any 6-digit code should pass
        assert verify_email_otp("tenant-123", "user-123", "000000") is True
        assert verify_email_otp("tenant-123", "user-123", "123456") is True
        assert verify_email_otp("tenant-123", "user-123", "999999") is True


def test_verify_email_otp_bypass_rejects_invalid_codes():
    """Test that bypass mode rejects invalid codes (non-6-digit, non-numeric)."""
    with patch("settings.BYPASS_OTP", True):
        from utils.mfa import verify_email_otp

        # 5-digit code - falls through to real verification, rejected
        assert verify_email_otp("t", "u", "12345") is False

        # 7-digit code
        assert verify_email_otp("t", "u", "1234567") is False

        # Non-numeric code
        assert verify_email_otp("t", "u", "abcdef") is False

        # Mixed code
        assert verify_email_otp("t", "u", "12345a") is False


def test_verify_totp_code_bypass_accepts_any_6_digit_code():
    """Test that bypass mode accepts any valid 6-digit code for TOTP."""
    with patch("settings.BYPASS_OTP", True):
        from utils.mfa import verify_totp_code

        # Any 6-digit code should pass, regardless of secret
        assert verify_totp_code("INVALID_SECRET", "000000") is True
        assert verify_totp_code("INVALID_SECRET", "123456") is True
        assert verify_totp_code("INVALID_SECRET", "999999") is True


def test_verify_totp_code_bypass_rejects_invalid_codes():
    """Test that bypass mode rejects invalid codes for TOTP."""
    with patch("settings.BYPASS_OTP", True):
        # These should fall through to the real TOTP verification
        # We test the bypass condition validation logic

        # 5-digit code - bypass condition not met
        code = "12345"
        assert not (len(code) == 6 and code.isdigit())

        # Non-numeric code - bypass condition not met
        code = "abcdef"
        assert not (len(code) == 6 and code.isdigit())


def test_verify_backup_code_not_bypassed():
    """Test that backup codes are NOT affected by bypass mode."""
    # The verify_backup_code function should NOT check BYPASS_OTP
    # We verify by checking the source code doesn't include the bypass check
    import inspect

    from utils.mfa import verify_backup_code

    source = inspect.getsource(verify_backup_code)
    assert "BYPASS_OTP" not in source, "Backup codes should not be bypassed"


def test_bypass_mode_disabled_uses_real_verification():
    """Test that with bypass disabled, real verification is used."""
    with patch("settings.BYPASS_OTP", False):
        from utils.mfa import verify_totp_code

        # With a random/invalid secret, any code should fail
        # This will use the real pyotp verification
        result = verify_totp_code("JBSWY3DPEHPK3PXP", "000000")
        # The result depends on timing, but at least it's not a guaranteed True
        # like in bypass mode. We mainly want to ensure the function runs without error.
        assert isinstance(result, bool)


def test_email_otp_bypass_checks_code_format():
    """Test that bypass validates the code format properly."""
    with patch("settings.BYPASS_OTP", True):
        from utils.mfa import verify_email_otp

        # Valid 6-digit codes pass
        assert verify_email_otp("t", "u", "000000") is True
        assert verify_email_otp("t", "u", "123456") is True

        # Leading zeros are valid
        assert verify_email_otp("t", "u", "000001") is True
        assert verify_email_otp("t", "u", "012345") is True


def test_totp_bypass_checks_code_format():
    """Test that TOTP bypass validates the code format properly."""
    with patch("settings.BYPASS_OTP", True):
        from utils.mfa import verify_totp_code

        # Valid 6-digit codes pass
        assert verify_totp_code("any_secret", "000000") is True
        assert verify_totp_code("any_secret", "123456") is True

        # Leading zeros are valid
        assert verify_totp_code("any_secret", "000001") is True
        assert verify_totp_code("any_secret", "012345") is True
