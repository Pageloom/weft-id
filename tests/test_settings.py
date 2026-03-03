"""Tests for settings validation."""

from unittest.mock import patch

import pytest


class TestValidateProductionSettings:
    """Tests for validate_production_settings function."""

    def test_validate_passes_in_dev_mode(self):
        """No error when IS_DEV=True regardless of other settings."""
        with patch.multiple(
            "settings",
            IS_DEV=True,
            SECRET_KEY="dev-secret-key-change-in-production",
            BYPASS_OTP=True,
        ):
            import settings

            # Should not raise
            settings.validate_production_settings()

    def test_validate_passes_with_proper_production_config(self):
        """No error when SECRET_KEY is customized and BYPASS_OTP=False."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SECRET_KEY="production-secret-key-abc123",
            BYPASS_OTP=False,
        ):
            import settings

            # Should not raise
            settings.validate_production_settings()

    def test_validate_fails_with_default_secret_key(self):
        """Error when SECRET_KEY has default value in production."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SECRET_KEY="dev-secret-key-change-in-production",
            BYPASS_OTP=False,
        ):
            import settings

            with pytest.raises(RuntimeError) as exc_info:
                settings.validate_production_settings()

            assert "SECRET_KEY has insecure default value" in str(exc_info.value)

    def test_validate_fails_with_bypass_otp_enabled(self):
        """Error when BYPASS_OTP=True in production."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SECRET_KEY="production-secret-key",
            BYPASS_OTP=True,
        ):
            import settings

            with pytest.raises(RuntimeError) as exc_info:
                settings.validate_production_settings()

            assert "BYPASS_OTP must be disabled in production" in str(exc_info.value)

    def test_validate_fails_with_multiple_issues(self):
        """Error message lists all configuration problems."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SECRET_KEY="dev-secret-key-change-in-production",
            BYPASS_OTP=True,
        ):
            import settings

            with pytest.raises(RuntimeError) as exc_info:
                settings.validate_production_settings()

            error_message = str(exc_info.value)
            assert "SECRET_KEY has insecure default value" in error_message
            assert "BYPASS_OTP must be disabled in production" in error_message
