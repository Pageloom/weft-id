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
            SESSION_SECRET_KEY="dev-secret-key-change-in-production",
            MFA_ENCRYPTION_KEY="dev-mfa-key-change-in-production-must-be-base64",
            SAML_KEY_ENCRYPTION_KEY="dev-saml-key-change-in-production-must-be-base64",
            EMAIL_VERIFICATION_KEY="dev-email-verification-key-change-in-production",
            BYPASS_OTP=True,
        ):
            import settings

            # Should not raise
            settings.validate_production_settings()

    def test_validate_passes_with_proper_production_config(self):
        """No error when all secrets are customized and BYPASS_OTP=False."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SESSION_SECRET_KEY="production-session-secret-key-abc123",
            MFA_ENCRYPTION_KEY="cHJvZHVjdGlvbi1tZmEta2V5LWFiYzEyMw==",
            SAML_KEY_ENCRYPTION_KEY="cHJvZHVjdGlvbi1zYW1sLWtleS1hYmMxMjM=",
            EMAIL_VERIFICATION_KEY="production-email-verification-key-abc123",
            BYPASS_OTP=False,
        ):
            import settings

            # Should not raise
            settings.validate_production_settings()

    def test_validate_fails_with_default_session_key(self):
        """Error when SESSION_SECRET_KEY has default value in production."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SESSION_SECRET_KEY="dev-secret-key-change-in-production",
            MFA_ENCRYPTION_KEY="cHJvZHVjdGlvbi1tZmEta2V5",
            SAML_KEY_ENCRYPTION_KEY="cHJvZHVjdGlvbi1zYW1sLWtleQ==",
            EMAIL_VERIFICATION_KEY="production-email-key",
            BYPASS_OTP=False,
        ):
            import settings

            with pytest.raises(RuntimeError) as exc_info:
                settings.validate_production_settings()

            assert "SESSION_SECRET_KEY has insecure default value" in str(exc_info.value)

    def test_validate_fails_with_default_mfa_key(self):
        """Error when MFA_ENCRYPTION_KEY has default value in production."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SESSION_SECRET_KEY="production-session-key",
            MFA_ENCRYPTION_KEY="dev-mfa-key-change-in-production-must-be-base64",
            SAML_KEY_ENCRYPTION_KEY="cHJvZHVjdGlvbi1zYW1sLWtleQ==",
            EMAIL_VERIFICATION_KEY="production-email-key",
            BYPASS_OTP=False,
        ):
            import settings

            with pytest.raises(RuntimeError) as exc_info:
                settings.validate_production_settings()

            assert "MFA_ENCRYPTION_KEY has insecure default value" in str(exc_info.value)

    def test_validate_fails_with_default_saml_key(self):
        """Error when SAML_KEY_ENCRYPTION_KEY has default value in production."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SESSION_SECRET_KEY="production-session-key",
            MFA_ENCRYPTION_KEY="cHJvZHVjdGlvbi1tZmEta2V5",
            SAML_KEY_ENCRYPTION_KEY="dev-saml-key-change-in-production-must-be-base64",
            EMAIL_VERIFICATION_KEY="production-email-key",
            BYPASS_OTP=False,
        ):
            import settings

            with pytest.raises(RuntimeError) as exc_info:
                settings.validate_production_settings()

            assert "SAML_KEY_ENCRYPTION_KEY has insecure default value" in str(
                exc_info.value
            )

    def test_validate_fails_with_default_email_key(self):
        """Error when EMAIL_VERIFICATION_KEY has default value in production."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SESSION_SECRET_KEY="production-session-key",
            MFA_ENCRYPTION_KEY="cHJvZHVjdGlvbi1tZmEta2V5",
            SAML_KEY_ENCRYPTION_KEY="cHJvZHVjdGlvbi1zYW1sLWtleQ==",
            EMAIL_VERIFICATION_KEY="dev-email-verification-key-change-in-production",
            BYPASS_OTP=False,
        ):
            import settings

            with pytest.raises(RuntimeError) as exc_info:
                settings.validate_production_settings()

            assert "EMAIL_VERIFICATION_KEY has insecure default value" in str(
                exc_info.value
            )

    def test_validate_fails_with_bypass_otp_enabled(self):
        """Error when BYPASS_OTP=True in production."""
        with patch.multiple(
            "settings",
            IS_DEV=False,
            SESSION_SECRET_KEY="production-session-key",
            MFA_ENCRYPTION_KEY="cHJvZHVjdGlvbi1tZmEta2V5",
            SAML_KEY_ENCRYPTION_KEY="cHJvZHVjdGlvbi1zYW1sLWtleQ==",
            EMAIL_VERIFICATION_KEY="production-email-key",
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
            SESSION_SECRET_KEY="dev-secret-key-change-in-production",
            MFA_ENCRYPTION_KEY="dev-mfa-key-change-in-production-must-be-base64",
            SAML_KEY_ENCRYPTION_KEY="cHJvZHVjdGlvbi1zYW1sLWtleQ==",
            EMAIL_VERIFICATION_KEY="production-email-key",
            BYPASS_OTP=True,
        ):
            import settings

            with pytest.raises(RuntimeError) as exc_info:
                settings.validate_production_settings()

            error_message = str(exc_info.value)
            assert "SESSION_SECRET_KEY has insecure default value" in error_message
            assert "MFA_ENCRYPTION_KEY has insecure default value" in error_message
            assert "BYPASS_OTP must be disabled in production" in error_message
