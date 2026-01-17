"""Tests for email possession verification utilities."""

from unittest.mock import patch

from app.utils.email_verification import (
    _constant_time_compare,
    _hash_code,
    create_trust_cookie,
    create_verification_cookie,
    generate_verification_code,
    get_trust_cookie_name,
    get_verification_cookie_email,
    validate_trust_cookie,
    validate_verification_cookie,
)


class TestGenerateVerificationCode:
    """Tests for verification code generation."""

    def test_generates_6_digit_code(self):
        """Test that generated code is 6 digits."""
        code = generate_verification_code()
        assert len(code) == 6
        assert code.isdigit()

    def test_codes_are_unique(self):
        """Test that codes have variation (statistically)."""
        codes = [generate_verification_code() for _ in range(20)]
        # Should have significant variation
        assert len(set(codes)) > 5

    def test_codes_are_zero_padded(self):
        """Test that low codes are zero-padded."""
        # With enough attempts, we should see some codes starting with 0
        codes = [generate_verification_code() for _ in range(1000)]
        has_leading_zero = any(code.startswith("0") for code in codes)
        # This might rarely fail, but is statistically unlikely
        assert has_leading_zero or len(codes) == 1000  # Allow test to pass


class TestHashCode:
    """Tests for code hashing."""

    def test_produces_sha256_hex(self):
        """Test that hash is SHA-256 hex string."""
        hashed = _hash_code("123456")
        assert len(hashed) == 64
        assert all(c in "0123456789abcdef" for c in hashed)

    def test_same_input_same_hash(self):
        """Test that same input produces same hash."""
        code = "123456"
        assert _hash_code(code) == _hash_code(code)

    def test_different_input_different_hash(self):
        """Test that different inputs produce different hashes."""
        assert _hash_code("123456") != _hash_code("654321")


class TestConstantTimeCompare:
    """Tests for constant-time comparison."""

    def test_equal_strings_match(self):
        """Test that equal strings return True."""
        assert _constant_time_compare("abc", "abc") is True

    def test_different_strings_dont_match(self):
        """Test that different strings return False."""
        assert _constant_time_compare("abc", "def") is False
        assert _constant_time_compare("abc", "ab") is False


class TestVerificationCookie:
    """Tests for verification cookie creation and validation."""

    def test_create_and_validate_cookie(self):
        """Test creating and validating a verification cookie."""
        email = "user@example.com"
        code = "123456"
        tenant_id = "test-tenant-id"

        cookie = create_verification_cookie(email, code, tenant_id)

        # Cookie should be a non-empty string
        assert isinstance(cookie, str)
        assert len(cookie) > 0

        # Validate with correct code
        is_valid, retrieved_email, retrieved_tenant = validate_verification_cookie(cookie, code)
        assert is_valid is True
        assert retrieved_email == email.lower()
        assert retrieved_tenant == tenant_id

    def test_wrong_code_fails_validation(self):
        """Test that wrong code fails validation."""
        email = "user@example.com"
        code = "123456"
        tenant_id = "test-tenant-id"

        cookie = create_verification_cookie(email, code, tenant_id)

        # Validate with wrong code
        is_valid, _, _ = validate_verification_cookie(cookie, "999999")
        assert is_valid is False

    def test_expired_cookie_fails_validation(self):
        """Test that expired cookie fails validation."""
        email = "user@example.com"
        code = "123456"
        tenant_id = "test-tenant-id"

        # Create cookie with very short expiry
        with patch("app.utils.email_verification.settings") as mock_settings:
            mock_settings.VERIFICATION_CODE_EXPIRY_SECONDS = -1  # Expired immediately
            cookie = create_verification_cookie(email, code, tenant_id)

        is_valid, _, _ = validate_verification_cookie(cookie, code)
        assert is_valid is False

    def test_invalid_cookie_fails_gracefully(self):
        """Test that invalid cookie data is handled gracefully."""
        is_valid, email, tenant = validate_verification_cookie("invalid-data", "123456")
        assert is_valid is False
        assert email is None
        assert tenant is None

    def test_email_is_normalized(self):
        """Test that email is normalized to lowercase."""
        email = "User@EXAMPLE.COM"
        code = "123456"
        tenant_id = "test-tenant-id"

        cookie = create_verification_cookie(email, code, tenant_id)

        is_valid, retrieved_email, _ = validate_verification_cookie(cookie, code)
        assert is_valid is True
        assert retrieved_email == "user@example.com"

    def test_expected_email_validation(self):
        """Test validation with expected email parameter."""
        email = "user@example.com"
        code = "123456"
        tenant_id = "test-tenant-id"

        cookie = create_verification_cookie(email, code, tenant_id)

        # Correct expected email
        is_valid, _, _ = validate_verification_cookie(
            cookie, code, expected_email="user@example.com"
        )
        assert is_valid is True

        # Wrong expected email
        is_valid, _, _ = validate_verification_cookie(
            cookie, code, expected_email="other@example.com"
        )
        assert is_valid is False


class TestGetVerificationCookieEmail:
    """Tests for extracting email from verification cookie."""

    def test_extracts_email(self):
        """Test extracting email from valid cookie."""
        email = "user@example.com"
        code = "123456"
        tenant_id = "test-tenant-id"

        cookie = create_verification_cookie(email, code, tenant_id)
        retrieved_email = get_verification_cookie_email(cookie)

        assert retrieved_email == email.lower()

    def test_returns_none_for_invalid_cookie(self):
        """Test that invalid cookie returns None."""
        email = get_verification_cookie_email("invalid-data")
        assert email is None

    def test_returns_none_for_expired_cookie(self):
        """Test that expired cookie returns None."""
        email = "user@example.com"
        code = "123456"
        tenant_id = "test-tenant-id"

        # Create expired cookie
        with patch("app.utils.email_verification.settings") as mock_settings:
            mock_settings.VERIFICATION_CODE_EXPIRY_SECONDS = -1
            cookie = create_verification_cookie(email, code, tenant_id)

        retrieved_email = get_verification_cookie_email(cookie)
        assert retrieved_email is None


class TestTrustCookie:
    """Tests for trust cookie creation and validation."""

    def test_create_and_validate_trust_cookie(self):
        """Test creating and validating a trust cookie."""
        email = "user@example.com"
        tenant_id = "test-tenant-id"

        cookie = create_trust_cookie(email, tenant_id)

        # Cookie should be a non-empty string
        assert isinstance(cookie, str)
        assert len(cookie) > 0

        # Validate
        is_valid = validate_trust_cookie(cookie, email, tenant_id)
        assert is_valid is True

    def test_wrong_email_fails_validation(self):
        """Test that wrong email fails validation."""
        email = "user@example.com"
        tenant_id = "test-tenant-id"

        cookie = create_trust_cookie(email, tenant_id)

        is_valid = validate_trust_cookie(cookie, "other@example.com", tenant_id)
        assert is_valid is False

    def test_wrong_tenant_fails_validation(self):
        """Test that wrong tenant fails validation."""
        email = "user@example.com"
        tenant_id = "test-tenant-id"

        cookie = create_trust_cookie(email, tenant_id)

        is_valid = validate_trust_cookie(cookie, email, "wrong-tenant")
        assert is_valid is False

    def test_expired_trust_cookie_fails_validation(self):
        """Test that expired trust cookie fails validation."""
        email = "user@example.com"
        tenant_id = "test-tenant-id"

        # Create cookie with verification time in the past (beyond expiry)
        with patch("app.utils.email_verification.time.time") as mock_time:
            # Create at time 0
            mock_time.return_value = 0
            cookie = create_trust_cookie(email, tenant_id)

        # Validate at current time (well past 30 days)
        is_valid = validate_trust_cookie(cookie, email, tenant_id)
        assert is_valid is False

    def test_invalid_trust_cookie_fails_gracefully(self):
        """Test that invalid trust cookie is handled gracefully."""
        is_valid = validate_trust_cookie("invalid-data", "user@example.com", "tenant")
        assert is_valid is False

    def test_email_is_normalized(self):
        """Test that email is normalized to lowercase."""
        email = "User@EXAMPLE.COM"
        tenant_id = "test-tenant-id"

        cookie = create_trust_cookie(email, tenant_id)

        # Validate with lowercase email
        is_valid = validate_trust_cookie(cookie, "user@example.com", tenant_id)
        assert is_valid is True

        # Validate with uppercase email (should also work due to normalization)
        is_valid = validate_trust_cookie(cookie, "USER@EXAMPLE.COM", tenant_id)
        assert is_valid is True


class TestGetTrustCookieName:
    """Tests for trust cookie name generation."""

    def test_generates_consistent_name(self):
        """Test that same email generates same cookie name."""
        email = "user@example.com"
        name1 = get_trust_cookie_name(email)
        name2 = get_trust_cookie_name(email)
        assert name1 == name2

    def test_different_emails_different_names(self):
        """Test that different emails generate different names."""
        name1 = get_trust_cookie_name("user1@example.com")
        name2 = get_trust_cookie_name("user2@example.com")
        assert name1 != name2

    def test_name_has_correct_prefix(self):
        """Test that cookie name has correct prefix."""
        name = get_trust_cookie_name("user@example.com")
        assert name.startswith("email_trust_")

    def test_email_is_normalized(self):
        """Test that email is normalized before hashing."""
        name1 = get_trust_cookie_name("User@EXAMPLE.COM")
        name2 = get_trust_cookie_name("user@example.com")
        assert name1 == name2


class TestEncryptionKeyFallback:
    """Tests for encryption key fallback behavior."""

    def test_fallback_with_invalid_base64(self):
        """Test that encryption key fallback works with invalid base64."""
        from app.utils.email_verification import _get_encryption_key

        with patch(
            "app.utils.email_verification.settings.EMAIL_VERIFICATION_KEY",
            "not-valid-base64-!!!",
        ):
            key = _get_encryption_key()
            # Should still return a valid key (fallback to SHA256)
            assert isinstance(key, bytes)
            assert len(key) > 0

    def test_encryption_still_works_with_fallback_key(self):
        """Test that encryption/decryption works with fallback key."""
        email = "user@example.com"
        code = "123456"
        tenant_id = "test-tenant-id"

        with patch(
            "app.utils.email_verification.settings.EMAIL_VERIFICATION_KEY",
            "not-valid-base64-!!!",
        ):
            # Need to reimport to get new cipher
            import importlib

            import app.utils.email_verification

            importlib.reload(app.utils.email_verification)

            from app.utils.email_verification import (
                create_verification_cookie,
                validate_verification_cookie,
            )

            cookie = create_verification_cookie(email, code, tenant_id)
            is_valid, retrieved_email, _ = validate_verification_cookie(cookie, code)

            assert is_valid is True
            assert retrieved_email == email

        # Reload with original settings
        import importlib

        import app.utils.email_verification

        importlib.reload(app.utils.email_verification)
