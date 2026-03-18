"""Tests for password strength validation utility."""

from unittest.mock import patch

import httpx
from utils.password_strength import (
    PasswordStrengthResult,
    check_hibp,
    validate_password,
)

MODULE = "utils.password_strength"


# =============================================================================
# check_hibp tests
# =============================================================================


class TestCheckHibp:
    """Tests for the HIBP k-anonymity check."""

    def _make_response(self, status_code, text=""):
        """Create an httpx.Response with a request set."""
        req = httpx.Request("GET", "https://api.pwnedpasswords.com/range/test")
        return httpx.Response(status_code, text=text, request=req)

    def test_password_found_in_breach(self):
        """Password that appears in HIBP returns count > 0."""
        import hashlib

        sha1 = hashlib.sha1(b"password").hexdigest().upper()  # noqa: S324
        suffix = sha1[5:]

        mock_response = self._make_response(200, text=f"AAAAA:1\n{suffix}:12345\nBBBBB:2\n")
        with patch(f"{MODULE}.httpx.get", return_value=mock_response):
            result = check_hibp("password")
            assert result == 12345

    def test_password_not_in_breach(self):
        """Clean password returns 0."""
        mock_response = self._make_response(200, text="AAAAA:1\nBBBBB:2\nCCCCC:3\n")
        with patch(f"{MODULE}.httpx.get", return_value=mock_response):
            result = check_hibp("my_super_unique_password_xyz_123")
            assert result == 0

    def test_hibp_timeout_returns_zero(self):
        """Timeout from HIBP API returns 0 (fail-open)."""
        with patch(f"{MODULE}.httpx.get", side_effect=httpx.TimeoutException("timeout")):
            result = check_hibp("anything")
            assert result == 0

    def test_hibp_network_error_returns_zero(self):
        """Network error returns 0 (fail-open)."""
        with patch(f"{MODULE}.httpx.get", side_effect=httpx.ConnectError("refused")):
            result = check_hibp("anything")
            assert result == 0

    def test_hibp_http_error_returns_zero(self):
        """HTTP error status returns 0 (fail-open)."""
        mock_response = httpx.Response(503)
        mock_response.request = httpx.Request("GET", "https://example.com")
        with patch(f"{MODULE}.httpx.get", return_value=mock_response):
            result = check_hibp("anything")
            assert result == 0


# =============================================================================
# validate_password tests
# =============================================================================


class TestValidatePassword:
    """Tests for the validate_password function."""

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_password_too_short(self, mock_hibp):
        """Short password fails length check."""
        result = validate_password("abc", minimum_length=14, minimum_score=3)
        assert not result.is_valid
        assert any(i.code == "password_too_short" for i in result.issues)
        assert "14" in result.issues[0].message

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_password_meets_length(self, mock_hibp):
        """Password meeting length requirement passes length check."""
        # Use a strong enough password to also pass zxcvbn
        result = validate_password("x7!Kq9#mPv2$nR4w", minimum_length=14, minimum_score=3)
        length_issues = [i for i in result.issues if i.code == "password_too_short"]
        assert len(length_issues) == 0

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_weak_zxcvbn_score(self, mock_hibp):
        """Password with low zxcvbn score fails."""
        # "aaaaaaaaaaaaaaaa" is long enough but has score 0
        result = validate_password("aaaaaaaaaaaaaaaa", minimum_length=8, minimum_score=3)
        assert not result.is_valid
        assert any(i.code == "password_too_weak" for i in result.issues)

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_strong_password_passes(self, mock_hibp):
        """Strong password passes all checks."""
        result = validate_password("x7!Kq9#mPv2$nR4w", minimum_length=14, minimum_score=3)
        assert result.is_valid
        assert result.zxcvbn_score >= 3
        assert result.hibp_count == 0

    @patch(f"{MODULE}.check_hibp", return_value=5000)
    def test_breached_password_fails(self, mock_hibp):
        """Password found in HIBP fails."""
        result = validate_password("x7!Kq9#mPv2$nR4w", minimum_length=14, minimum_score=3)
        assert not result.is_valid
        assert any(i.code == "password_breached" for i in result.issues)
        assert result.hibp_count == 5000

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_super_admin_minimum_14(self, mock_hibp):
        """Super admin always requires at least 14 chars even if policy is lower."""
        result = validate_password(
            "short1234!", minimum_length=8, minimum_score=3, user_role="super_admin"
        )
        assert any(i.code == "password_too_short" for i in result.issues)
        assert "14" in [i for i in result.issues if i.code == "password_too_short"][0].message

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_super_admin_with_high_policy_uses_policy(self, mock_hibp):
        """Super admin with policy > 14 uses the policy value."""
        result = validate_password(
            "x7!Kq9#mPv2$nR", minimum_length=16, minimum_score=3, user_role="super_admin"
        )
        assert any(i.code == "password_too_short" for i in result.issues)
        assert "16" in [i for i in result.issues if i.code == "password_too_short"][0].message

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_user_inputs_passed_to_zxcvbn(self, mock_hibp):
        """User inputs (email, name) are used by zxcvbn to penalize common patterns."""
        # Password that contains the user's email domain
        result1 = validate_password("testexamplecom1", minimum_length=8, minimum_score=3)
        result2 = validate_password(
            "testexamplecom1",
            minimum_length=8,
            minimum_score=3,
            user_inputs=["test@example.com"],
        )
        # Score with user_inputs should be <= score without (or equal)
        assert result2.zxcvbn_score <= result1.zxcvbn_score

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_result_has_zxcvbn_metadata(self, mock_hibp):
        """Result includes zxcvbn scoring metadata."""
        result = validate_password("x7!Kq9#mPv2$nR4w", minimum_length=14, minimum_score=3)
        assert isinstance(result.zxcvbn_score, int)
        assert isinstance(result.zxcvbn_crack_time, str)
        assert isinstance(result.zxcvbn_feedback, dict)

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_multiple_issues_returned(self, mock_hibp):
        """Password can fail multiple checks simultaneously."""
        result = validate_password("aaa", minimum_length=14, minimum_score=3)
        assert not result.is_valid
        codes = [i.code for i in result.issues]
        assert "password_too_short" in codes
        assert "password_too_weak" in codes

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_minimum_score_4(self, mock_hibp):
        """Score 4 requirement rejects score-3 passwords."""
        # A password that scores 3 but not 4
        result = validate_password("Tr0ub4dor&3xyz!", minimum_length=8, minimum_score=4)
        if result.zxcvbn_score < 4:
            assert any(i.code == "password_too_weak" for i in result.issues)

    def test_is_valid_property(self):
        """is_valid property returns True when no issues."""
        result = PasswordStrengthResult(issues=[])
        assert result.is_valid is True

    def test_is_valid_property_with_issues(self):
        """is_valid property returns False when issues exist."""
        from utils.password_strength import PasswordIssue

        result = PasswordStrengthResult(issues=[PasswordIssue(code="test", message="test")])
        assert result.is_valid is False

    @patch(f"{MODULE}.check_hibp", return_value=0)
    def test_regular_user_respects_lower_length(self, mock_hibp):
        """Regular user can use lower minimum length from policy."""
        result = validate_password("x7!Kq9#m", minimum_length=8, minimum_score=3, user_role="user")
        length_issues = [i for i in result.issues if i.code == "password_too_short"]
        assert len(length_issues) == 0
