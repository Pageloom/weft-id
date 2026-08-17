"""Tests for redirect-target validation."""

import pytest
from utils.redirects import (
    DEFAULT_TARGET,
    MAX_TARGET_LEN,
    is_safe_path,
    safe_external_redirect,
    safe_path,
    safe_redirect,
)


class TestIsSafePath:
    """Validation of same-origin relative paths."""

    @pytest.mark.parametrize(
        "target",
        [
            "/dashboard",
            "/users/list?error=user_not_found",
            "/users/abc-123/profile?success=attributes_saved",
            "/admin/integrations/apps/xyz?success=updated",
            "/",
            "/path/with/trailing?a=1&b=2#fragment",
            "/path%20with%20encoding",
        ],
    )
    def test_accepts_relative_paths(self, target):
        assert is_safe_path(target) is True

    @pytest.mark.parametrize(
        "target",
        [
            "//evil.com",
            "//evil.com/path",
            "https://evil.com",
            "http://evil.com",
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "dashboard",
            "../dashboard",
            "",
        ],
    )
    def test_rejects_off_origin_targets(self, target):
        assert is_safe_path(target) is False

    def test_rejects_none(self):
        assert is_safe_path(None) is False

    @pytest.mark.parametrize("target", ["/\\evil.com", "/path\\to\\thing", "\\\\evil.com"])
    def test_rejects_backslash(self, target):
        """Browsers fold backslash into forward slash before resolving."""
        assert is_safe_path(target) is False

    @pytest.mark.parametrize(
        "target",
        ["/path\r\nLocation: https://evil.com", "/path\nSet-Cookie: a=b", "/path\x00", "/path\x7f"],
    )
    def test_rejects_control_characters(self, target):
        """Control characters can split the Location header."""
        assert is_safe_path(target) is False

    def test_rejects_over_length(self):
        assert is_safe_path("/" + "a" * MAX_TARGET_LEN) is False

    def test_accepts_at_length_limit(self):
        target = "/" + "a" * (MAX_TARGET_LEN - 1)
        assert len(target) == MAX_TARGET_LEN
        assert is_safe_path(target) is True

    def test_rejects_scheme_relative_with_userinfo(self):
        """A userinfo segment must not smuggle an off-origin host through."""
        assert is_safe_path("//user:pass@evil.com/path") is False


class TestSafePath:
    """Fallback behavior."""

    def test_returns_valid_target(self):
        assert safe_path("/users/list") == "/users/list"

    def test_falls_back_on_hostile_target(self):
        assert safe_path("//evil.com") == DEFAULT_TARGET

    def test_falls_back_on_none(self):
        assert safe_path(None) == DEFAULT_TARGET

    def test_honors_custom_default(self):
        assert safe_path("https://evil.com", default="/login") == "/login"


class TestSafeRedirect:
    """Response construction for same-origin redirects."""

    def test_builds_redirect_to_valid_target(self):
        response = safe_redirect("/users/list?success=saved")
        assert response.status_code == 303
        assert response.headers["location"] == "/users/list?success=saved"

    def test_redirects_to_default_on_hostile_target(self):
        response = safe_redirect("//evil.com")
        assert response.headers["location"] == DEFAULT_TARGET

    def test_honors_custom_status_code(self):
        assert safe_redirect("/login", status_code=302).status_code == 302

    def test_honors_custom_default(self):
        response = safe_redirect("javascript:alert(1)", default="/login")
        assert response.headers["location"] == "/login"


class TestSafeExternalRedirect:
    """Cross-origin hops restricted to an allowlist."""

    ALLOWED = frozenset({"portal.example.com", "app.example.com"})

    def test_builds_redirect_for_allowlisted_host(self):
        response = safe_external_redirect("portal.example.com", "/callback?token=x", self.ALLOWED)
        assert response is not None
        assert response.status_code == 302
        assert response.headers["location"] == "https://portal.example.com/callback?token=x"

    def test_returns_none_for_unlisted_host(self):
        assert safe_external_redirect("evil.com", "/callback", self.ALLOWED) is None

    def test_returns_none_for_empty_host(self):
        assert safe_external_redirect("", "/callback", self.ALLOWED) is None

    def test_returns_none_for_unsafe_path(self):
        assert safe_external_redirect("portal.example.com", "//evil.com", self.ALLOWED) is None

    def test_returns_none_when_allowlist_empty(self):
        assert safe_external_redirect("portal.example.com", "/callback", frozenset()) is None

    def test_host_match_is_exact_not_suffix(self):
        """A host that merely ends with an allowlisted domain is rejected."""
        assert safe_external_redirect("evil-example.com", "/callback", self.ALLOWED) is None
        assert safe_external_redirect("sub.portal.example.com", "/cb", self.ALLOWED) is None
