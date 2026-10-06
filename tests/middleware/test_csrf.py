"""Tests for CSRF middleware."""

from unittest.mock import MagicMock

from middleware.csrf import (
    CSRF_SESSION_KEY,
    _is_exempt,
    generate_csrf_token,
    get_csrf_token,
)


class TestGenerateCsrfToken:
    """Tests for generate_csrf_token function."""

    def test_generates_unique_tokens(self):
        """Each call should generate a different token."""
        token1 = generate_csrf_token()
        token2 = generate_csrf_token()
        assert token1 != token2

    def test_generates_non_empty_token(self):
        """Token should not be empty."""
        token = generate_csrf_token()
        assert len(token) > 0

    def test_generates_url_safe_token(self):
        """Token should be URL-safe (no special characters)."""
        token = generate_csrf_token()
        # URL-safe base64 only contains letters, numbers, underscores, and hyphens
        assert all(c.isalnum() or c in "-_" for c in token)


class TestGetCsrfToken:
    """Tests for get_csrf_token function."""

    def test_creates_token_if_not_exists(self):
        """Should create and store a token if none exists."""
        request = MagicMock()
        request.session = {}

        token = get_csrf_token(request)

        assert token is not None
        assert len(token) > 0
        assert request.session[CSRF_SESSION_KEY] == token

    def test_returns_existing_token(self):
        """Should return existing token from session."""
        existing_token = "existing-token-123"
        request = MagicMock()
        request.session = {CSRF_SESSION_KEY: existing_token}

        token = get_csrf_token(request)

        assert token == existing_token


class TestIsExempt:
    """Tests for _is_exempt function."""

    def test_api_routes_are_exempt(self):
        """API routes should be exempt from CSRF."""
        assert _is_exempt("/api/v1/users") is True
        assert _is_exempt("/api/v1/oauth2/clients") is True
        assert _is_exempt("/api/anything") is True

    def test_saml_acs_is_exempt(self):
        """SAML ACS endpoint should be exempt."""
        assert _is_exempt("/saml/acs") is True
        assert _is_exempt("/saml/acs/") is True

    def test_upstream_backchannel_logout_is_exempt(self):
        """The upstream IdP POSTs logout tokens server to server."""
        assert _is_exempt("/auth/oidc/0b1c/backchannel-logout") is True

    def test_upstream_backchannel_logout_pattern_is_exact(self):
        """Only that one path shape; its siblings and extensions stay protected."""
        assert _is_exempt("/auth/oidc/0b1c/login") is False
        assert _is_exempt("/auth/oidc/0b1c/backchannel-logout/extra") is False
        assert _is_exempt("/auth/oidc/a/b/backchannel-logout") is False
        assert _is_exempt("/x/auth/oidc/0b1c/backchannel-logout") is False

    def test_upstream_callback_pattern_is_exact(self):
        """The upstream callback takes a provider's cross-site form_post (Apple)."""
        assert _is_exempt("/auth/oidc/0b1c/callback") is True
        assert _is_exempt("/auth/oidc/0b1c/callback/extra") is False
        assert _is_exempt("/auth/oidc/a/b/callback") is False
        assert _is_exempt("/auth/oidc/confirm-email") is False

    def test_oauth2_token_is_exempt(self):
        """OAuth2 token endpoint should be exempt."""
        assert _is_exempt("/oauth2/token") is True

    def test_oauth2_authorize_is_exempt_exactly(self):
        """The authorization endpoint accepts cross-site POSTs from relying
        parties, but the consent decision form beneath it must keep CSRF."""
        assert _is_exempt("/oauth2/authorize") is True
        assert _is_exempt("/oauth2/authorize/decision") is False
        assert _is_exempt("/oauth2/authorize/") is False
        assert _is_exempt("/oauth2/authorized") is False

    def test_regular_routes_not_exempt(self):
        """Regular web routes should not be exempt."""
        assert _is_exempt("/login") is False
        assert _is_exempt("/users/new") is False
        assert _is_exempt("/admin/audit/events") is False
        assert _is_exempt("/account/profile") is False
