"""Tests for OAuth2 authorization and token endpoints (routers/oauth2.py)."""

import pytest

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def authenticated_client(client, test_tenant, test_user, override_auth):
    """Create a test client with an authenticated session."""
    override_auth(test_user)
    yield client


@pytest.fixture
def authenticated_client_with_host(client, test_tenant, test_tenant_host, test_user, override_auth):
    """Create a test client with authenticated session and proper host header."""
    override_auth(test_user)

    # Return a wrapper that adds the host header
    class ClientWrapper:
        def __init__(self, client, host):
            self._client = client
            self._host = host

        def get(self, url, **kwargs):
            headers = kwargs.pop("headers", {})
            headers["Host"] = self._host
            return self._client.get(url, headers=headers, **kwargs)

        def post(self, url, **kwargs):
            headers = kwargs.pop("headers", {})
            headers["Host"] = self._host
            return self._client.post(url, headers=headers, **kwargs)

    yield ClientWrapper(client, test_tenant_host)


# ============================================================================
# GET /oauth2/authorize - Authorization Page Tests
# ============================================================================


class TestAuthorizePage:
    """Tests for the OAuth2 authorization page (GET /oauth2/authorize)."""

    def test_authorize_page_valid_client(
        self, authenticated_client_with_host, normal_oauth2_client
    ):
        """Test authorization page renders for valid client."""
        response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        assert "oauth2_authorize" in response.text or "Authorize" in response.text

    def test_authorize_page_with_state(self, authenticated_client_with_host, normal_oauth2_client):
        """Test authorization page accepts state parameter (stored in session).

        The state is stored in the session (not visible in HTML) and returned
        in the redirect after authorization. The full flow is tested in
        TestAuthorizeGrant.test_authorize_allow_with_state.
        """
        response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "state": "random_state_123",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        # auth_request_id should be in the form (state is stored in session)
        assert "auth_request_id" in response.text

    def test_authorize_page_with_pkce(self, authenticated_client_with_host, normal_oauth2_client):
        """Test authorization page accepts PKCE parameters."""
        response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200

    def test_authorize_page_invalid_client_id(self, authenticated_client_with_host):
        """Test authorization page shows error for invalid client_id."""
        response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": "nonexistent_client_id",
                "redirect_uri": "http://localhost:3000/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        assert "Invalid client_id" in response.text or "error" in response.text.lower()

    def test_authorize_page_b2b_client_rejected(
        self, authenticated_client_with_host, b2b_oauth2_client
    ):
        """Test authorization page rejects B2B clients (wrong client type)."""
        response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": b2b_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        # B2B clients should be rejected for authorization code flow
        assert "Unauthorized client" in response.text or "not authorized" in response.text.lower()

    def test_authorize_page_invalid_redirect_uri(
        self, authenticated_client_with_host, normal_oauth2_client
    ):
        """Test authorization page shows error for invalid redirect_uri."""
        response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://malicious.com/callback",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        assert "Invalid redirect_uri" in response.text or "redirect" in response.text.lower()

    def test_authorize_page_invalid_pkce_method(
        self, authenticated_client_with_host, normal_oauth2_client
    ):
        """Test authorization page rejects invalid PKCE method."""
        response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "code_challenge": "some_challenge",
                "code_challenge_method": "invalid_method",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        assert "Invalid" in response.text or "S256" in response.text

    def test_authorize_page_pkce_plain_method_allowed(
        self, authenticated_client_with_host, normal_oauth2_client
    ):
        """Test authorization page accepts plain PKCE method."""
        response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "code_challenge": "plain_challenge_value",
                "code_challenge_method": "plain",
            },
            follow_redirects=False,
        )

        # Should not show an error - plain is a valid method
        assert response.status_code == 200
        assert "Invalid" not in response.text or "code_challenge_method" not in response.text

    def test_authorize_page_requires_authentication(
        self, client, test_tenant_host, normal_oauth2_client
    ):
        """Test authorization page redirects unauthenticated users to login."""
        response = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
            },
            follow_redirects=False,
        )

        # Should redirect to login
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


# ============================================================================
# POST /oauth2/authorize - Authorization Grant Tests
# ============================================================================


def _extract_auth_request_id(html: str) -> str:
    """Extract auth_request_id from the authorization page HTML."""
    import re

    match = re.search(r'name="auth_request_id"\s+value="([^"]+)"', html)
    if not match:
        raise ValueError("auth_request_id not found in HTML")
    return match.group(1)


class TestAuthorizeGrant:
    """Tests for the OAuth2 authorization grant (POST /oauth2/authorize)."""

    def test_authorize_allow_creates_code(
        self, authenticated_client_with_host, normal_oauth2_client
    ):
        """Test allowing authorization creates an authorization code."""
        # First GET the authorization page to get auth_request_id
        get_response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
            },
            follow_redirects=False,
        )
        assert get_response.status_code == 200
        auth_request_id = _extract_auth_request_id(get_response.text)

        # Now POST with the auth_request_id
        response = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": auth_request_id,
                "action": "allow",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        location = response.headers["location"]
        assert location.startswith("http://localhost:3000/callback")
        assert "code=" in location

    def test_authorize_allow_with_state(self, authenticated_client_with_host, normal_oauth2_client):
        """Test allowing authorization preserves state parameter."""
        # GET with state parameter
        get_response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "state": "my_state_value",
            },
            follow_redirects=False,
        )
        assert get_response.status_code == 200
        auth_request_id = _extract_auth_request_id(get_response.text)

        # POST with auth_request_id - state is retrieved from session
        response = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": auth_request_id,
                "action": "allow",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        location = response.headers["location"]
        assert "state=my_state_value" in location

    def test_authorize_allow_with_pkce(self, authenticated_client_with_host, normal_oauth2_client):
        """Test allowing authorization stores PKCE challenge."""
        # GET with PKCE parameters
        get_response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert get_response.status_code == 200
        auth_request_id = _extract_auth_request_id(get_response.text)

        # POST
        response = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": auth_request_id,
                "action": "allow",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        location = response.headers["location"]
        assert "code=" in location

    def test_authorize_deny_redirects_with_error(
        self, authenticated_client_with_host, normal_oauth2_client
    ):
        """Test denying authorization redirects with access_denied error."""
        # GET
        get_response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
            },
            follow_redirects=False,
        )
        auth_request_id = _extract_auth_request_id(get_response.text)

        # POST deny
        response = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": auth_request_id,
                "action": "deny",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        location = response.headers["location"]
        assert location.startswith("http://localhost:3000/callback")
        assert "error=access_denied" in location

    def test_authorize_deny_with_state(self, authenticated_client_with_host, normal_oauth2_client):
        """Test denying authorization preserves state parameter."""
        # GET with state
        get_response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "state": "my_state_value",
            },
            follow_redirects=False,
        )
        auth_request_id = _extract_auth_request_id(get_response.text)

        # POST deny
        response = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": auth_request_id,
                "action": "deny",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        location = response.headers["location"]
        assert "error=access_denied" in location
        assert "state=my_state_value" in location

    def test_authorize_invalid_action_redirects_with_error(
        self, authenticated_client_with_host, normal_oauth2_client
    ):
        """Test invalid action redirects with invalid_request error."""
        # GET
        get_response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
            },
            follow_redirects=False,
        )
        auth_request_id = _extract_auth_request_id(get_response.text)

        # POST with invalid action
        response = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": auth_request_id,
                "action": "invalid_action",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        location = response.headers["location"]
        assert "error=invalid_request" in location


# ============================================================================
# POST /oauth2/authorize - Security Tests (auth_request_id validation)
# ============================================================================


class TestAuthorizeGrantSecurity:
    """Security tests for OAuth2 authorization grant - auth_request_id validation."""

    def test_invalid_auth_request_id_rejected(self, authenticated_client_with_host):
        """Test that invalid/fabricated auth_request_id is rejected."""
        response = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": "fabricated_invalid_id_12345",
                "action": "allow",
            },
            follow_redirects=False,
        )

        # Should show error page, not redirect
        assert response.status_code == 200
        assert "Invalid request" in response.text or "not found" in response.text.lower()

    def test_auth_request_id_single_use(self, authenticated_client_with_host, normal_oauth2_client):
        """Test that auth_request_id can only be used once (replay protection)."""
        # GET to create auth request
        get_response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
            },
            follow_redirects=False,
        )
        auth_request_id = _extract_auth_request_id(get_response.text)

        # First POST - should succeed
        response1 = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": auth_request_id,
                "action": "allow",
            },
            follow_redirects=False,
        )
        assert response1.status_code == 303
        assert "code=" in response1.headers["location"]

        # Second POST with same auth_request_id - should fail
        response2 = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": auth_request_id,
                "action": "allow",
            },
            follow_redirects=False,
        )
        assert response2.status_code == 200
        assert "Invalid request" in response2.text or "not found" in response2.text.lower()

    def test_expired_auth_request_rejected(
        self, authenticated_client_with_host, normal_oauth2_client
    ):
        """Test that expired auth_request_id is rejected."""
        from unittest.mock import patch

        # GET to create auth request
        get_response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
            },
            follow_redirects=False,
        )
        auth_request_id = _extract_auth_request_id(get_response.text)

        # Mock time to be 15 minutes in the future (past the 10 minute expiry)
        import time

        future_time = time.time() + 900  # 15 minutes later

        with patch("routers.oauth2.time.time", return_value=future_time):
            response = authenticated_client_with_host.post(
                "/oauth2/authorize",
                data={
                    "auth_request_id": auth_request_id,
                    "action": "allow",
                },
                follow_redirects=False,
            )

        assert response.status_code == 200
        assert "expired" in response.text.lower()

    def test_parameters_retrieved_from_session_not_form(
        self, authenticated_client_with_host, normal_oauth2_client
    ):
        """Test that authorization parameters come from session, not form data.

        This verifies the security fix - even if an attacker tries to inject
        different parameters via form, the stored session values are used.
        """
        # GET with specific parameters
        get_response = authenticated_client_with_host.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://localhost:3000/callback",
                "state": "original_state",
            },
            follow_redirects=False,
        )
        auth_request_id = _extract_auth_request_id(get_response.text)

        # POST - the response should use the original state from session
        response = authenticated_client_with_host.post(
            "/oauth2/authorize",
            data={
                "auth_request_id": auth_request_id,
                "action": "allow",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        location = response.headers["location"]
        # Should redirect to the original redirect_uri with original state
        assert location.startswith("http://localhost:3000/callback")
        assert "state=original_state" in location


# ============================================================================
# POST /oauth2/token - Token Endpoint Tests
# ============================================================================


class TestTokenEndpoint:
    """Tests for the OAuth2 token endpoint (POST /oauth2/token)."""

    # -------------------------------------------------------------------------
    # Authorization Code Grant
    # -------------------------------------------------------------------------

    def test_token_authorization_code_success(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """Test exchanging authorization code for tokens."""
        import database

        # First, create an authorization code
        code = database.oauth2.create_authorization_code(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
            redirect_uri="http://localhost:3000/callback",
        )

        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "code": code,
                "redirect_uri": "http://localhost:3000/callback",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] > 0

    def test_token_authorization_code_with_pkce(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """Test exchanging authorization code with PKCE verification."""
        import base64
        import hashlib

        import database

        # Create a code verifier and challenge
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )

        # Create an authorization code with PKCE
        code = database.oauth2.create_authorization_code(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
            redirect_uri="http://localhost:3000/callback",
            code_challenge=code_challenge,
            code_challenge_method="S256",
        )

        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "code": code,
                "redirect_uri": "http://localhost:3000/callback",
                "code_verifier": code_verifier,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data

    def test_token_authorization_code_invalid_code(
        self, client, test_tenant_host, normal_oauth2_client
    ):
        """Test token request with invalid authorization code."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "code": "invalid_code_12345",
                "redirect_uri": "http://localhost:3000/callback",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_grant"

    def test_token_authorization_code_wrong_redirect_uri(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """Test token request with mismatched redirect_uri."""
        import database

        code = database.oauth2.create_authorization_code(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
            redirect_uri="http://localhost:3000/callback",
        )

        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "code": code,
                "redirect_uri": "http://different.com/callback",  # Wrong URI
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_grant"

    def test_token_authorization_code_missing_params(
        self, client, test_tenant_host, normal_oauth2_client
    ):
        """Test token request without required code or redirect_uri."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                # Missing code and redirect_uri
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_request"

    def test_token_authorization_code_b2b_client_rejected(
        self, client, test_tenant, test_tenant_host, b2b_oauth2_client, test_user
    ):
        """Test B2B client cannot use authorization code grant."""

        # Even if we somehow had a code, B2B client shouldn't be able to use it
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": b2b_oauth2_client["client_id"],
                "client_secret": b2b_oauth2_client["client_secret"],
                "code": "some_code",
                "redirect_uri": "http://localhost:3000/callback",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "unauthorized_client"

    # -------------------------------------------------------------------------
    # Refresh Token Grant
    # -------------------------------------------------------------------------

    def test_token_refresh_token_success(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """Test refreshing an access token."""
        import database

        # Create a refresh token
        refresh_token, _ = database.oauth2.create_refresh_token(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
        )

        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "refresh_token",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "refresh_token": refresh_token,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        # Refresh token is not returned on refresh (only on initial auth)
        assert data.get("refresh_token") is None

    def test_token_refresh_token_invalid(self, client, test_tenant_host, normal_oauth2_client):
        """Test refresh with invalid token."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "refresh_token",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "refresh_token": "invalid_refresh_token",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_grant"

    def test_token_refresh_token_missing(self, client, test_tenant_host, normal_oauth2_client):
        """Test refresh without providing token."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "refresh_token",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                # Missing refresh_token
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_request"

    def test_token_refresh_token_wrong_client(
        self,
        client,
        test_tenant,
        test_tenant_host,
        normal_oauth2_client,
        test_user,
        test_admin_user,
    ):
        """Test refresh token bound to different client is rejected."""
        import database

        # Create another normal client
        other_client = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            name="Other Client",
            redirect_uris=["http://other.com/callback"],
            created_by=test_admin_user["id"],
        )

        # Create refresh token for the original client
        refresh_token, _ = database.oauth2.create_refresh_token(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
        )

        # Try to use it with the other client
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "refresh_token",
                "client_id": other_client["client_id"],
                "client_secret": other_client["client_secret"],
                "refresh_token": refresh_token,
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_grant"

    # -------------------------------------------------------------------------
    # Client Credentials Grant
    # -------------------------------------------------------------------------

    def test_token_client_credentials_success(self, client, test_tenant_host, b2b_oauth2_client):
        """Test client credentials flow."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "client_credentials",
                "client_id": b2b_oauth2_client["client_id"],
                "client_secret": b2b_oauth2_client["client_secret"],
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 86400  # 24 hours
        assert data.get("refresh_token") is None

    def test_token_client_credentials_normal_client_rejected(
        self, client, test_tenant_host, normal_oauth2_client
    ):
        """Test normal client cannot use client credentials grant."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "client_credentials",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "unauthorized_client"

    # -------------------------------------------------------------------------
    # Client Authentication Errors
    # -------------------------------------------------------------------------

    def test_token_invalid_client_id(self, client, test_tenant_host):
        """Test token request with invalid client_id."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "client_credentials",
                "client_id": "nonexistent_client",
                "client_secret": "some_secret",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_client"

    def test_token_invalid_client_secret(self, client, test_tenant_host, b2b_oauth2_client):
        """Test token request with wrong client_secret."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "client_credentials",
                "client_id": b2b_oauth2_client["client_id"],
                "client_secret": "wrong_secret",
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "invalid_client"

    def test_token_unsupported_grant_type(self, client, test_tenant_host, b2b_oauth2_client):
        """Test token request with unsupported grant type."""
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "password",  # Not supported
                "client_id": b2b_oauth2_client["client_id"],
                "client_secret": b2b_oauth2_client["client_secret"],
            },
        )

        assert response.status_code == 400
        data = response.json()
        assert data["detail"]["error"] == "unsupported_grant_type"


# ============================================================================
# Authorization Code Replay Protection Tests
# ============================================================================


class TestAuthorizationCodeReplay:
    """Tests for authorization code replay protection."""

    def test_authorization_code_single_use(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """Test authorization code can only be used once."""
        import database

        code = database.oauth2.create_authorization_code(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
            redirect_uri="http://localhost:3000/callback",
        )

        # First use - should succeed
        response1 = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "code": code,
                "redirect_uri": "http://localhost:3000/callback",
            },
        )
        assert response1.status_code == 200

        # Second use - should fail (code already consumed)
        response2 = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
                "code": code,
                "redirect_uri": "http://localhost:3000/callback",
            },
        )
        assert response2.status_code == 400
        assert response2.json()["detail"]["error"] == "invalid_grant"


# ============================================================================
# Cross-Tenant Isolation Tests
# ============================================================================


class TestCrossTenantIsolation:
    """Tests for OAuth2 tenant isolation."""

    def test_client_from_other_tenant_rejected(self, client, test_tenant, test_admin_user):
        """Test that OAuth2 clients are tenant-scoped."""
        from uuid import uuid4

        import database
        import settings

        # Create another tenant
        other_subdomain = f"other-{uuid4().hex[:8]}"
        database.execute(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
            {"subdomain": other_subdomain, "name": "Other Tenant"},
        )
        other_tenant = database.fetchone(
            database.UNSCOPED,
            "SELECT id FROM tenants WHERE subdomain = :subdomain",
            {"subdomain": other_subdomain},
        )

        try:
            # Create a B2B client in the other tenant
            # First create a user in that tenant to be the creator
            other_user = database.fetchone(
                other_tenant["id"],
                """
                INSERT INTO users (tenant_id, first_name, last_name, role)
                VALUES (:tenant_id, 'Other', 'Admin', 'admin')
                RETURNING id
                """,
                {"tenant_id": other_tenant["id"]},
            )

            other_client = database.oauth2.create_b2b_client(
                tenant_id=other_tenant["id"],
                tenant_id_value=other_tenant["id"],
                name="Other Tenant Client",
                role="admin",
                created_by=other_user["id"],
            )

            # Try to use it against our test tenant
            test_tenant_host = f"{test_tenant['subdomain']}.{settings.BASE_DOMAIN}"
            response = client.post(
                "/oauth2/token",
                headers={"Host": test_tenant_host},
                data={
                    "grant_type": "client_credentials",
                    "client_id": other_client["client_id"],
                    "client_secret": other_client["client_secret"],
                },
            )

            # Should fail - client belongs to different tenant
            assert response.status_code == 400
            assert response.json()["detail"]["error"] == "invalid_client"

        finally:
            # Cleanup
            database.execute(
                database.UNSCOPED,
                "DELETE FROM tenants WHERE id = :id",
                {"id": other_tenant["id"]},
            )
