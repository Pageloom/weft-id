"""Tests for OIDC upstream login-initiation helpers (PKCE, state, nonce, URL)."""

import base64
import hashlib

from services.oidc_upstream import auth as auth_helpers


class TestPkce:
    def test_generate_pkce_pair_returns_verifier_and_challenge(self):
        verifier, challenge = auth_helpers.generate_pkce_pair()
        assert verifier
        assert challenge
        assert verifier != challenge

    def test_challenge_is_s256_of_verifier(self):
        verifier, challenge = auth_helpers.generate_pkce_pair()
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        assert challenge == expected

    def test_verifier_is_high_entropy(self):
        a, _ = auth_helpers.generate_pkce_pair()
        b, _ = auth_helpers.generate_pkce_pair()
        assert a != b


class TestStateAndNonce:
    def test_state_is_high_entropy(self):
        assert auth_helpers.generate_state() != auth_helpers.generate_state()

    def test_nonce_is_high_entropy(self):
        assert auth_helpers.generate_nonce() != auth_helpers.generate_nonce()


class TestBuildAuthorizeUrl:
    def test_builds_url_with_required_params(self):
        url = auth_helpers.build_authorize_url(
            authorization_endpoint="https://idp.example.com/authorize",
            client_id="client-123",
            redirect_uri="https://tenant.example.com/auth/oidc/c1/callback",
            state="state-1",
            nonce="nonce-1",
            code_challenge="challenge-1",
            scopes="openid profile email",
        )
        assert url.startswith("https://idp.example.com/authorize?")
        assert "response_type=code" in url
        assert "client_id=client-123" in url
        assert "state=state-1" in url
        assert "nonce=nonce-1" in url
        assert "code_challenge=challenge-1" in url
        assert "code_challenge_method=S256" in url
        assert "scope=openid+profile+email" in url

    def test_includes_hosted_domain_when_set(self):
        url = auth_helpers.build_authorize_url(
            authorization_endpoint="https://idp.example.com/authorize",
            client_id="client-123",
            redirect_uri="https://tenant.example.com/cb",
            state="s",
            nonce="n",
            code_challenge="c",
            scopes="openid",
            hosted_domain="example.com",
        )
        assert "hd=example.com" in url

    def test_omits_hosted_domain_when_none(self):
        url = auth_helpers.build_authorize_url(
            authorization_endpoint="https://idp.example.com/authorize",
            client_id="client-123",
            redirect_uri="https://tenant.example.com/cb",
            state="s",
            nonce="n",
            code_challenge="c",
            scopes="openid",
        )
        assert "hd=" not in url
