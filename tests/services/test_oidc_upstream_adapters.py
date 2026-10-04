"""Tests for the OIDC upstream provider adapter seam.

Covers adapter selection, the single credential resolver and callback URL
builder, ``client_secret_post`` token exchange, and the spec OIDC adapter's
login and completion steps (each failure maps to its audit reason). No live
network calls.
"""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import jwt
import pytest
from services.oidc_upstream import adapters, presets
from services.oidc_upstream import token_exchange as te
from services.oidc_upstream.connections import _encrypt_secret
from services.oidc_upstream.errors import DiscoveryIssuerMismatchError

from tests.fixtures.oidc import load_fixture, load_fixture_text


class _FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json_body = json_body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_bytes(self):
        yield json.dumps(self._json_body).encode()


class _RecordingClient:
    """A fake safe client that records each request's keyword arguments."""

    def __init__(self, response):
        self._response = response
        self.calls: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self._response


def _connection(**overrides):
    row = {
        "id": "11111111-1111-1111-1111-111111111111",
        "name": "Test",
        "provider_type": "generic",
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "userinfo_endpoint": None,
        "jwks_uri": "https://idp.example.com/jwks",
        "client_id": "client-123",
        "client_secret_enc": _encrypt_secret("secret-123"),
        "scopes": "openid profile email",
        "correlation_claim": "sub",
        "hosted_domain": None,
    }
    row.update(overrides)
    return row


def _id_token(**overrides):
    now = datetime.now(UTC)
    claims = {
        "iss": "https://idp.example.com",
        "aud": "client-123",
        "sub": "subject-123",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "nonce": "n-1",
        "sid": "session-1",
        "email": "user@example.com",
    }
    claims.update(overrides)
    return jwt.encode(
        claims,
        load_fixture_text("private_key.pem"),
        algorithm="RS256",
        headers={"kid": "oidc-upstream-fixture-key"},
    )


@pytest.fixture(autouse=True)
def _clear_jwks():
    from services.oidc_upstream import jwks

    jwks.clear_jwks_cache("t1", "11111111-1111-1111-1111-111111111111")
    yield


def _complete(connection, token_response, **kwargs):
    with (
        patch("services.oidc_upstream.exchange_code", return_value=token_response) as exchange,
        patch("services.oidc_upstream.jwks._fetch_jwks", return_value=load_fixture("jwks")),
    ):
        identity = adapters.SpecOIDCAdapter().complete(
            "t1",
            connection,
            code="code-1",
            redirect_uri="https://t.example.com/cb",
            code_verifier="verifier-1",
            nonce=kwargs.get("nonce", "n-1"),
        )
    return identity, exchange


class TestGetAdapter:
    @pytest.mark.parametrize(
        "provider_type", ["generic", "google", "entra", "microsoft", "linkedin", "gitlab", None]
    )
    def test_spec_oidc_is_default(self, provider_type):
        assert isinstance(adapters.get_adapter(provider_type), adapters.SpecOIDCAdapter)


class TestCallbackUrl:
    def test_builds_tenant_callback(self):
        assert adapters.callback_url("https://acme.example.com", "abc") == (
            "https://acme.example.com/auth/oidc/abc/callback"
        )


class TestResolveClientCredentials:
    def test_decrypts_secret(self):
        creds = adapters.resolve_client_credentials(_connection())
        assert creds == adapters.ClientCredentials(
            client_id="client-123",
            client_secret="secret-123",
            token_auth_method=presets.TOKEN_AUTH_BASIC,
        )

    def test_linkedin_posts_credentials(self):
        creds = adapters.resolve_client_credentials(_connection(provider_type="linkedin"))
        assert creds.token_auth_method == presets.TOKEN_AUTH_POST

    @pytest.mark.parametrize("missing", ["client_id", "client_secret_enc"])
    def test_missing_credentials(self, missing):
        assert adapters.resolve_client_credentials(_connection(**{missing: None})) is None


class TestTokenAuthMethod:
    def _exchange(self, auth_method=None):
        client = _RecordingClient(_FakeResponse(200, {"access_token": "at"}))
        kwargs = {} if auth_method is None else {"auth_method": auth_method}
        with patch("services.oidc_upstream.token_exchange.build_safe_client", return_value=client):
            te.exchange_code(
                token_endpoint="https://idp.example.com/token",
                client_id="cid",
                client_secret="secret",
                code="code",
                redirect_uri="https://rp.example.com/cb",
                code_verifier="verifier",
                **kwargs,
            )
        return client.calls[0]

    def test_basic_is_default(self):
        call = self._exchange()
        assert call["auth"] == ("cid", "secret")
        assert "client_secret" not in call["data"]

    def test_post_sends_credentials_in_body(self):
        call = self._exchange("client_secret_post")
        assert call["auth"] is None
        assert call["data"]["client_id"] == "cid"
        assert call["data"]["client_secret"] == "secret"
        assert call["data"]["code_verifier"] == "verifier"


class TestSpecAuthorizeUrl:
    def test_builds_url(self):
        url = adapters.SpecOIDCAdapter().authorize_url(
            _connection(hosted_domain="example.com"),
            redirect_uri="https://t.example.com/cb",
            state="s",
            nonce="n",
            code_challenge="c",
        )
        assert url.startswith("https://idp.example.com/authorize?")
        assert "client_id=client-123" in url
        assert "hd=example.com" in url
        assert "code_challenge_method=S256" in url

    def test_falls_back_to_default_scopes(self):
        url = adapters.SpecOIDCAdapter().authorize_url(
            _connection(scopes=None),
            redirect_uri="https://t.example.com/cb",
            state="s",
            nonce="n",
            code_challenge="c",
        )
        assert "scope=openid+profile+email" in url

    @pytest.mark.parametrize("missing", ["authorization_endpoint", "client_id"])
    def test_unconfigured(self, missing):
        with pytest.raises(adapters.ProviderLoginError) as exc_info:
            adapters.SpecOIDCAdapter().authorize_url(
                _connection(**{missing: None}),
                redirect_uri="https://t.example.com/cb",
                state="s",
                nonce="n",
                code_challenge="c",
            )
        assert exc_info.value.public_error == "configuration_error"


class TestSpecPrepare:
    def test_delegates_to_discovery_refresh(self):
        conn = _connection()
        with patch(
            "services.oidc_upstream.refresh_for_login", return_value={**conn, "x": 1}
        ) as refresh:
            result = adapters.SpecOIDCAdapter().prepare("t1", conn)
        refresh.assert_called_once_with("t1", conn)
        assert result["x"] == 1

    def test_discovery_error_propagates(self):
        with patch(
            "services.oidc_upstream.refresh_for_login",
            side_effect=DiscoveryIssuerMismatchError("a", "b"),
        ):
            with pytest.raises(DiscoveryIssuerMismatchError):
                adapters.SpecOIDCAdapter().prepare("t1", _connection())


class TestSpecComplete:
    def test_returns_identity(self):
        token = _id_token()
        identity, exchange = _complete(_connection(), {"access_token": "at", "id_token": token})
        assert identity.subject == "subject-123"
        assert identity.claims["email"] == "user@example.com"
        assert identity.upstream_sub == "subject-123"
        assert identity.upstream_sid == "session-1"
        assert identity.id_token == token
        kwargs = exchange.call_args.kwargs
        assert kwargs["client_secret"] == "secret-123"
        assert kwargs["auth_method"] == presets.TOKEN_AUTH_BASIC
        assert kwargs["redirect_uri"] == "https://t.example.com/cb"
        assert kwargs["code_verifier"] == "verifier-1"

    def test_linkedin_exchanges_with_post(self):
        _, exchange = _complete(_connection(provider_type="linkedin"), {"id_token": _id_token()})
        assert exchange.call_args.kwargs["auth_method"] == presets.TOKEN_AUTH_POST

    def test_correlates_on_configured_claim(self):
        identity, _ = _complete(
            _connection(correlation_claim="oid"), {"id_token": _id_token(oid="object-1")}
        )
        assert identity.subject == "object-1"
        # The session subject stays the ID token's sub.
        assert identity.upstream_sub == "subject-123"

    def test_non_string_sid_dropped(self):
        identity, _ = _complete(_connection(), {"id_token": _id_token(sid=42)})
        assert identity.upstream_sid is None

    def test_userinfo_merged_without_overriding_id_token(self):
        conn = _connection(userinfo_endpoint="https://idp.example.com/userinfo")
        userinfo = {"sub": "subject-123", "email": "other@example.com", "locale": "sv"}
        with patch("services.oidc_upstream.fetch_userinfo", return_value=userinfo):
            identity, _ = _complete(conn, {"access_token": "at", "id_token": _id_token()})
        assert identity.claims["locale"] == "sv"
        assert identity.claims["email"] == "user@example.com"

    @pytest.mark.parametrize(
        ("overrides", "token_response", "reason", "public_error"),
        [
            ({"token_endpoint": None}, {}, "configuration_error", "configuration_error"),
            ({"client_secret_enc": None}, {}, "configuration_error", "configuration_error"),
            ({}, {"access_token": "at"}, "missing_id_token", "auth_failed"),
            ({"jwks_uri": None}, None, "configuration_error", "configuration_error"),
            ({}, {"id_token": "not-a-jwt"}, "id_token", "auth_failed"),
            ({"correlation_claim": "employee_id"}, None, "missing_sub", "auth_failed"),
        ],
    )
    def test_failures_carry_reason(self, overrides, token_response, reason, public_error):
        if token_response is None:
            token_response = {"id_token": _id_token()}
        with pytest.raises(adapters.ProviderLoginError) as exc_info:
            _complete(_connection(**overrides), token_response)
        assert exc_info.value.reason == reason
        assert exc_info.value.public_error == public_error

    def test_token_exchange_failure(self):
        with (
            patch(
                "services.oidc_upstream.exchange_code",
                side_effect=te.TokenExchangeError("HTTP 400"),
            ),
            pytest.raises(adapters.ProviderLoginError) as exc_info,
        ):
            adapters.SpecOIDCAdapter().complete(
                "t1",
                _connection(),
                code="c",
                redirect_uri="https://t.example.com/cb",
                code_verifier="v",
                nonce="n-1",
            )
        assert exc_info.value.reason == "token_exchange"
        assert "400" in exc_info.value.detail

    def test_userinfo_subject_mismatch(self):
        conn = _connection(userinfo_endpoint="https://idp.example.com/userinfo")
        with (
            patch(
                "services.oidc_upstream.fetch_userinfo",
                side_effect=te.UserinfoSubjectMismatchError("mismatch"),
            ),
            pytest.raises(adapters.ProviderLoginError) as exc_info,
        ):
            _complete(conn, {"access_token": "at", "id_token": _id_token()})
        assert exc_info.value.reason == "userinfo_sub_mismatch"

    def test_userinfo_unreachable_is_tolerated(self):
        conn = _connection(userinfo_endpoint="https://idp.example.com/userinfo")
        with patch(
            "services.oidc_upstream.fetch_userinfo", side_effect=te.UserinfoError("HTTP 503")
        ):
            identity, _ = _complete(conn, {"access_token": "at", "id_token": _id_token()})
        assert identity.subject == "subject-123"


class TestProviderLoginError:
    def test_message_defaults_to_reason(self):
        err = adapters.ProviderLoginError("missing_sub")
        assert str(err) == "missing_sub"
        assert err.detail is None
        assert err.public_error == "auth_failed"
