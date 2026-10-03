"""Tests for OIDC upstream token exchange and userinfo helpers.

Both go through the SSRF guard; the safe client is patched with a fake
response so no live network calls occur.
"""

import json
from unittest.mock import patch

import pytest
from services.oidc_upstream import token_exchange as te


class _FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json_body = json_body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_bytes(self):
        yield b"not json" if self._json_body is None else json.dumps(self._json_body).encode()


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url, **kwargs):
        return self._response


def _patch_client(response):
    return patch(
        "services.oidc_upstream.token_exchange.build_safe_client",
        return_value=_FakeClient(response),
    )


class TestExchangeCode:
    def test_success(self):
        body = {"access_token": "at", "id_token": "idt", "token_type": "Bearer"}
        with _patch_client(_FakeResponse(200, body)):
            result = te.exchange_code(
                token_endpoint="https://idp.example.com/token",
                client_id="cid",
                client_secret="secret",
                code="code",
                redirect_uri="https://rp.example.com/cb",
                code_verifier="verifier",
            )
        assert result["access_token"] == "at"

    def test_error_response(self):
        with _patch_client(_FakeResponse(200, {"error": "invalid_grant"})):
            with pytest.raises(te.TokenExchangeError):
                te.exchange_code(
                    token_endpoint="https://idp.example.com/token",
                    client_id="cid",
                    client_secret="secret",
                    code="code",
                    redirect_uri="https://rp.example.com/cb",
                    code_verifier="verifier",
                )

    def test_http_error(self):
        with _patch_client(_FakeResponse(400)):
            with pytest.raises(te.TokenExchangeError):
                te.exchange_code(
                    token_endpoint="https://idp.example.com/token",
                    client_id="cid",
                    client_secret="secret",
                    code="code",
                    redirect_uri="https://rp.example.com/cb",
                    code_verifier="verifier",
                )


class TestSsrFGuard:
    def test_exchange_code_private_address_refused(self):
        with pytest.raises(te.TokenExchangeError):
            te.exchange_code(
                token_endpoint="http://127.0.0.1/token",
                client_id="cid",
                client_secret="secret",
                code="code",
                redirect_uri="https://rp.example.com/cb",
                code_verifier="verifier",
            )

    def test_exchange_code_link_local_refused(self):
        with pytest.raises(te.TokenExchangeError):
            te.exchange_code(
                token_endpoint="http://169.254.169.254/latest/meta-data",
                client_id="cid",
                client_secret="secret",
                code="code",
                redirect_uri="https://rp.example.com/cb",
                code_verifier="verifier",
            )

    def test_fetch_userinfo_private_address_refused(self):
        with pytest.raises(te.UserinfoError):
            te.fetch_userinfo(
                userinfo_endpoint="http://127.0.0.1/userinfo",
                access_token="at",
                expected_sub="subject-123",
            )


class TestFetchUserinfo:
    def test_success(self):
        body = {"sub": "subject-123", "email": "a@example.com"}
        with _patch_client(_FakeResponse(200, body)):
            result = te.fetch_userinfo(
                userinfo_endpoint="https://idp.example.com/userinfo",
                access_token="at",
                expected_sub="subject-123",
            )
        assert result["email"] == "a@example.com"

    def test_http_error(self):
        with _patch_client(_FakeResponse(401)):
            with pytest.raises(te.UserinfoError):
                te.fetch_userinfo(
                    userinfo_endpoint="https://idp.example.com/userinfo",
                    access_token="at",
                    expected_sub="subject-123",
                )

    @pytest.mark.parametrize(
        "body",
        [
            {"sub": "someone-else", "email": "a@example.com"},
            {"email": "a@example.com"},
            {"sub": 123},
        ],
        ids=["different", "missing", "not-a-string"],
    )
    def test_sub_mismatch_refused(self, body):
        """OIDC Core 5.3.2: a response whose sub differs must not be used.

        The error is not a UserinfoError, which callers tolerate."""
        with _patch_client(_FakeResponse(200, body)):
            with pytest.raises(te.UserinfoSubjectMismatchError) as exc:
                te.fetch_userinfo(
                    userinfo_endpoint="https://idp.example.com/userinfo",
                    access_token="at",
                    expected_sub="subject-123",
                )
        assert not isinstance(exc.value, te.UserinfoError)


class TestDevBaseDomainRewrite:
    """The upstream fetchers opt into the SSRF guard's dev-only base-domain
    rewrite so a dev-stack tenant can be its own upstream IdP (loopback E2E).
    The flag is inert outside IS_DEV (see utils.safe_http)."""

    def test_exchange_code_passes_flag(self):
        body = {"access_token": "at", "id_token": "idt"}
        with _patch_client(_FakeResponse(200, body)) as mock_client:
            te.exchange_code(
                token_endpoint="https://idp.example.com/token",
                client_id="cid",
                client_secret="secret",
                code="code",
                redirect_uri="https://rp.example.com/cb",
                code_verifier="verifier",
            )
        assert mock_client.call_args.kwargs["dev_base_domain_rewrite"] is True
        assert mock_client.call_args.kwargs["dev_hostname_allowlist"] == frozenset(
            {"localhost.emobix.co.uk"}
        )

    def test_fetch_userinfo_passes_flag(self):
        with _patch_client(_FakeResponse(200, {"sub": "s"})) as mock_client:
            te.fetch_userinfo(
                userinfo_endpoint="https://idp.example.com/ui", access_token="at", expected_sub="s"
            )
        assert mock_client.call_args.kwargs["dev_base_domain_rewrite"] is True
        assert mock_client.call_args.kwargs["dev_hostname_allowlist"] == frozenset(
            {"localhost.emobix.co.uk"}
        )
