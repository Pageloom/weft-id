"""Tests for the connector's bounded response reader."""

import httpx
import pytest
from services.oidc_upstream import _http


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_safe_client_options_carry_a_total_budget():
    assert _http.SAFE_CLIENT_OPTIONS["timeout"] == _http.FETCH_TIMEOUT_SECONDS
    assert _http.SAFE_CLIENT_OPTIONS["total_timeout"] == _http.TOTAL_TIMEOUT_SECONDS
    assert _http.SAFE_CLIENT_OPTIONS["dev_base_domain_rewrite"] is True
    assert _http.SAFE_CLIENT_OPTIONS["dev_hostname_allowlist"] == _http.DEV_HOSTNAME_ALLOWLIST


def test_returns_status_and_body():
    with _client(lambda request: httpx.Response(200, content=b'{"a": 1}')) as client:
        assert _http.read_capped(client, "GET", "https://idp.example.com/x") == (200, b'{"a": 1}')


def test_passes_request_arguments_through():
    seen = {}

    def handler(request):
        seen["method"] = request.method
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.content
        return httpx.Response(200, content=b"{}")

    with _client(handler) as client:
        _http.read_capped(
            client, "POST", "https://idp.example.com/token", data={"k": "v"}, auth=("id", "pw")
        )
    assert seen["method"] == "POST"
    assert seen["auth"].startswith("Basic ")
    assert seen["body"] == b"k=v"


def test_body_of_a_non_200_is_not_read():
    class _Body(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("the body must not be read")

    with _client(lambda request: httpx.Response(503, stream=_Body())) as client:
        assert _http.read_capped(client, "GET", "https://idp.example.com/x") == (503, b"")


def test_oversized_body_is_refused(monkeypatch):
    monkeypatch.setattr(_http, "MAX_RESPONSE_BYTES", 8)
    with _client(lambda request: httpx.Response(200, content=b"123456789")) as client:
        with pytest.raises(_http.ResponseTooLargeError):
            _http.read_capped(client, "GET", "https://idp.example.com/x")


def test_body_at_the_cap_is_accepted(monkeypatch):
    monkeypatch.setattr(_http, "MAX_RESPONSE_BYTES", 8)
    with _client(lambda request: httpx.Response(200, content=b"12345678")) as client:
        assert _http.read_capped(client, "GET", "https://idp.example.com/x") == (200, b"12345678")
