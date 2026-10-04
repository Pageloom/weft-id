"""Tests for the shared OAuth2 adapter plumbing (services.oidc_upstream._oauth2)."""

import httpx
import pytest
from services.oidc_upstream import _oauth2

from tests.fixtures.oauth2_api import mock_provider_api


class TestApiGet:
    def test_sends_token_and_headers(self):
        with mock_provider_api({"/v1/me": {"id": 1}}) as requests:
            body = _oauth2.api_get(
                "https://api.example.com/v1/me",
                access_token="tok",
                headers={"Accept": "application/json"},
                params={"fields": "id"},
            )
        assert body == {"id": 1}
        assert requests[0].headers["authorization"] == "Bearer tok"
        assert requests[0].headers["accept"] == "application/json"
        assert requests[0].url.params["fields"] == "id"

    @pytest.mark.parametrize(
        ("response", "message"),
        [
            (httpx.Response(403), "/v1/me returned HTTP 403"),
            (httpx.Response(200, content=b"{"), "/v1/me returned invalid JSON"),
        ],
    )
    def test_failures(self, response, message):
        with mock_provider_api({"/v1/me": response}):
            with pytest.raises(_oauth2.ProviderAPIError, match=message):
                _oauth2.api_get("https://api.example.com/v1/me?x=1", access_token="tok")

    def test_transport_failure(self):
        def boom(request):
            raise httpx.ConnectError("down")

        with mock_provider_api({"/v1/me": boom}):
            with pytest.raises(_oauth2.ProviderAPIError, match="/v1/me failed"):
                _oauth2.api_get("https://api.example.com/v1/me", access_token="tok")


class TestRequestStatus:
    def test_returns_status(self):
        with mock_provider_api({"/token": httpx.Response(401)}):
            assert _oauth2.request_status("POST", "https://api.example.com/token") == 401

    def test_transport_failure(self):
        def boom(request):
            raise httpx.ConnectError("down")

        with mock_provider_api({"/token": boom}):
            with pytest.raises(_oauth2.ProviderAPIError, match="/token failed"):
                _oauth2.request_status("POST", "https://api.example.com/token")


class TestSplitName:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("Ada Lovelace", ("Ada", "Lovelace")),
            ("  Ada  King Lovelace ", ("Ada", "King Lovelace")),
            ("Ada", ("Ada", None)),
            ("", ("fallback", None)),
            ("   ", ("fallback", None)),
            (None, ("fallback", None)),
            (42, ("fallback", None)),
        ],
    )
    def test_split(self, name, expected):
        assert _oauth2.split_name(name, "fallback") == expected
