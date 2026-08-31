"""Tests for OIDC upstream JWKS fetching and caching.

Covers cache hit/miss/rotation and the SSRF guard. No live network calls:
the safe client is patched with a fake response.
"""

from unittest.mock import patch

import pytest
from services.oidc_upstream import jwks as jwks_service
from services.oidc_upstream.errors import JwksError

from tests.fixtures.oidc import load_fixture

JWKS_DOC = load_fixture("jwks")


class _FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json_body = json_body

    def json(self):
        if self._json_body is None:
            raise ValueError("no json")
        return self._json_body


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, url):
        return self._response


def _patch_client(response):
    return patch(
        "services.oidc_upstream.jwks.build_safe_client",
        return_value=_FakeClient(response),
    )


class TestGetJwks:
    def test_fetch_and_parse(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        with _patch_client(_FakeResponse(200, JWKS_DOC)):
            key_set = jwks_service.get_jwks("t1", "c1", "https://idp.example.com/jwks")
        assert len(list(key_set)) == 1

    def test_cache_hit_avoids_refetch(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        with _patch_client(_FakeResponse(200, JWKS_DOC)):
            jwks_service.get_jwks("t1", "c1", "https://idp.example.com/jwks")

        # Second call within TTL does not hit the network.
        with _patch_client(_FakeResponse(500)) as mock:
            key_set = jwks_service.get_jwks("t1", "c1", "https://idp.example.com/jwks")
            assert mock.call_count == 0
        assert len(list(key_set)) == 1

    def test_refresh_forces_refetch(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        with _patch_client(_FakeResponse(200, JWKS_DOC)):
            jwks_service.get_jwks("t1", "c1", "https://idp.example.com/jwks")

        with _patch_client(_FakeResponse(200, JWKS_DOC)) as mock:
            jwks_service.refresh_jwks("t1", "c1", "https://idp.example.com/jwks")
            assert mock.call_count == 1

    def test_http_error_raises(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        with _patch_client(_FakeResponse(500)):
            with pytest.raises(JwksError):
                jwks_service.get_jwks("t1", "c1", "https://idp.example.com/jwks")

    def test_missing_keys_raises(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        with _patch_client(_FakeResponse(200, {"not": "keys"})):
            with pytest.raises(JwksError):
                jwks_service.get_jwks("t1", "c1", "https://idp.example.com/jwks")

    def test_private_address_refused(self):
        jwks_service.clear_jwks_cache("t1", "c1")
        with pytest.raises(JwksError):
            jwks_service._fetch_jwks("http://127.0.0.1/jwks")
