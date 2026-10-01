"""Request objects (OpenID Connect Core 1.0 section 6): verification, merge
rules, and fetching by reference. Pure service tests with inline client keys
and an in-process HTTP transport."""

import logging
import time

import httpx
import jwt
import pytest
from services import oauth2_request_objects as svc
from services.exceptions import ValidationError

from tests.helpers.client_keys import (
    EC_KEY,
    JWKS,
    OTHER_RSA_KEY,
    RSA_KEY,
    make_request_object,
)

ISSUER = "https://acme.weftid.example"
CLIENT_ID = "weft-id_client_ro"
REQUEST_URI = "https://rp.example.com/requests/one.jwt"


def _client(**extra) -> dict:
    client = {
        "id": "c-uuid",
        "client_id": CLIENT_ID,
        "jwks": JWKS,
        "jwks_uri": None,
        "registration_metadata": {"request_uris": [REQUEST_URI + "#v1"]},
    }
    client.update(extra)
    return client


def _claims(**overrides) -> dict:
    claims = {
        "iss": CLIENT_ID,
        "aud": ISSUER,
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": "https://rp.example.com/cb",
        "scope": "openid email",
        "state": "st-obj",
        "nonce": "n-obj",
    }
    for name, value in overrides.items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    return claims


def _resolve(client=None, *, request_object=None, request_uri=None, query_response_type="code"):
    return svc.resolve_request_object(
        "t1",
        client or _client(),
        request_object=request_object,
        request_uri=request_uri,
        issuer=ISSUER,
        query_client_id=CLIENT_ID,
        query_response_type=query_response_type,
    )


def _refused(code: str, **kwargs) -> None:
    with pytest.raises(ValidationError) as exc:
        _resolve(**kwargs)
    assert exc.value.code == code


def _mock_http(monkeypatch, handler):
    calls: list[str] = []

    def wrapped(request):
        calls.append(str(request.url))
        return handler(request)

    monkeypatch.setattr(
        svc,
        "build_safe_client",
        lambda **_: httpx.Client(transport=httpx.MockTransport(wrapped)),
    )
    return calls


class TestByValue:
    def test_returns_the_parameters(self):
        params = _resolve(request_object=make_request_object(_claims()))
        assert params == {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": "https://rp.example.com/cb",
            "scope": "openid email",
            "state": "st-obj",
            "nonce": "n-obj",
        }

    @pytest.mark.parametrize(
        ("key", "alg", "kid"),
        [(RSA_KEY, "PS256", "rsa-1"), (EC_KEY, "ES256", "ec-1"), (RSA_KEY, "RS256", None)],
    )
    def test_supported_algorithms(self, key, alg, kid):
        obj = make_request_object(_claims(), key=key, alg=alg, kid=kid)
        assert _resolve(request_object=obj)["state"] == "st-obj"

    def test_max_age_number_becomes_a_string(self):
        params = _resolve(request_object=make_request_object(_claims(max_age=300)))
        assert params["max_age"] == "300"

    def test_unknown_claims_are_ignored(self):
        claims = _claims(claims={"userinfo": {}}, request="nested", jti="x")
        params = _resolve(request_object=make_request_object(claims))
        assert "claims" not in params and "request" not in params

    def test_iss_aud_optional(self):
        params = _resolve(request_object=make_request_object(_claims(iss=None, aud=None)))
        assert params["client_id"] == CLIENT_ID

    def test_aud_array_and_trailing_slash(self):
        obj = make_request_object(_claims(aud=["https://other.example", ISSUER + "/"]))
        assert _resolve(request_object=obj)["state"] == "st-obj"

    def test_response_type_only_in_object(self):
        params = _resolve(request_object=make_request_object(_claims()), query_response_type=None)
        assert params["response_type"] == "code"


class TestByValueRefused:
    def test_unsigned(self):
        obj = jwt.encode(_claims(), key=None, algorithm="none")
        _refused(svc.INVALID_REQUEST_OBJECT, request_object=obj)

    def test_hmac_with_public_key_material(self):
        obj = jwt.encode(_claims(), "shared-secret-of-sufficient-length!", algorithm="HS256")
        _refused(svc.INVALID_REQUEST_OBJECT, request_object=obj)

    def test_unregistered_key(self):
        obj = make_request_object(_claims(), key=OTHER_RSA_KEY, kid=None)
        _refused(svc.INVALID_REQUEST_OBJECT, request_object=obj)

    def test_not_a_jwt(self):
        _refused(svc.INVALID_REQUEST_OBJECT, request_object="not-a-jwt")

    def test_registered_alg_enforced(self):
        client = _client(registration_metadata={"request_object_signing_alg": "ES256"})
        obj = make_request_object(_claims())
        _refused(svc.INVALID_REQUEST_OBJECT, client=client, request_object=obj)

    def test_registered_alg_accepted(self):
        client = _client(registration_metadata={"request_object_signing_alg": "ES256"})
        obj = make_request_object(_claims(), key=EC_KEY, alg="ES256", kid="ec-1")
        assert _resolve(client, request_object=obj)["state"] == "st-obj"

    def test_client_without_keys(self):
        client = _client(jwks=None, jwks_uri=None)
        _refused(
            svc.INVALID_REQUEST_OBJECT, client=client, request_object=make_request_object(_claims())
        )

    @pytest.mark.parametrize(
        "overrides",
        [
            {"iss": "someone-else"},
            {"aud": "https://other-op.example"},
            {"aud": ["https://other-op.example"]},
            {"exp": int(time.time()) - 600},
            {"nbf": int(time.time()) + 600},
            {"client_id": "another-client"},
            {"response_type": "token"},
            {"state": 7},
            {"max_age": True},
            {"scope": ["openid"]},
            {"state": "s" * 2049},
            {"nonce": "n" * 513},
        ],
    )
    def test_bad_claims(self, overrides):
        obj = make_request_object(_claims(**overrides))
        _refused(svc.INVALID_REQUEST_OBJECT, request_object=obj)

    def test_both_request_and_request_uri(self):
        _refused(
            svc.INVALID_REQUEST,
            request_object=make_request_object(_claims()),
            request_uri=REQUEST_URI,
        )

    def test_refusal_is_logged_without_the_object(self, caplog):
        obj = make_request_object(_claims(iss="someone-else"))
        with caplog.at_level(logging.INFO, logger=svc.__name__), pytest.raises(ValidationError):
            _resolve(request_object=obj)
        assert "iss is not the client_id" in caplog.text
        assert obj not in caplog.text


class TestByReference:
    def test_fetches_the_registered_uri(self, monkeypatch):
        obj = make_request_object(_claims())
        calls = _mock_http(monkeypatch, lambda _: httpx.Response(200, content=obj.encode()))
        # Registered with fragment #v1, requested with #v2: matched without it.
        assert _resolve(request_uri=REQUEST_URI + "#v2")["state"] == "st-obj"
        assert calls == [REQUEST_URI]

    def test_surrounding_whitespace_is_ignored(self, monkeypatch):
        obj = make_request_object(_claims())
        _mock_http(monkeypatch, lambda _: httpx.Response(200, content=f"\n{obj}\n".encode()))
        assert _resolve(request_uri=REQUEST_URI)["state"] == "st-obj"

    def test_unregistered_uri_is_never_fetched(self, monkeypatch):
        calls = _mock_http(monkeypatch, lambda _: httpx.Response(200))
        _refused(svc.INVALID_REQUEST_URI, request_uri="https://rp.example.com/other.jwt")
        assert calls == []

    def test_client_without_registered_uris(self, monkeypatch):
        _mock_http(monkeypatch, lambda _: httpx.Response(200))
        _refused(
            svc.INVALID_REQUEST_URI,
            client=_client(registration_metadata=None),
            request_uri=REQUEST_URI,
        )

    @pytest.mark.parametrize(
        "response",
        [httpx.Response(404), httpx.Response(200, content=b"x" * 20000)],
    )
    def test_unusable_responses(self, monkeypatch, response):
        _mock_http(monkeypatch, lambda _: response)
        _refused(svc.INVALID_REQUEST_URI, request_uri=REQUEST_URI)

    def test_empty_document(self, monkeypatch):
        _mock_http(monkeypatch, lambda _: httpx.Response(200, content=b"  "))
        _refused(svc.INVALID_REQUEST_OBJECT, request_uri=REQUEST_URI)

    def test_non_ascii_document(self, monkeypatch):
        _mock_http(monkeypatch, lambda _: httpx.Response(200, content="é".encode()))
        _refused(svc.INVALID_REQUEST_OBJECT, request_uri=REQUEST_URI)

    def test_fetched_object_is_verified(self, monkeypatch):
        obj = make_request_object(_claims(), key=OTHER_RSA_KEY, kid=None)
        _mock_http(monkeypatch, lambda _: httpx.Response(200, content=obj.encode()))
        _refused(svc.INVALID_REQUEST_OBJECT, request_uri=REQUEST_URI)

    def test_transport_error(self, monkeypatch):
        def fail(request):
            raise httpx.ConnectError("refused", request=request)

        _mock_http(monkeypatch, fail)
        _refused(svc.INVALID_REQUEST_URI, request_uri=REQUEST_URI)

    def test_ssrf_guard_blocks_private_addresses(self):
        """The real client refuses a registered URI that resolves to loopback."""
        uri = "https://127.0.0.1/request.jwt"
        client = _client(registration_metadata={"request_uris": [uri]})
        _refused(svc.INVALID_REQUEST_URI, client=client, request_uri=uri)


class TestRegisteredRequestUris:
    def test_ignores_non_strings(self):
        client = _client(registration_metadata={"request_uris": [REQUEST_URI, 7]})
        assert svc.registered_request_uris(client) == [REQUEST_URI]

    def test_not_a_list(self):
        client = _client(registration_metadata={"request_uris": REQUEST_URI})
        assert svc.registered_request_uris(client) == []
