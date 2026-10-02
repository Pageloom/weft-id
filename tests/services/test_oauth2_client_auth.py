"""Service tests for private_key_jwt client authentication
(services.oauth2_client_auth). Real database.

Protocol behaviour (claims, algorithms, replay, one method per request) is
covered end to end in tests/routers/test_oauth2_private_key_jwt.py; this file
covers key validation, the jwks_uri fetch and cache, the refusal log, and the
admin setter (authorization, rules, secret handling, audit).
"""

import json
import logging

import database
import httpx
import oauth2
import pytest
from services import oauth2_client_auth as svc
from services.exceptions import ForbiddenError, NotFoundError, UnauthorizedError, ValidationError

from tests.helpers.client_keys import EC_KEY, JWKS, RSA_KEY, make_assertion, public_jwk

ISSUER = "https://tenant.example.test"
URI = "https://keys.example.com/jwks.json"


def _user(test_tenant, user, role):
    return {"id": str(user["id"]), "tenant_id": str(test_tenant["id"]), "role": role}


def _events(test_tenant, event_type):
    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=30)
        if e["event_type"] == event_type
    ]


def _mock_http(monkeypatch, handler):
    """Route the JWKS fetch through an in-process handler; count requests."""
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


class TestValidateJwks:
    def test_valid_set(self):
        assert svc.validate_jwks(JWKS) is JWKS

    @pytest.mark.parametrize(
        "jwks",
        [
            None,
            [],
            {"keys": "nope"},
            {"keys": []},
            {"keys": [1]},
            {"keys": [public_jwk(RSA_KEY, f"k{i}") for i in range(21)]},
            {"keys": [{**public_jwk(RSA_KEY, "k"), "x5c": ["a" * 40000]}]},
            {"keys": [{"kty": "oct", "k": "c2VjcmV0"}]},
            {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            {"keys": [{"kty": "RSA", "e": "AQAB"}]},
        ],
    )
    def test_invalid_sets(self, jwks):
        with pytest.raises(ValueError):
            svc.validate_jwks(jwks)

    @pytest.mark.parametrize("member", ["d", "p", "q", "dp", "dq", "qi"])
    def test_private_members_refused(self, member):
        key = {**public_jwk(RSA_KEY, "k"), member: "AQAB"}
        with pytest.raises(ValueError, match="public keys only"):
            svc.validate_jwks({"keys": [key]})


class TestValidateJwksUri:
    def test_valid(self):
        assert svc.validate_jwks_uri(URI) == URI

    @pytest.mark.parametrize(
        "uri",
        [
            None,
            "",
            "http://keys.example.com/jwks",
            "https:///jwks",
            "https://keys.example.com/jwks#frag",
            "https://keys.example.com/" + "a" * 2048,
            "not a url",
            "https://[::1/jwks",
        ],
    )
    def test_invalid(self, uri):
        with pytest.raises(ValueError):
            svc.validate_jwks_uri(uri)


class TestFetchJwks:
    def test_fetches_and_validates(self, monkeypatch):
        calls = _mock_http(monkeypatch, lambda _: httpx.Response(200, json=JWKS))
        assert svc._fetch_jwks(URI) == JWKS
        assert calls == [URI]

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(404),
            httpx.Response(200, content=b"not json"),
            httpx.Response(200, json={"keys": []}),
            httpx.Response(200, content=json.dumps({"keys": [], "pad": "a" * 40000}).encode()),
        ],
    )
    def test_unusable_responses(self, monkeypatch, response):
        _mock_http(monkeypatch, lambda _: response)
        with pytest.raises(svc._AssertionRejectedError):
            svc._fetch_jwks(URI)

    def test_transport_error(self, monkeypatch):
        def fail(request):
            raise httpx.ConnectError("refused", request=request)

        _mock_http(monkeypatch, fail)
        with pytest.raises(svc._AssertionRejectedError, match="ConnectError"):
            svc._fetch_jwks(URI)

    def test_ssrf_guard_blocks_private_addresses(self):
        """The real client refuses a key URL that resolves to loopback."""
        with pytest.raises(svc._AssertionRejectedError, match="SsrfBlockedError"):
            svc._fetch_jwks("https://127.0.0.1/jwks.json")


class TestClientJwks:
    def test_inline_keys_never_refresh(self):
        client = {"id": "c1", "jwks": JWKS, "jwks_uri": None}
        assert svc._client_jwks("t1", client, refresh=False) == JWKS
        assert svc._client_jwks("t1", client, refresh=True) is None

    def test_no_keys(self):
        with pytest.raises(svc._AssertionRejectedError, match="no keys"):
            svc._client_jwks("t1", {"id": "c1", "jwks": None, "jwks_uri": None}, refresh=False)

    def test_changed_uri_is_refetched(self, monkeypatch):
        calls = _mock_http(monkeypatch, lambda _: httpx.Response(200, json=JWKS))
        svc.clear_jwks_cache("t1", "c2")
        svc._client_jwks("t1", {"id": "c2", "jwks": None, "jwks_uri": URI}, refresh=False)
        other = "https://keys.example.com/other.json"
        svc._client_jwks("t1", {"id": "c2", "jwks": None, "jwks_uri": other}, refresh=False)
        assert calls == [URI, other]
        svc.clear_jwks_cache("t1", "c2")

    def test_failed_fetch_is_not_retried_at_once(self, monkeypatch):
        calls = _mock_http(monkeypatch, lambda _: httpx.Response(503))
        client = {"id": "c3", "jwks": None, "jwks_uri": URI}
        for _ in range(2):
            with pytest.raises(svc._AssertionRejectedError, match="HTTP 503"):
                svc._client_jwks("t1", client, refresh=False)
        assert calls == [URI]

        # Changing the client's keys drops the cached failure.
        svc.clear_jwks_cache("t1", "c3")
        with pytest.raises(svc._AssertionRejectedError):
            svc._client_jwks("t1", client, refresh=False)
        assert calls == [URI, URI]

    def test_concurrent_fetch_fails_fast(self, monkeypatch):
        calls = _mock_http(monkeypatch, lambda _: httpx.Response(200, json=JWKS))
        monkeypatch.setattr(svc, "_jwks_fetch_guard", svc.FetchGuard(max_in_flight=0))
        with pytest.raises(svc._AssertionRejectedError, match="in progress"):
            svc._client_jwks("t1", {"id": "c4", "jwks": None, "jwks_uri": URI}, refresh=False)
        assert calls == []


class TestCandidateKeys:
    def test_filters_keys_that_cannot_verify(self):
        rsa = public_jwk(RSA_KEY, None)
        jwks = {
            "keys": [
                "not a key",
                {**rsa, "use": "enc"},
                {**rsa, "alg": "PS256"},
                {"kty": "RSA", "n": "AQAB"},
                public_jwk(EC_KEY, None),
                rsa,
            ]
        }
        candidates = svc._candidate_keys(jwks, {}, "RS256")
        assert len(candidates) == 1
        assert candidates[0].algorithm_name == "RS256"

    def test_kid_selects_one_key(self):
        assert len(svc._candidate_keys(JWKS, {"kid": "ec-1"}, "ES256")) == 1
        assert svc._candidate_keys(JWKS, {"kid": "ec-1"}, "RS256") == []


class TestAuthenticateClientAssertion:
    def test_refusal_is_logged_without_the_assertion(
        self, test_tenant, normal_oauth2_client, caplog
    ):
        assertion = make_assertion(normal_oauth2_client["client_id"], ISSUER)
        with caplog.at_level(logging.INFO, logger="services.oauth2_client_auth"):
            with pytest.raises(UnauthorizedError) as exc:
                svc.authenticate_client_assertion(
                    test_tenant["id"], assertion=assertion, client_id=None, audiences=[ISSUER]
                )
        assert exc.value.code == "invalid_client"
        assert "not a private_key_jwt client" in caplog.text
        assert assertion not in caplog.text

    def test_success_returns_the_client(self, test_tenant, test_admin_user, normal_oauth2_client):
        svc.set_client_authentication(
            _user(test_tenant, test_admin_user, "admin"),
            normal_oauth2_client["client_id"],
            method="private_key_jwt",
            jwks=JWKS,
        )
        assertion = make_assertion(
            normal_oauth2_client["client_id"], ISSUER, key=EC_KEY, alg="ES256", kid="ec-1"
        )
        client = svc.authenticate_client_assertion(
            test_tenant["id"],
            assertion=assertion,
            client_id=normal_oauth2_client["client_id"],
            audiences=[ISSUER],
        )
        assert client["client_id"] == normal_oauth2_client["client_id"]

    def test_rotated_keys_are_refetched_once(
        self, test_tenant, test_admin_user, normal_oauth2_client, monkeypatch
    ):
        """The cached set lacks the signing key: one refetch finds it."""
        served = [{"keys": [public_jwk(RSA_KEY, "rsa-1")]}, JWKS]
        calls = _mock_http(monkeypatch, lambda _: httpx.Response(200, json=served[len(calls) - 1]))
        client_id = normal_oauth2_client["client_id"]
        svc.set_client_authentication(
            _user(test_tenant, test_admin_user, "admin"),
            client_id,
            method="private_key_jwt",
            jwks_uri=URI,
        )
        assertion = make_assertion(client_id, ISSUER, key=EC_KEY, alg="ES256", kid="ec-1")

        client = svc.authenticate_client_assertion(
            test_tenant["id"], assertion=assertion, client_id=client_id, audiences=[ISSUER]
        )

        assert client["client_id"] == client_id
        assert calls == [URI, URI]

    def test_jti_kept_through_the_leeway_window(
        self, test_tenant, test_admin_user, normal_oauth2_client
    ):
        """An assertion just past exp still decodes (clock-skew leeway); its
        jti must still be on record then, or it could be replayed."""
        import time

        svc.set_client_authentication(
            _user(test_tenant, test_admin_user, "admin"),
            normal_oauth2_client["client_id"],
            method="private_key_jwt",
            jwks=JWKS,
        )
        now = int(time.time())
        assertion = make_assertion(
            normal_oauth2_client["client_id"], ISSUER, iat=now - 90, exp=now - 30
        )

        def authenticate():
            return svc.authenticate_client_assertion(
                test_tenant["id"],
                assertion=assertion,
                client_id=normal_oauth2_client["client_id"],
                audiences=[ISSUER],
            )

        authenticate()
        # The replay's own insert first sweeps rows past their expires_at; the
        # jti must survive that sweep.
        with pytest.raises(UnauthorizedError):
            authenticate()
        row = database.fetchone(
            test_tenant["id"],
            "select expires_at from oauth2_client_assertion_jtis order by created_at desc limit 1",
            {},
        )
        assert row["expires_at"].timestamp() >= now + 29


class TestSetClientAuthentication:
    def test_switch_to_private_key_jwt(self, test_tenant, test_admin_user, normal_oauth2_client):
        updated = svc.set_client_authentication(
            _user(test_tenant, test_admin_user, "admin"),
            normal_oauth2_client["client_id"],
            method="private_key_jwt",
            jwks=JWKS,
        )
        assert updated["client_auth_method"] == "private_key_jwt"
        assert "client_secret" not in updated
        row = database.oauth2.get_client_by_client_id(
            test_tenant["id"], normal_oauth2_client["client_id"]
        )
        assert not oauth2.verify_token_hash(
            normal_oauth2_client["client_secret"], row["client_secret_hash"]
        )
        events = _events(test_tenant, "oauth2_client_authentication_changed")
        assert len(events) == 1
        assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])
        assert str(events[0]["artifact_id"]) == str(normal_oauth2_client["id"])
        assert (
            events[0]["metadata"].items()
            >= {
                "client_auth_method": "private_key_jwt",
                "previous_client_auth_method": "client_secret",
                "key_source": "jwks",
                "jwks_uri": None,
                "secret_rotated": True,
            }.items()
        )

    def test_switch_back_issues_a_secret(self, test_tenant, test_admin_user, normal_oauth2_client):
        admin = _user(test_tenant, test_admin_user, "admin")
        client_id = normal_oauth2_client["client_id"]
        svc.set_client_authentication(admin, client_id, method="private_key_jwt", jwks_uri=URI)
        updated = svc.set_client_authentication(admin, client_id, method="client_secret")
        assert updated["client_auth_method"] == "client_secret"
        assert updated["jwks_uri"] is None
        row = database.oauth2.get_client_by_client_id(test_tenant["id"], client_id)
        assert oauth2.verify_token_hash(updated["client_secret"], row["client_secret_hash"])
        last = _events(test_tenant, "oauth2_client_authentication_changed")[0]
        assert last["metadata"]["secret_rotated"] is True
        assert last["metadata"]["key_source"] == "none"

    def test_key_change_keeps_secret_and_method(
        self, test_tenant, test_admin_user, normal_oauth2_client
    ):
        """Updating the keys of a secret client does not touch its secret."""
        updated = svc.set_client_authentication(
            _user(test_tenant, test_admin_user, "admin"),
            normal_oauth2_client["client_id"],
            method="client_secret",
            jwks_uri=URI,
        )
        assert "client_secret" not in updated
        assert updated["jwks_uri"] == URI
        row = database.oauth2.get_client_by_client_id(
            test_tenant["id"], normal_oauth2_client["client_id"]
        )
        assert oauth2.verify_token_hash(
            normal_oauth2_client["client_secret"], row["client_secret_hash"]
        )
        event = _events(test_tenant, "oauth2_client_authentication_changed")[0]
        assert event["metadata"]["secret_rotated"] is False
        assert event["metadata"]["key_source"] == "jwks_uri"

    def test_registered_signing_alg_kept_only_for_private_key_jwt(
        self, test_tenant, test_admin_user, normal_oauth2_client
    ):
        admin = _user(test_tenant, test_admin_user, "admin")
        client_id = normal_oauth2_client["client_id"]
        database.oauth2.set_client_authentication(
            test_tenant["id"],
            client_id,
            client_auth_method="private_key_jwt",
            jwks=JWKS,
            jwks_uri=None,
            token_endpoint_auth_signing_alg="PS256",
            rotate_secret=True,
        )
        kept = svc.set_client_authentication(
            admin, client_id, method="private_key_jwt", jwks_uri=URI
        )
        assert kept["token_endpoint_auth_signing_alg"] == "PS256"
        dropped = svc.set_client_authentication(admin, client_id, method="client_secret")
        assert dropped["token_endpoint_auth_signing_alg"] is None

    def test_clears_the_cached_jwks(
        self, test_tenant, test_admin_user, normal_oauth2_client, monkeypatch
    ):
        calls = _mock_http(monkeypatch, lambda _: httpx.Response(200, json=JWKS))
        admin = _user(test_tenant, test_admin_user, "admin")
        client_id = normal_oauth2_client["client_id"]
        updated = svc.set_client_authentication(
            admin, client_id, method="private_key_jwt", jwks_uri=URI
        )
        svc._client_jwks(test_tenant["id"], updated, refresh=False)
        updated = svc.set_client_authentication(
            admin, client_id, method="private_key_jwt", jwks_uri=URI
        )
        svc._client_jwks(test_tenant["id"], updated, refresh=False)
        assert calls == [URI, URI]

    @pytest.mark.parametrize(
        ("kwargs", "code"),
        [
            ({"method": "tls_client_auth"}, "invalid_client_auth_method"),
            ({"method": "private_key_jwt"}, "client_keys_required"),
            ({"method": "private_key_jwt", "jwks": JWKS, "jwks_uri": URI}, "invalid_client_keys"),
            ({"method": "private_key_jwt", "jwks": {"keys": []}}, "invalid_client_keys"),
            (
                {"method": "private_key_jwt", "jwks_uri": "http://k.example/jwks"},
                "invalid_client_keys",
            ),
        ],
    )
    def test_validation(self, test_tenant, test_admin_user, normal_oauth2_client, kwargs, code):
        with pytest.raises(ValidationError) as exc:
            svc.set_client_authentication(
                _user(test_tenant, test_admin_user, "admin"),
                normal_oauth2_client["client_id"],
                **kwargs,
            )
        assert exc.value.code == code
        assert _events(test_tenant, "oauth2_client_authentication_changed") == []

    def test_public_client_refused(self, test_tenant, test_admin_user):
        public = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="TV App",
            redirect_uris=[],
            created_by=str(test_admin_user["id"]),
            device_grant_enabled=True,
            is_public=True,
        )
        with pytest.raises(ValidationError) as exc:
            svc.set_client_authentication(
                _user(test_tenant, test_admin_user, "admin"),
                public["client_id"],
                method="private_key_jwt",
                jwks=JWKS,
            )
        assert exc.value.code == "public_client_auth_fixed"

    def test_member_forbidden(self, test_tenant, test_user, normal_oauth2_client):
        with pytest.raises(ForbiddenError):
            svc.set_client_authentication(
                _user(test_tenant, test_user, "member"),
                normal_oauth2_client["client_id"],
                method="private_key_jwt",
                jwks=JWKS,
            )

    def test_admin_forbidden_on_b2b(self, test_tenant, test_admin_user, b2b_oauth2_client):
        with pytest.raises(ForbiddenError):
            svc.set_client_authentication(
                _user(test_tenant, test_admin_user, "admin"),
                b2b_oauth2_client["client_id"],
                method="private_key_jwt",
                jwks=JWKS,
            )

    def test_super_admin_on_b2b(self, test_tenant, test_super_admin_user, b2b_oauth2_client):
        updated = svc.set_client_authentication(
            _user(test_tenant, test_super_admin_user, "super_admin"),
            b2b_oauth2_client["client_id"],
            method="private_key_jwt",
            jwks=JWKS,
        )
        assert updated["client_auth_method"] == "private_key_jwt"

    def test_unknown_client(self, test_tenant, test_admin_user):
        with pytest.raises(NotFoundError):
            svc.set_client_authentication(
                _user(test_tenant, test_admin_user, "admin"), "nope", method="client_secret"
            )
