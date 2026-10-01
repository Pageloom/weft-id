"""Pushed Authorization Requests (RFC 9126), end to end through the real app.

Covers ``POST /oauth2/par`` (response shape, client authentication, parameter
validation, request objects) and the authorization endpoint's side: redeeming
a pushed ``request_uri`` once, ignoring front-channel parameters, the login
stash, and the per-client ``require_pushed_authorization_requests`` switch.
"""

import base64
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import database
import pytest
from routers.saml_idp._helpers import PENDING_OAUTH2_AUTHORIZE_KEY
from services import oauth2_par as par_service

from tests.helpers.client_keys import ASSERTION_TYPE, JWKS, make_assertion, make_request_object

REDIRECT_URI = "http://localhost:3000/callback"
URN_PREFIX = "urn:ietf:params:oauth:request_uri:"


@pytest.fixture
def session_data(mocker) -> dict:
    """A plain dict standing in for the Starlette session."""
    data: dict = {}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: data),
    )
    return data


@pytest.fixture
def http(client, test_tenant_host):
    """Tenant-scoped client that never follows redirects."""

    class _Client:
        def get(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            headers = kw.pop("headers", {})
            headers["Host"] = test_tenant_host
            return client.get(url, headers=headers, **kw)

        def post(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            headers = kw.pop("headers", {})
            headers["Host"] = test_tenant_host
            return client.post(url, headers=headers, **kw)

        def without_csrf(self):
            return client.without_csrf()

    return _Client()


@pytest.fixture
def authed(http, test_user, override_auth, session_data):
    override_auth(test_user)
    session_data["user_id"] = str(test_user["id"])
    session_data["session_start"] = int(time.time())
    return http


@pytest.fixture
def issuer(test_tenant_host):
    return f"https://{test_tenant_host}"


def _basic(client_row: dict) -> dict[str, str]:
    raw = f"{client_row['client_id']}:{client_row['client_secret']}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


def _par_params(**extra: str) -> dict[str, str]:
    params = {
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid",
        "state": "st-par",
        "nonce": "n-par",
    }
    params.update(extra)
    return params


def _push(http, client_row: dict, **extra: str):
    return http.post("/oauth2/par", data=_par_params(**extra), headers=_basic(client_row))


def _pushed_uri(http, client_row: dict, **extra: str) -> str:
    response = _push(http, client_row, **extra)
    assert response.status_code == 201, response.text
    return response.json()["request_uri"]


def _location_query(response) -> dict[str, list[str]]:
    location = response.headers["location"]
    assert location.startswith(REDIRECT_URI + "?"), location
    return parse_qs(urlsplit(location).query)


def _require_par(test_tenant, client_row: dict) -> None:
    database.oauth2.update_client(
        test_tenant["id"], client_row["client_id"], require_pushed_authorization_requests=True
    )


# ============================================================================
# POST /oauth2/par
# ============================================================================


class TestPushEndpoint:
    def test_returns_request_uri_and_expires_in(self, http, normal_oauth2_client):
        response = _push(http, normal_oauth2_client)
        assert response.status_code == 201
        body = response.json()
        assert body["request_uri"].startswith(URN_PREFIX)
        assert body["expires_in"] == 60
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"

    def test_each_push_gets_a_new_request_uri(self, http, normal_oauth2_client):
        assert _pushed_uri(http, normal_oauth2_client) != _pushed_uri(http, normal_oauth2_client)

    def test_logs_pushed_event(self, http, normal_oauth2_client, mocker):
        log = mocker.patch("services.oauth2_par.log_event")
        _push(http, normal_oauth2_client)
        kwargs = log.call_args.kwargs
        assert kwargs["event_type"] == "oauth2_authorization_request_pushed"
        assert kwargs["artifact_id"] == str(normal_oauth2_client["id"])
        assert kwargs["metadata"]["client_id"] == normal_oauth2_client["client_id"]
        assert kwargs["metadata"]["scope"] == "openid"

    def test_client_secret_post(self, http, normal_oauth2_client):
        response = http.post(
            "/oauth2/par",
            data=_par_params(
                client_id=normal_oauth2_client["client_id"],
                client_secret=normal_oauth2_client["client_secret"],
            ),
        )
        assert response.status_code == 201

    def test_private_key_jwt(self, http, test_tenant, normal_oauth2_client, issuer):
        database.oauth2.set_client_authentication(
            test_tenant["id"],
            normal_oauth2_client["client_id"],
            client_auth_method="private_key_jwt",
            jwks=JWKS,
            jwks_uri=None,
            token_endpoint_auth_signing_alg=None,
            rotate_secret=True,
        )
        response = http.post(
            "/oauth2/par",
            data=_par_params(
                client_assertion_type=ASSERTION_TYPE,
                client_assertion=make_assertion(
                    normal_oauth2_client["client_id"], f"{issuer}/oauth2/par"
                ),
            ),
        )
        assert response.status_code == 201

    def test_no_csrf_token_needed(self, http, normal_oauth2_client):
        with http.without_csrf():
            response = _push(http, normal_oauth2_client)
        assert response.status_code == 201

    def test_wrong_secret_is_invalid_client(self, http, normal_oauth2_client):
        response = _push(http, {**normal_oauth2_client, "client_secret": "wrong"})
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_no_authentication_is_invalid_client(self, http, normal_oauth2_client):
        response = http.post(
            "/oauth2/par", data=_par_params(client_id=normal_oauth2_client["client_id"])
        )
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_public_client_cannot_push(self, http, test_tenant, test_admin_user):
        public = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="Public",
            redirect_uris=[],
            created_by=str(test_admin_user["id"]),
            device_grant_enabled=True,
            is_public=True,
        )
        response = http.post("/oauth2/par", data=_par_params(client_id=public["client_id"]))
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_b2b_client_is_unauthorized(self, http, b2b_oauth2_client):
        response = _push(http, b2b_oauth2_client)
        assert response.status_code == 400
        assert response.json()["error"] == "unauthorized_client"

    def test_deactivated_client_is_invalid_client(self, http, test_tenant, normal_oauth2_client):
        database.oauth2.deactivate_client(test_tenant["id"], normal_oauth2_client["client_id"])
        response = _push(http, normal_oauth2_client)
        assert response.status_code == 401

    @pytest.mark.parametrize(
        ("extra", "error"),
        [
            ({"redirect_uri": "https://evil.example/cb"}, "invalid_request"),
            ({"redirect_uri": ""}, "invalid_request"),
            ({"response_type": ""}, "invalid_request"),
            ({"response_type": "token"}, "unsupported_response_type"),
            ({"response_mode": "fragment"}, "invalid_request"),
            ({"code_challenge": "abc", "code_challenge_method": "S512"}, "invalid_request"),
            ({"prompt": "none login"}, "invalid_request"),
            ({"max_age": "-1"}, "invalid_request"),
            ({"request_uri": "https://rp.example/ro"}, "invalid_request"),
        ],
    )
    def test_invalid_parameters_refused(self, http, normal_oauth2_client, extra, error):
        response = _push(http, normal_oauth2_client, **extra)
        assert response.status_code == 400
        assert response.json()["error"] == error
        assert response.headers["cache-control"] == "no-store"

    def test_over_long_parameter_is_invalid_request(self, http, normal_oauth2_client):
        response = _push(http, normal_oauth2_client, state="x" * 2049)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_nothing_stored_on_refusal(self, http, test_tenant, normal_oauth2_client):
        _push(http, normal_oauth2_client, response_type="token")
        rows = database.fetchall(
            test_tenant["id"], "select id from oauth2_pushed_authorization_requests", {}
        )
        assert rows == []


class TestPushWithRequestObject:
    @pytest.fixture
    def keyed_client(self, test_tenant, normal_oauth2_client):
        database.oauth2.set_client_authentication(
            test_tenant["id"],
            normal_oauth2_client["client_id"],
            client_auth_method="client_secret",
            jwks=JWKS,
            jwks_uri=None,
            token_endpoint_auth_signing_alg=None,
            rotate_secret=False,
        )
        return normal_oauth2_client

    def _object(self, client_row: dict, issuer: str, **claims) -> str:
        body = {
            "iss": client_row["client_id"],
            "aud": issuer,
            "client_id": client_row["client_id"],
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "st-obj",
            "nonce": "n-obj",
        }
        body.update(claims)
        return make_request_object(body)

    def test_object_parameters_are_pushed(self, http, authed, keyed_client, issuer, session_data):
        response = http.post(
            "/oauth2/par",
            data={"request": self._object(keyed_client, issuer)},
            headers=_basic(keyed_client),
        )
        assert response.status_code == 201
        consent = authed.get(
            "/oauth2/authorize",
            params={
                "client_id": keyed_client["client_id"],
                "request_uri": response.json()["request_uri"],
            },
        )
        assert consent.status_code == 200
        stored = next(iter(session_data["oauth2_auth_requests"].values()))
        assert stored["state"] == "st-obj"
        assert stored["nonce"] == "n-obj"

    def test_unverifiable_object_refused(self, http, keyed_client, issuer):
        response = http.post(
            "/oauth2/par",
            data={"request": self._object(keyed_client, issuer, aud="https://other.example")},
            headers=_basic(keyed_client),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request_object"

    def test_object_for_another_client_refused(self, http, keyed_client, issuer):
        response = http.post(
            "/oauth2/par",
            data={"request": self._object(keyed_client, issuer, client_id="someone-else")},
            headers=_basic(keyed_client),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request_object"

    def test_object_values_are_validated(self, http, keyed_client, issuer):
        response = http.post(
            "/oauth2/par",
            data={"request": self._object(keyed_client, issuer, redirect_uri="https://x.example")},
            headers=_basic(keyed_client),
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"


# ============================================================================
# The authorization endpoint redeems a pushed request_uri
# ============================================================================


class TestAuthorizeWithPushedRequest:
    def test_consent_page_uses_pushed_parameters(
        self, http, authed, normal_oauth2_client, session_data
    ):
        request_uri = _pushed_uri(http, normal_oauth2_client)
        response = authed.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        assert response.status_code == 200
        assert 'name="auth_request_id"' in response.text
        stored = next(iter(session_data["oauth2_auth_requests"].values()))
        assert stored["redirect_uri"] == REDIRECT_URI
        assert stored["state"] == "st-par"
        assert stored["nonce"] == "n-par"
        assert stored["scope"] == "openid"

    def test_post_binding(self, http, authed, normal_oauth2_client):
        request_uri = _pushed_uri(http, normal_oauth2_client)
        response = authed.post(
            "/oauth2/authorize",
            data={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        assert response.status_code == 200
        assert 'name="auth_request_id"' in response.text

    def test_front_channel_parameters_are_ignored(
        self, http, authed, normal_oauth2_client, session_data
    ):
        """RFC 9126 section 4: only the pushed parameters count."""
        request_uri = _pushed_uri(http, normal_oauth2_client)
        authed.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "request_uri": request_uri,
                "redirect_uri": "http://localhost:3000/auth/callback",
                "state": "tampered",
                "scope": "openid email",
            },
        )
        stored = next(iter(session_data["oauth2_auth_requests"].values()))
        assert stored["redirect_uri"] == REDIRECT_URI
        assert stored["state"] == "st-par"
        assert stored["scope"] == "openid"

    def test_pushed_error_reaches_redirect_uri(self, http, authed, normal_oauth2_client):
        """prompt=none without consent: answered at the pushed redirect_uri."""
        request_uri = _pushed_uri(http, normal_oauth2_client, prompt="none")
        response = authed.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        query = _location_query(response)
        assert query["error"] == ["consent_required"]
        assert query["state"] == ["st-par"]

    def test_request_uri_works_once(self, http, authed, normal_oauth2_client):
        request_uri = _pushed_uri(http, normal_oauth2_client)
        params = {"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri}
        assert authed.get("/oauth2/authorize", params=params).status_code == 200
        again = authed.get("/oauth2/authorize", params=params)
        assert again.status_code == 200
        assert "Invalid request" in again.text
        assert "already used" in again.text

    def test_other_clients_request_uri_refused(
        self, http, authed, test_tenant, test_admin_user, normal_oauth2_client
    ):
        other = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="Other",
            redirect_uris=[REDIRECT_URI],
            created_by=str(test_admin_user["id"]),
        )
        request_uri = _pushed_uri(http, other)
        response = authed.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        assert "Invalid request" in response.text
        # Still usable by the client that pushed it.
        ok = authed.get(
            "/oauth2/authorize",
            params={"client_id": other["client_id"], "request_uri": request_uri},
        )
        assert 'name="auth_request_id"' in ok.text

    def test_expired_request_uri_refused(self, http, authed, test_tenant, normal_oauth2_client):
        request_uri = _pushed_uri(http, normal_oauth2_client)
        database.execute(
            test_tenant["id"],
            "update oauth2_pushed_authorization_requests set expires_at = :t",
            {"t": datetime.now(UTC) - timedelta(seconds=1)},
        )
        response = authed.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        assert "Invalid request" in response.text

    def test_unknown_request_uri_with_registered_redirect_redirects_error(
        self, authed, normal_oauth2_client
    ):
        response = authed.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "request_uri": URN_PREFIX + "nope",
                "redirect_uri": REDIRECT_URI,
                "state": "s1",
            },
        )
        query = _location_query(response)
        assert query["error"] == ["invalid_request_uri"]
        assert query["state"] == ["s1"]

    def test_request_and_pushed_request_uri_refused(self, http, authed, normal_oauth2_client):
        request_uri = _pushed_uri(http, normal_oauth2_client)
        response = authed.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "request_uri": request_uri,
                "request": "a.b.c",
            },
        )
        assert "Invalid request" in response.text
        assert "not both" in response.text


class TestLoginStash:
    def test_unauthenticated_stash_is_a_new_pushed_request(
        self, http, test_user, override_auth, normal_oauth2_client, session_data
    ):
        request_uri = _pushed_uri(http, normal_oauth2_client)
        response = http.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        assert response.headers["location"].startswith("/login")
        stashed = session_data[PENDING_OAUTH2_AUTHORIZE_KEY]
        query = parse_qs(urlsplit(stashed).query)
        assert set(query) == {"client_id", "request_uri"}
        assert query["request_uri"][0] != request_uri
        assert query["request_uri"][0].startswith(URN_PREFIX)
        assert "st-par" not in stashed

        # Login completes; the stashed path resumes as a pushed request.
        override_auth(test_user)
        session_data["user_id"] = str(test_user["id"])
        session_data["session_start"] = int(time.time())
        resumed = http.get(stashed)
        assert resumed.status_code == 200
        stored = next(iter(session_data["oauth2_auth_requests"].values()))
        assert stored["state"] == "st-par"

    def test_resume_lasts_the_login_window(
        self, http, test_tenant, normal_oauth2_client, session_data
    ):
        request_uri = _pushed_uri(http, normal_oauth2_client)
        http.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        row = database.fetchone(
            test_tenant["id"],
            "select expires_at from oauth2_pushed_authorization_requests",
            {},
        )
        remaining = (row["expires_at"] - datetime.now(UTC)).total_seconds()
        assert 590 < remaining <= 600

    def test_reauth_stash_strips_prompt_and_resumes(
        self, http, authed, test_tenant, normal_oauth2_client, session_data
    ):
        request_uri = _pushed_uri(http, normal_oauth2_client, prompt="login")
        first = authed.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        assert first.status_code == 303
        stashed = session_data.pop(PENDING_OAUTH2_AUTHORIZE_KEY)
        assert set(parse_qs(urlsplit(stashed).query)) == {"client_id", "request_uri"}
        row = database.fetchone(
            test_tenant["id"], "select parameters from oauth2_pushed_authorization_requests", {}
        )
        assert "prompt" not in row["parameters"]

        session_data.clear()
        session_data["user_id"] = "x"
        session_data["session_start"] = int(time.time())
        resumed = authed.get(stashed)
        assert resumed.status_code == 200
        assert 'name="auth_request_id"' in resumed.text


class TestRequirePushedAuthorizationRequests:
    def test_plain_request_refused_at_registered_redirect_uri(
        self, authed, test_tenant, normal_oauth2_client
    ):
        _require_par(test_tenant, normal_oauth2_client)
        response = authed.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "state": "s1",
            },
        )
        query = _location_query(response)
        assert query["error"] == ["invalid_request"]
        assert query["state"] == ["s1"]
        assert "pushed authorization" in query["error_description"][0]

    def test_plain_request_with_unregistered_redirect_renders_error_page(
        self, authed, test_tenant, normal_oauth2_client
    ):
        _require_par(test_tenant, normal_oauth2_client)
        response = authed.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "https://evil.example/cb",
                "response_type": "code",
            },
        )
        assert response.status_code == 200
        assert "must use pushed authorization requests" in response.text

    def test_request_object_refused(self, authed, test_tenant, normal_oauth2_client):
        _require_par(test_tenant, normal_oauth2_client)
        response = authed.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request": "a.b.c"},
        )
        assert "must use pushed authorization requests" in response.text

    def test_pushed_request_accepted(self, http, authed, test_tenant, normal_oauth2_client):
        _require_par(test_tenant, normal_oauth2_client)
        request_uri = _pushed_uri(http, normal_oauth2_client)
        response = authed.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        assert 'name="auth_request_id"' in response.text

    def test_login_resume_still_pushed(
        self, http, test_user, override_auth, test_tenant, normal_oauth2_client, session_data
    ):
        """The stash is itself a pushed request, so the required check passes."""
        _require_par(test_tenant, normal_oauth2_client)
        request_uri = _pushed_uri(http, normal_oauth2_client)
        http.get(
            "/oauth2/authorize",
            params={"client_id": normal_oauth2_client["client_id"], "request_uri": request_uri},
        )
        stashed = session_data[PENDING_OAUTH2_AUTHORIZE_KEY]
        override_auth(test_user)
        session_data["user_id"] = str(test_user["id"])
        session_data["session_start"] = int(time.time())
        resumed = http.get(stashed)
        assert 'name="auth_request_id"' in resumed.text


def test_service_constants_match_the_endpoint():
    assert par_service.REQUEST_URI_PREFIX == URN_PREFIX
    assert par_service.EXPIRES_IN == 60


class TestAdminSetting:
    def test_web_form_sets_and_clears(
        self,
        client,
        test_tenant,
        test_tenant_host,
        test_admin_user,
        override_auth,
        normal_oauth2_client,
    ):
        override_auth(test_admin_user, level="admin")
        url = f"/applications/oauth/{normal_oauth2_client['client_id']}"
        form = {
            "name": "Test OAuth2 Client",
            "redirect_uris": REDIRECT_URI,
            "require_pushed_authorization_requests": "true",
        }
        response = client.post(
            f"{url}/edit", data=form, headers={"Host": test_tenant_host}, follow_redirects=False
        )
        assert "success=updated" in response.headers["location"]
        row = database.oauth2.get_client_by_client_id(
            test_tenant["id"], normal_oauth2_client["client_id"]
        )
        assert row["require_pushed_authorization_requests"] is True

        page = client.get(url, headers={"Host": test_tenant_host})
        assert 'name="require_pushed_authorization_requests" value="true"' in page.text
        assert "checked" in page.text.split('id="require_pushed_authorization_requests"')[1][:200]

        del form["require_pushed_authorization_requests"]
        client.post(
            f"{url}/edit", data=form, headers={"Host": test_tenant_host}, follow_redirects=False
        )
        row = database.oauth2.get_client_by_client_id(
            test_tenant["id"], normal_oauth2_client["client_id"]
        )
        assert row["require_pushed_authorization_requests"] is False
