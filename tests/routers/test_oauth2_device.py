"""Device authorization grant (RFC 8628), end to end through the real app.

Covers ``POST /oauth2/device_authorization`` (response shape, client
authentication, per-client enablement), the token endpoint's device_code
grant (pending, slow_down, denied, expired, redeemed once, access re-check,
tokens and ID token), and the ``/device`` verification page (login stash,
code entry, confirmation, decision, rate limit, access control).
"""

import base64
import time

import database
import jwt
import pytest
from routers.device import DEVICE_VERIFICATION_KEY
from routers.saml_idp._helpers import PENDING_DEVICE_KEY, get_post_auth_redirect
from services import oauth2_device as device_service
from services.exceptions import RateLimitError

GRANT = "urn:ietf:params:oauth:grant-type:device_code"


@pytest.fixture
def session_data(mocker) -> dict:
    """A plain dict standing in for the Starlette session."""
    data: dict = {}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: data),
    )
    return data


def _make_client(test_tenant, test_admin_user, *, oidc=True, available_to_all=True, enabled=True):
    created = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Device CLI",
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(test_admin_user["id"]),
        device_grant_enabled=enabled,
    )
    database.execute(
        test_tenant["id"],
        "update oauth2_clients set oidc_enabled = :o, available_to_all = :a where id = :id",
        {"o": oidc, "a": available_to_all, "id": created["id"]},
    )
    return created


@pytest.fixture
def device_client(test_tenant, test_admin_user):
    return _make_client(test_tenant, test_admin_user)


def _start(http, host, oauth_client, scope="openid profile"):
    return http.post(
        "/oauth2/device_authorization",
        headers={"Host": host},
        data={
            "client_id": oauth_client["client_id"],
            "client_secret": oauth_client["client_secret"],
            "scope": scope,
        },
    )


def _poll(http, host, oauth_client, device_code):
    return http.post(
        "/oauth2/token",
        headers={"Host": host},
        data={
            "grant_type": GRANT,
            "device_code": device_code,
            "client_id": oauth_client["client_id"],
            "client_secret": oauth_client["client_secret"],
        },
    )


def _decide(test_tenant, user, user_code, *, approved=True):
    pending = device_service.find_pending_request(test_tenant["id"], user_code)
    assert device_service.decide_request(
        test_tenant["id"],
        pending,
        str(user["id"]),
        approved=approved,
        auth_time=None,
    )


def _assert_error(response, error, status=400):
    assert response.status_code == status, response.text
    body = response.json()
    assert body["error"] == error
    assert isinstance(body["error_description"], str)
    assert response.headers["cache-control"] == "no-store"


# ============================================================================
# POST /oauth2/device_authorization
# ============================================================================


class TestDeviceAuthorizationEndpoint:
    def test_no_csrf_token_needed(self, client, test_tenant_host, device_client):
        """A device is not a browser: it can never send a CSRF token."""
        with client.without_csrf():
            response = _start(client, test_tenant_host, device_client)
        assert response.status_code == 200

    def test_returns_codes_and_verification_uris(self, client, test_tenant_host, device_client):
        response = _start(client, test_tenant_host, device_client)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        assert set(body) == {
            "device_code",
            "user_code",
            "verification_uri",
            "verification_uri_complete",
            "expires_in",
            "interval",
        }
        assert body["verification_uri"] == f"https://{test_tenant_host}/device"
        assert body["verification_uri_complete"] == (
            f"https://{test_tenant_host}/device?user_code={body['user_code']}"
        )
        assert body["expires_in"] == 600
        assert body["interval"] == 5

    def test_basic_auth(self, client, test_tenant_host, device_client):
        creds = f"{device_client['client_id']}:{device_client['client_secret']}"
        response = client.post(
            "/oauth2/device_authorization",
            headers={
                "Host": test_tenant_host,
                "Authorization": "Basic " + base64.b64encode(creds.encode()).decode(),
            },
            data={"scope": "openid"},
        )
        assert response.status_code == 200

    def test_wrong_secret_is_invalid_client(self, client, test_tenant_host, device_client):
        response = _start(client, test_tenant_host, {**device_client, "client_secret": "nope"})
        _assert_error(response, "invalid_client", 401)

    def test_client_without_device_grant(
        self, client, test_tenant, test_tenant_host, test_admin_user
    ):
        disabled = _make_client(test_tenant, test_admin_user, enabled=False)
        _assert_error(_start(client, test_tenant_host, disabled), "unauthorized_client")

    def test_over_long_scope_is_invalid_request(self, client, test_tenant_host, device_client):
        response = _start(client, test_tenant_host, device_client, scope="x" * 501)
        _assert_error(response, "invalid_request")


# ============================================================================
# Token endpoint: device_code grant
# ============================================================================


class TestDeviceCodeGrant:
    def test_pending_then_slow_down(self, client, test_tenant_host, device_client):
        started = _start(client, test_tenant_host, device_client).json()
        first = _poll(client, test_tenant_host, device_client, started["device_code"])
        _assert_error(first, "authorization_pending")
        second = _poll(client, test_tenant_host, device_client, started["device_code"])
        _assert_error(second, "slow_down")

    def test_missing_device_code(self, client, test_tenant_host, device_client):
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": GRANT,
                "client_id": device_client["client_id"],
                "client_secret": device_client["client_secret"],
            },
        )
        _assert_error(response, "invalid_request")

    def test_approved_issues_tokens_once(
        self, client, test_tenant, test_tenant_host, device_client, test_user
    ):
        started = _start(client, test_tenant_host, device_client).json()
        _decide(test_tenant, test_user, started["user_code"])

        response = _poll(client, test_tenant_host, device_client, started["device_code"])
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["token_type"] == "Bearer"
        assert body["access_token"] and body["refresh_token"]

        claims = jwt.decode(body["id_token"], options={"verify_signature": False})
        assert claims["sub"] == str(test_user["id"])
        assert claims["aud"] == device_client["client_id"]
        assert claims["iss"] == f"https://{test_tenant_host}"
        assert "auth_time" in claims
        # Not tied to a browser session.
        assert "sid" not in claims
        refresh_row = database.fetchone(
            test_tenant["id"],
            "select sid, grant_id from oauth2_tokens where token_type = 'refresh' "
            "and client_id = :c",
            {"c": device_client["id"]},
        )
        assert refresh_row["sid"] is None
        assert refresh_row["grant_id"] is not None

        # The access token works at userinfo.
        userinfo = client.get(
            "/userinfo",
            headers={"Host": test_tenant_host, "Authorization": f"Bearer {body['access_token']}"},
        )
        assert userinfo.status_code == 200
        assert userinfo.json()["sub"] == str(test_user["id"])

        again = _poll(client, test_tenant_host, device_client, started["device_code"])
        _assert_error(again, "invalid_grant")

    def test_refresh_token_from_device_grant_rotates(
        self, client, test_tenant, test_tenant_host, device_client, test_user
    ):
        started = _start(client, test_tenant_host, device_client).json()
        _decide(test_tenant, test_user, started["user_code"])
        tokens = _poll(client, test_tenant_host, device_client, started["device_code"]).json()

        refreshed = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": device_client["client_id"],
                "client_secret": device_client["client_secret"],
            },
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["refresh_token"] != tokens["refresh_token"]

    def test_plain_oauth2_client_gets_no_id_token(
        self, client, test_tenant, test_tenant_host, test_admin_user, test_user
    ):
        plain = _make_client(test_tenant, test_admin_user, oidc=False)
        started = _start(client, test_tenant_host, plain).json()
        _decide(test_tenant, test_user, started["user_code"])
        body = _poll(client, test_tenant_host, plain, started["device_code"]).json()
        assert "access_token" in body
        assert "id_token" not in body

    def test_denied(self, client, test_tenant, test_tenant_host, device_client, test_user):
        started = _start(client, test_tenant_host, device_client).json()
        _decide(test_tenant, test_user, started["user_code"], approved=False)
        response = _poll(client, test_tenant_host, device_client, started["device_code"])
        _assert_error(response, "access_denied")

    def test_expired(self, client, test_tenant, test_tenant_host, device_client):
        started = _start(client, test_tenant_host, device_client).json()
        database.execute(
            test_tenant["id"],
            "update oauth2_device_codes set expires_at = now() - interval '1 second'",
            {},
        )
        response = _poll(client, test_tenant_host, device_client, started["device_code"])
        _assert_error(response, "expired_token")

    def test_unknown_device_code(self, client, test_tenant_host, device_client):
        response = _poll(client, test_tenant_host, device_client, "device_nope")
        _assert_error(response, "invalid_grant")

    def test_grant_switched_off_after_start(
        self, client, test_tenant, test_tenant_host, device_client
    ):
        started = _start(client, test_tenant_host, device_client).json()
        database.oauth2.update_client(
            test_tenant["id"], device_client["client_id"], device_grant_enabled=False
        )
        response = _poll(client, test_tenant_host, device_client, started["device_code"])
        _assert_error(response, "unauthorized_client")

    def test_access_rechecked_at_redemption(
        self, client, test_tenant, test_tenant_host, device_client, test_user
    ):
        started = _start(client, test_tenant_host, device_client).json()
        _decide(test_tenant, test_user, started["user_code"])
        database.execute(
            test_tenant["id"],
            "update oauth2_clients set available_to_all = false where id = :id",
            {"id": device_client["id"]},
        )
        response = _poll(client, test_tenant_host, device_client, started["device_code"])
        _assert_error(response, "access_denied")

    def test_user_token_revocation_voids_approval(
        self, client, test_tenant, test_tenant_host, device_client, test_user
    ):
        started = _start(client, test_tenant_host, device_client).json()
        _decide(test_tenant, test_user, started["user_code"])
        database.oauth2.revoke_all_user_tokens(test_tenant["id"], str(test_user["id"]))
        response = _poll(client, test_tenant_host, device_client, started["device_code"])
        _assert_error(response, "invalid_grant")


# ============================================================================
# /device verification page
# ============================================================================


@pytest.fixture
def anon(client, test_tenant_host, session_data):
    class _Client:
        def get(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.get(url, headers={"Host": test_tenant_host}, **kw)

        def post(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.post(url, headers={"Host": test_tenant_host}, **kw)

    return _Client()


@pytest.fixture
def authed(anon, test_user, override_auth, session_data):
    override_auth(test_user)
    session_data["user_id"] = str(test_user["id"])
    session_data["session_start"] = int(time.time())
    return anon


@pytest.fixture
def started(client, test_tenant_host, device_client):
    return _start(client, test_tenant_host, device_client).json()


class TestDevicePageEntry:
    def test_anonymous_is_sent_to_login_with_code_stashed(self, anon, session_data):
        response = anon.get("/device?user_code=bcdf ghjk")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert session_data[PENDING_DEVICE_KEY] == "/device?user_code=BCDF-GHJK"
        # Login completion resumes here.
        assert get_post_auth_redirect(session_data) == "/device?user_code=BCDF-GHJK"

    def test_anonymous_with_junk_code_stashes_bare_page(self, anon, session_data):
        anon.get("/device?user_code=<script>")
        assert session_data[PENDING_DEVICE_KEY] == "/device"

    def test_signed_in_sees_prefilled_form(self, authed):
        response = authed.get("/device?user_code=bcdfghjk")
        assert response.status_code == 200
        assert 'value="BCDF-GHJK"' in response.text
        assert 'action="/device"' in response.text

    @pytest.mark.parametrize("path", ["/device", "/device/decision"])
    def test_anonymous_posts_go_to_login(self, anon, path):
        response = anon.post(path, data={"user_code": "BCDF-GHJK", "action": "allow"})
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_forced_profile_completion(self, anon, test_user, override_auth):
        override_auth({**test_user, "force_profile_completion": True})
        response = anon.get("/device")
        assert response.status_code == 303
        assert response.headers["location"] == "/account/profile"


class TestDevicePageSubmit:
    def test_valid_code_shows_confirmation(
        self, authed, started, device_client, session_data, test_user
    ):
        response = authed.post("/device", data={"user_code": started["user_code"].lower()})
        assert response.status_code == 200
        assert device_client["name"] in response.text
        assert started["user_code"] in response.text
        assert "If someone else sent you this code, deny it." in response.text
        assert 'action="/device/decision"' in response.text
        stash = session_data[DEVICE_VERIFICATION_KEY]
        assert stash["user_code"] == started["user_code"]
        assert stash["user_id"] == str(test_user["id"])

    def test_invalid_code(self, authed, started, session_data):
        response = authed.post("/device", data={"user_code": "ZZZZ-ZZZZ"})
        assert response.status_code == 400
        assert "That code is not valid or has expired." in response.text
        assert DEVICE_VERIFICATION_KEY not in session_data

    def test_rate_limited(self, authed, started, mocker):
        mocker.patch("routers.device.ratelimit.prevent", side_effect=RateLimitError(message="slow"))
        response = authed.post("/device", data={"user_code": started["user_code"]})
        assert response.status_code == 429
        assert "Too many attempts" in response.text

    def test_user_without_access(
        self, authed, client, test_tenant, test_tenant_host, test_admin_user
    ):
        gated = _make_client(test_tenant, test_admin_user, available_to_all=False)
        code = _start(client, test_tenant_host, gated).json()["user_code"]
        response = authed.post("/device", data={"user_code": code})
        assert response.status_code == 403
        assert 'data-outcome="no_access"' in response.text


class TestDevicePageDecision:
    def _confirm(self, authed, started):
        assert authed.post("/device", data={"user_code": started["user_code"]}).status_code == 200

    def test_allow_then_device_gets_tokens(
        self, authed, started, client, test_tenant_host, device_client, session_data
    ):
        self._confirm(authed, started)
        response = authed.post("/device/decision", data={"action": "allow"})
        assert response.status_code == 200
        assert 'data-outcome="approved"' in response.text
        assert DEVICE_VERIFICATION_KEY not in session_data

        tokens = _poll(client, test_tenant_host, device_client, started["device_code"])
        assert tokens.status_code == 200
        claims = jwt.decode(tokens.json()["id_token"], options={"verify_signature": False})
        # auth_time is the approving session's login time.
        assert claims["auth_time"] == session_data["session_start"]

    def test_deny(self, authed, started, client, test_tenant_host, device_client):
        self._confirm(authed, started)
        response = authed.post("/device/decision", data={"action": "deny"})
        assert 'data-outcome="denied"' in response.text
        polled = _poll(client, test_tenant_host, device_client, started["device_code"])
        _assert_error(polled, "access_denied")

    def test_without_confirmation_step(self, authed, started):
        response = authed.post("/device/decision", data={"action": "allow"})
        assert response.status_code == 400
        assert 'data-outcome="expired"' in response.text

    def test_stash_of_another_user(self, authed, started, session_data):
        self._confirm(authed, started)
        session_data[DEVICE_VERIFICATION_KEY]["user_id"] = "someone-else"
        response = authed.post("/device/decision", data={"action": "allow"})
        assert 'data-outcome="expired"' in response.text

    def test_stale_confirmation(self, authed, started, session_data):
        self._confirm(authed, started)
        session_data[DEVICE_VERIFICATION_KEY]["created_at"] = time.time() - 601
        response = authed.post("/device/decision", data={"action": "allow"})
        assert 'data-outcome="expired"' in response.text

    def test_decided_elsewhere_first(self, authed, started, test_tenant, test_user):
        self._confirm(authed, started)
        _decide(test_tenant, test_user, started["user_code"], approved=False)
        response = authed.post("/device/decision", data={"action": "allow"})
        assert 'data-outcome="expired"' in response.text

    def test_invalid_action(self, authed, started):
        self._confirm(authed, started)
        response = authed.post("/device/decision", data={"action": "maybe"})
        assert response.status_code == 400

    def test_access_revoked_between_steps(self, authed, started, test_tenant, device_client):
        self._confirm(authed, started)
        database.execute(
            test_tenant["id"],
            "update oauth2_clients set available_to_all = false where id = :id",
            {"id": device_client["id"]},
        )
        response = authed.post("/device/decision", data={"action": "allow"})
        assert response.status_code == 403
        assert 'data-outcome="no_access"' in response.text
