"""Upstream OIDC back-channel logout, end to end at the HTTP layer.

Covers the whole loop: an upstream sign-in links the new WeftID session to the
upstream session (``/auth/oidc/{id}/callback`` and login completion, including
the platform-MFA detour), the IdP POSTs a logout token to the receiver, and
the session is signed out on its next request because
``utils.auth.get_current_user`` consults the revocation list. Also the
receiver's HTTP contract (Back-Channel Logout 1.0, section 2.8).
"""

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import database
import jwt
import pytest
from routers.auth import _login_completion
from services.exceptions import RateLimitError
from services.oidc_upstream import jwks as jwks_service
from services.oidc_upstream import logout as logout_service
from starlette.requests import Request
from utils.session import SESSION_ID_KEY

from tests.fixtures.oidc import load_fixture, load_fixture_text
from tests.fixtures.oidc_login import login_session

JWKS_DOC = load_fixture("jwks")
PRIVATE_KEY_PEM = load_fixture_text("private_key.pem")
KID = "oidc-upstream-fixture-key"
ISSUER = "https://idp.example.com"
CLIENT_ID = "client-123"


@pytest.fixture(autouse=True)
def _jwks():
    logout_service._last_refetch.clear()
    with patch("services.oidc_upstream.jwks._fetch_jwks", return_value=JWKS_DOC):
        yield


@pytest.fixture
def session_data(mocker) -> dict:
    data: dict = {}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: data),
    )
    return data


@pytest.fixture
def http(client, test_tenant_host, session_data):
    class _Client:
        def get(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.get(url, headers={"Host": test_tenant_host}, **kw)

        def post(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.post(url, headers={"Host": test_tenant_host}, **kw)

    return _Client()


@pytest.fixture
def connection(test_tenant, test_admin_user):
    from services.oidc_upstream.connections import _encrypt_secret

    row = database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=f"IdP {uuid4().hex[:6]}",
        provider_type="generic",
        issuer=ISSUER,
        created_by=str(test_admin_user["id"]),
        authorization_endpoint="https://idp.example.com/authorize",
        token_endpoint="https://idp.example.com/token",
        jwks_uri="https://idp.example.com/jwks",
        client_id=CLIENT_ID,
        client_secret_enc=_encrypt_secret("super-secret-value"),
        is_enabled=True,
        jit_provisioning=True,
    )
    yield row
    jwks_service.clear_jwks_cache(str(test_tenant["id"]), str(row["id"]))


def _logout_token(**overrides) -> str:
    now = datetime.now(UTC)
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=2)).timestamp()),
        "jti": uuid4().hex,
        "events": {logout_service.BACKCHANNEL_LOGOUT_EVENT: {}},
        "sub": "subject-123",
        "sid": "idp-session-1",
    }
    payload.update(overrides)
    payload = {k: v for k, v in payload.items() if v is not None}
    return jwt.encode(
        payload, PRIVATE_KEY_PEM, algorithm="RS256", headers={"kid": KID, "typ": "logout+jwt"}
    )


def _id_token(**extra) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "subject-123",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "nonce": "n-1",
            "email": f"oidc-{uuid4().hex[:6]}@example.com",
            "email_verified": True,
            "given_name": "Oidc",
            "family_name": "User",
            **extra,
        },
        PRIVATE_KEY_PEM,
        algorithm="RS256",
        headers={"kid": KID},
    )


def _sign_in_upstream(http, session_data, connection, id_token):
    session_data.update(login_session(connection))
    with patch(
        "services.oidc_upstream.exchange_code",
        return_value={"access_token": "at", "id_token": id_token},
    ):
        return http.get(f"/auth/oidc/{connection['id']}/callback?state=state-1&code=code-1")


def _post_logout(http, connection, token):
    return http.post(
        f"/auth/oidc/{connection['id']}/backchannel-logout", data={"logout_token": token}
    )


class TestSignInLinksSession:
    def test_callback_links_new_session_to_upstream_sid(
        self, http, session_data, connection, test_tenant
    ):
        response = _sign_in_upstream(http, session_data, connection, _id_token(sid="idp-session-1"))

        assert response.status_code == 303
        sid = session_data[SESSION_ID_KEY]
        row = database.oidc_upstream.get_idp_session(str(test_tenant["id"]), sid)
        assert str(row["idp_id"]) == str(connection["id"])
        assert str(row["user_id"]) == session_data["user_id"]
        assert row["upstream_sub"] == "subject-123"
        assert row["upstream_sid"] == "idp-session-1"
        assert _login_completion.PENDING_UPSTREAM_OIDC_SESSION_KEY not in session_data

    def test_callback_without_upstream_sid_links_by_sub(
        self, http, session_data, connection, test_tenant
    ):
        _sign_in_upstream(http, session_data, connection, _id_token())
        row = database.oidc_upstream.get_idp_session(
            str(test_tenant["id"]), session_data[SESSION_ID_KEY]
        )
        assert row["upstream_sid"] is None

    def test_non_string_upstream_sid_ignored(self, http, session_data, connection, test_tenant):
        _sign_in_upstream(http, session_data, connection, _id_token(sid=123))
        row = database.oidc_upstream.get_idp_session(
            str(test_tenant["id"]), session_data[SESSION_ID_KEY]
        )
        assert row["upstream_sid"] is None

    def test_mfa_detour_keeps_the_stash_for_completion(
        self, http, session_data, test_tenant, test_admin_user
    ):
        from services.oidc_upstream.connections import _encrypt_secret

        conn = database.oidc_upstream.create_connection(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="MFA IdP",
            provider_type="generic",
            issuer=ISSUER,
            created_by=str(test_admin_user["id"]),
            token_endpoint="https://idp.example.com/token",
            jwks_uri="https://idp.example.com/jwks",
            client_id=CLIENT_ID,
            client_secret_enc=_encrypt_secret("s"),
            is_enabled=True,
            jit_provisioning=True,
            require_platform_mfa=True,
        )
        with patch("routers.oidc_upstream.authentication.send_mfa_code_email"):
            response = _sign_in_upstream(http, session_data, conn, _id_token(sid="idp-2"))

        assert response.headers["location"] == "/mfa/verify"
        stash = session_data[_login_completion.PENDING_UPSTREAM_OIDC_SESSION_KEY]
        assert stash["connection_id"] == str(conn["id"])
        assert stash["user_id"] == session_data["pending_mfa_user_id"]
        assert stash["sub"] == "subject-123"
        assert stash["sid"] == "idp-2"


def _request(session: dict) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/mfa/verify",
            "headers": [],
            "query_string": b"",
            "scheme": "https",
            "server": ("test", 443),
            "client": ("203.0.113.9", 1234),
            "session": session,
        }
    )


class TestLoginCompletionRecordsLink:
    def _stash(self, session, connection, user_id, overrides=None):
        _login_completion.stash_upstream_oidc_session(
            session,
            connection_id=str(connection["id"]),
            user_id=user_id,
            upstream_sub="subject-123",
            upstream_sid="idp-3",
        )
        session[_login_completion.PENDING_UPSTREAM_OIDC_SESSION_KEY].update(overrides or {})

    def _complete(self, test_tenant, test_user, session):
        request = _request(session)
        _login_completion.complete_authenticated_login(
            request, str(test_tenant["id"]), str(test_user["id"]), mfa_method="email"
        )
        return request.session

    def test_fresh_stash_for_this_user_is_recorded(self, test_tenant, test_user, connection):
        session: dict = {}
        self._stash(session, connection, str(test_user["id"]))
        after = self._complete(test_tenant, test_user, session)
        row = database.oidc_upstream.get_idp_session(str(test_tenant["id"]), after[SESSION_ID_KEY])
        assert row["upstream_sid"] == "idp-3"
        assert _login_completion.PENDING_UPSTREAM_OIDC_SESSION_KEY not in after

    @pytest.mark.parametrize(
        "overrides",
        [
            {"user_id": "someone-else"},
            {"at": int(time.time()) - 16 * 60},
            {"at": "yesterday"},
            {"sub": None},
            {"connection_id": None},
        ],
    )
    def test_foreign_stale_or_malformed_stash_is_dropped(
        self, test_tenant, test_user, connection, overrides
    ):
        session: dict = {}
        self._stash(session, connection, str(test_user["id"]), overrides)
        after = self._complete(test_tenant, test_user, session)
        assert (
            database.oidc_upstream.get_idp_session(str(test_tenant["id"]), after[SESSION_ID_KEY])
            is None
        )

    def test_non_dict_stash_is_dropped(self, test_tenant, test_user):
        session = {_login_completion.PENDING_UPSTREAM_OIDC_SESSION_KEY: "junk"}
        after = self._complete(test_tenant, test_user, session)
        assert _login_completion.PENDING_UPSTREAM_OIDC_SESSION_KEY not in after
        assert (
            database.oidc_upstream.get_idp_session(str(test_tenant["id"]), after[SESSION_ID_KEY])
            is None
        )


class TestReceiver:
    def test_logout_signs_the_linked_session_out(self, http, session_data, connection, test_tenant):
        _sign_in_upstream(http, session_data, connection, _id_token(sid="idp-session-1"))
        assert http.get("/account/profile").status_code == 200

        response = _post_logout(http, connection, _logout_token())

        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.content == b""
        denied = http.get("/account/profile")
        assert denied.status_code == 303
        assert denied.headers["location"] == "/login"
        assert "user_id" not in session_data

    def test_logout_for_other_upstream_session_leaves_this_one(
        self, http, session_data, connection
    ):
        _sign_in_upstream(http, session_data, connection, _id_token(sid="idp-session-1"))
        response = _post_logout(http, connection, _logout_token(sid="idp-session-2"))
        assert response.status_code == 200
        assert http.get("/account/profile").status_code == 200

    def test_invalid_token_is_400_invalid_request(self, http, connection):
        response = _post_logout(http, connection, _logout_token(aud="someone-else"))
        assert response.status_code == 400
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "error": "invalid_request",
            "error_description": "The logout token was rejected",
        }

    def test_replayed_token_is_400(self, http, connection):
        token = _logout_token()
        assert _post_logout(http, connection, token).status_code == 200
        assert _post_logout(http, connection, token).status_code == 400

    def test_missing_token_is_400(self, http, connection):
        response = http.post(f"/auth/oidc/{connection['id']}/backchannel-logout", data={})
        assert response.status_code == 400
        assert response.json()["error_description"] == "logout_token is required"

    def test_malformed_connection_id_is_400(self, http):
        response = http.post(
            "/auth/oidc/not-a-uuid/backchannel-logout", data={"logout_token": _logout_token()}
        )
        assert response.status_code == 400
        assert response.json()["error_description"] == "Unknown connection"

    def test_unknown_connection_is_400(self, http):
        response = http.post(
            f"/auth/oidc/{uuid4()}/backchannel-logout", data={"logout_token": _logout_token()}
        )
        assert response.status_code == 400

    def test_overlong_token_is_rejected(self, http, connection):
        response = _post_logout(http, connection, "a" * 16385)
        assert response.status_code == 422

    def test_rate_limited(self, http, connection):
        with patch(
            "routers.oidc_upstream.logout.ratelimit.prevent",
            side_effect=RateLimitError(message="slow", limit=60, timespan=300, retry_after=300),
        ):
            response = _post_logout(http, connection, _logout_token())
        assert response.status_code == 429
        assert response.json()["error"] == "slow_down"
        assert response.headers["cache-control"] == "no-store"


class TestCopiedCookieAfterLogout:
    def test_logout_kills_a_copy_of_the_session(self, http, session_data, test_user):
        session_data.update(
            {
                "user_id": str(test_user["id"]),
                "session_start": int(time.time()),
                SESSION_ID_KEY: "copied-sid",
            }
        )
        assert http.get("/account/profile").status_code == 200
        stolen = dict(session_data)

        assert http.post("/logout").headers["location"] == "/login"

        # The signed cookie a thief kept still carries the same payload.
        session_data.clear()
        session_data.update(stolen)
        response = http.get("/account/profile")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert session_data == {}
