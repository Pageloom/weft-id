"""RP-initiated logout to upstream OIDC providers, and the post-logout landing.

A session that began at an upstream OIDC connection with "sign out at the
provider" on continues, after the WeftID logout, to the provider's
end_session endpoint (OpenID Connect RP-Initiated Logout 1.0) with the
upstream ID token as ``id_token_hint``. A logout an RP started through
end_session keeps its return address across the round trip: it is stashed in
the signed-out session and ``/logout/complete`` (the post_logout_redirect_uri
WeftID registers upstream) finishes there. The same stash carries an
end_session logout through upstream SAML Single Logout (``/saml/slo``).

Real database throughout; the upstream token exchange and JWKS are patched.
"""

import html
import re
import time
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import database
import pytest
from routers.auth import logout as logout_router
from services import oidc_upstream as oidc_upstream_service
from services.oidc import tokens as tokens_service
from services.oidc_upstream import logout as upstream_logout
from utils.session import SESSION_ID_KEY

from tests.routers.test_oidc_upstream_backchannel_logout import (  # noqa: F401 - fixtures
    CLIENT_ID,
    ISSUER,
    _id_token,
    _jwks,
    _sign_in_upstream,
    connection,
)

END_SESSION = "https://idp.example.com/logout"
SID = "sess-rp-logout"
BYE = "https://rp.example/bye"


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
def sign_out_connection(test_tenant, connection):  # noqa: F811 - fixture reuse
    """The shared connection with an end_session endpoint and the toggle on."""
    return database.oidc_upstream.update_connection(
        str(test_tenant["id"]),
        str(connection["id"]),
        end_session_endpoint=END_SESSION,
        sign_out_at_idp=True,
    )


@pytest.fixture
def signed_in(http, test_user, override_auth, session_data):
    override_auth(test_user)
    session_data.update(
        {
            "user_id": str(test_user["id"]),
            "session_start": int(time.time()),
            SESSION_ID_KEY: SID,
        }
    )
    return http


def _link(test_tenant, test_user, conn, *, sid=SID, id_token="upstream.id.token"):
    tid = str(test_tenant["id"])
    database.oidc_upstream.record_idp_session(
        tid,
        tid,
        sid=sid,
        idp_id=str(conn["id"]),
        user_id=str(test_user["id"]),
        upstream_sub="subject-123",
        upstream_sid="idp-session-1",
        id_token=id_token,
    )


def _refresh_target(response) -> str:
    """The URL a page's declarative refresh navigates to."""
    match = re.search(r'http-equiv="refresh" content="0; ?url=([^"]+)"', response.text)
    assert match, response.text
    return html.unescape(match.group(1))


def _last_signed_out(test_tenant) -> dict:
    return next(
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=20)
        if e["event_type"] == "user_signed_out"
    )


# ============================================================================
# Service: build_upstream_logout_url
# ============================================================================


class TestBuildUpstreamLogoutUrl:
    def _url(self, test_tenant, sid=SID):
        return upstream_logout.build_upstream_logout_url(
            tenant_id=str(test_tenant["id"]),
            sid=sid,
            post_logout_redirect_uri="https://tenant.example/logout/complete",
        )

    def test_full_request(self, test_tenant, test_user, sign_out_connection):
        _link(test_tenant, test_user, sign_out_connection)
        url = self._url(test_tenant)
        parts = urlsplit(url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == END_SESSION
        assert parse_qs(parts.query) == {
            "id_token_hint": ["upstream.id.token"],
            "client_id": [CLIENT_ID],
            "post_logout_redirect_uri": ["https://tenant.example/logout/complete"],
        }

    def test_without_kept_id_token_identifies_by_client_id(
        self, test_tenant, test_user, sign_out_connection
    ):
        _link(test_tenant, test_user, sign_out_connection, id_token=None)
        query = parse_qs(urlsplit(self._url(test_tenant)).query)
        assert "id_token_hint" not in query
        assert query["client_id"] == [CLIENT_ID]

    def test_endpoint_with_query_is_joined_with_ampersand(
        self, test_tenant, test_user, sign_out_connection
    ):
        database.oidc_upstream.update_connection(
            str(test_tenant["id"]),
            str(sign_out_connection["id"]),
            end_session_endpoint=f"{END_SESSION}?p=b2c_1",
        )
        _link(test_tenant, test_user, sign_out_connection)
        url = self._url(test_tenant)
        assert url.startswith(f"{END_SESSION}?p=b2c_1&")
        assert parse_qs(urlsplit(url).query)["p"] == ["b2c_1"]

    def test_toggle_off_is_none(self, test_tenant, test_user, connection):  # noqa: F811
        database.oidc_upstream.update_connection(
            str(test_tenant["id"]), str(connection["id"]), end_session_endpoint=END_SESSION
        )
        _link(test_tenant, test_user, connection)
        assert self._url(test_tenant) is None

    def test_no_endpoint_is_none(self, test_tenant, test_user, connection):  # noqa: F811
        database.oidc_upstream.update_connection(
            str(test_tenant["id"]), str(connection["id"]), sign_out_at_idp=True
        )
        _link(test_tenant, test_user, connection)
        assert self._url(test_tenant) is None

    def test_no_client_id_is_none(self, test_tenant, test_user, sign_out_connection):
        database.oidc_upstream.update_connection(
            str(test_tenant["id"]), str(sign_out_connection["id"]), client_id=None
        )
        _link(test_tenant, test_user, sign_out_connection)
        assert self._url(test_tenant) is None

    def test_session_not_from_upstream_is_none(self, test_tenant, sign_out_connection):
        assert self._url(test_tenant, sid="never-linked") is None

    def test_disabled_connection_still_signs_out(self, test_tenant, test_user, sign_out_connection):
        database.oidc_upstream.set_connection_enabled(
            str(test_tenant["id"]), str(sign_out_connection["id"]), False
        )
        _link(test_tenant, test_user, sign_out_connection)
        assert self._url(test_tenant).startswith(END_SESSION)

    def test_other_tenant_sees_no_link(self, test_tenant, test_user, sign_out_connection):
        _link(test_tenant, test_user, sign_out_connection)
        suffix = uuid4().hex[:8]
        other = database.fetchone(
            database.UNSCOPED,
            "insert into tenants (subdomain, name) values (:s, :n) returning id",
            {"s": f"other-{suffix}", "n": f"Other {suffix}"},
        )
        try:
            assert self._url(other) is None
        finally:
            database.execute(
                database.UNSCOPED, "delete from tenants where id = :id", {"id": other["id"]}
            )


class TestIdTokenKept:
    def test_callback_keeps_the_verified_id_token(
        self,
        http,
        session_data,
        connection,  # noqa: F811
        test_tenant,
    ):
        token = _id_token(sid="idp-session-1")
        _sign_in_upstream(http, session_data, connection, token)
        row = database.oidc_upstream.get_idp_session(
            str(test_tenant["id"]), session_data[SESSION_ID_KEY]
        )
        assert row["id_token"] == token

    def test_mfa_detour_leaves_a_large_token_out_of_the_cookie(
        self, http, session_data, test_tenant, test_admin_user
    ):
        from routers.auth import _login_completion
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
        from unittest.mock import patch

        with patch("routers.oidc_upstream.authentication.send_mfa_code_email"):
            _sign_in_upstream(http, session_data, conn, _id_token(padding="x" * 3000))
        stash = session_data[_login_completion.PENDING_UPSTREAM_OIDC_SESSION_KEY]
        assert stash["id_token"] is None
        assert stash["sub"] == "subject-123"

    def test_mfa_detour_keeps_a_small_token(self, http, session_data, test_tenant, test_admin_user):
        from unittest.mock import patch

        from routers.auth import _login_completion
        from services.oidc_upstream.connections import _encrypt_secret

        conn = database.oidc_upstream.create_connection(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="MFA IdP small",
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
        token = _id_token()
        with patch("routers.oidc_upstream.authentication.send_mfa_code_email"):
            _sign_in_upstream(http, session_data, conn, token)
        stash = session_data[_login_completion.PENDING_UPSTREAM_OIDC_SESSION_KEY]
        assert stash["id_token"] == token

    def test_oversized_token_is_not_stored(self, test_tenant, test_user, connection):  # noqa: F811
        upstream_logout.record_upstream_session(
            tenant_id=str(test_tenant["id"]),
            sid="big-token",
            connection_id=str(connection["id"]),
            user_id=str(test_user["id"]),
            upstream_sub="subject-123",
            upstream_sid=None,
            id_token="x" * (upstream_logout.MAX_STORED_ID_TOKEN_LENGTH + 1),
        )
        row = database.oidc_upstream.get_idp_session(str(test_tenant["id"]), "big-token")
        assert row is not None
        assert row["id_token"] is None


# ============================================================================
# The logout button
# ============================================================================


class TestLogoutButton:
    def test_continues_to_the_provider_through_a_page(
        self, signed_in, session_data, test_tenant, test_user, sign_out_connection
    ):
        _link(test_tenant, test_user, sign_out_connection)

        response = signed_in.post("/logout")

        # A page, not a 303: Chromium applies the logout form's CSP
        # form-action to every redirect hop after the POST.
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        target = _refresh_target(response)
        assert target.startswith(f"{END_SESSION}?")
        query = parse_qs(urlsplit(target).query)
        assert query["id_token_hint"] == ["upstream.id.token"]
        assert query["post_logout_redirect_uri"][0].endswith(oidc_upstream_service.POST_LOGOUT_PATH)
        assert "Signing you out of your identity provider" in response.text
        # The session ended and was revoked; nothing is stashed for the return.
        assert "user_id" not in session_data
        assert logout_router.PENDING_LOGOUT_RETURN_KEY not in session_data
        assert database.revoked_sessions.is_session_revoked(str(test_tenant["id"]), SID)
        assert _last_signed_out(test_tenant)["metadata"]["upstream_oidc_logout"] is True

    def test_toggle_off_stays_local(
        self,
        signed_in,
        test_tenant,
        test_user,
        connection,  # noqa: F811
    ):
        _link(test_tenant, test_user, connection)
        response = signed_in.post("/logout")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert _last_signed_out(test_tenant)["metadata"]["upstream_oidc_logout"] is False

    def test_session_without_upstream_link_stays_local(self, signed_in, sign_out_connection):
        response = signed_in.post("/logout")
        assert response.headers["location"] == "/login"

    def test_builder_failure_never_blocks_logout(
        self, signed_in, session_data, test_tenant, test_user, sign_out_connection, mocker
    ):
        _link(test_tenant, test_user, sign_out_connection)
        mocker.patch(
            "routers.auth.logout.oidc_upstream_service.build_upstream_logout_url",
            side_effect=RuntimeError("db down"),
        )
        response = signed_in.post("/logout")
        assert response.headers["location"] == "/login"
        assert "user_id" not in session_data


# ============================================================================
# The post-logout landing
# ============================================================================


class TestLogoutComplete:
    def _stash(self, session_data, url, at=None):
        session_data[logout_router.PENDING_LOGOUT_RETURN_KEY] = {
            "url": url,
            "at": int(time.time()) if at is None else at,
        }

    def test_nothing_stashed_goes_to_login(self, http):
        response = http.get("/logout/complete")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_stashed_rp_address_is_honoured_once(self, http, session_data):
        self._stash(session_data, f"{BYE}?state=abc")
        response = http.get("/logout/complete")
        assert response.headers["location"] == f"{BYE}?state=abc"
        assert logout_router.PENDING_LOGOUT_RETURN_KEY not in session_data
        assert http.get("/logout/complete").headers["location"] == "/login"

    def test_stashed_path_goes_through_safe_redirect(self, http, session_data):
        self._stash(session_data, "/oauth2/logout/done")
        assert http.get("/logout/complete").headers["location"] == "/oauth2/logout/done"

    def test_unsafe_path_falls_back(self, http, session_data):
        self._stash(session_data, "//evil.example/x")
        assert http.get("/logout/complete").headers["location"] == "/dashboard"

    @pytest.mark.parametrize(
        "stash",
        [
            {"url": BYE, "at": int(time.time()) - 11 * 60},
            {"url": BYE, "at": "now"},
            {"url": "", "at": int(time.time())},
            {"url": 5, "at": int(time.time())},
            "not-a-dict",
        ],
    )
    def test_stale_or_malformed_stash_is_dropped(self, http, session_data, stash):
        session_data[logout_router.PENDING_LOGOUT_RETURN_KEY] = stash
        assert http.get("/logout/complete").headers["location"] == "/login"
        assert logout_router.PENDING_LOGOUT_RETURN_KEY not in session_data


# ============================================================================
# end_session (an RP started the logout) through an upstream round trip
# ============================================================================


@pytest.fixture
def rp_client(test_tenant, test_admin_user):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name=f"RP {uuid4().hex[:6]}",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        post_logout_redirect_uris=[BYE],
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], client["client_id"], oidc_enabled=True, available_to_all=True
    )
    return client


@pytest.fixture
def hint(test_tenant, test_tenant_host, rp_client, test_user):
    return tokens_service.issue_id_token(
        tenant_id=str(test_tenant["id"]),
        issuer=f"https://{test_tenant_host}",
        client_uuid=str(rp_client["id"]),
        client_id=rp_client["client_id"],
        user_id=str(test_user["id"]),
        scopes={"openid"},
    )


class TestEndSessionRoundTrip:
    def test_upstream_oidc_then_back_to_the_rp(
        self, signed_in, session_data, hint, test_tenant, test_user, sign_out_connection
    ):
        _link(test_tenant, test_user, sign_out_connection)

        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": hint, "post_logout_redirect_uri": BYE, "state": "st"},
        )

        assert response.status_code == 200
        assert _refresh_target(response).startswith(f"{END_SESSION}?")
        assert "user_id" not in session_data

        # The provider sends the browser back to the landing.
        back = signed_in.get("/logout/complete")
        assert back.status_code == 303
        assert back.headers["location"] == f"{BYE}?state=st"

    def test_without_post_logout_uri_finishes_on_signed_out_page(
        self, signed_in, hint, test_tenant, test_user, sign_out_connection
    ):
        _link(test_tenant, test_user, sign_out_connection)
        signed_in.get("/oauth2/logout", params={"id_token_hint": hint})
        assert signed_in.get("/logout/complete").headers["location"] == "/oauth2/logout/done"

    def test_confirmed_logout_finishes_on_signed_out_page(
        self, signed_in, test_tenant, test_user, sign_out_connection
    ):
        _link(test_tenant, test_user, sign_out_connection)
        response = signed_in.post("/oauth2/logout/confirm")
        assert _refresh_target(response).startswith(f"{END_SESSION}?")
        assert signed_in.get("/logout/complete").headers["location"] == "/oauth2/logout/done"

    def test_upstream_saml_slo_then_back_to_the_rp(self, signed_in, session_data, hint, mocker):
        session_data.update({"saml_idp_id": "idp-1", "saml_name_id": "user@example.com"})
        mocker.patch(
            "services.saml.initiate_sp_logout",
            return_value="https://saml-idp.example/slo?SAMLRequest=x",
        )

        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": hint, "post_logout_redirect_uri": BYE, "state": "st"},
        )

        assert response.status_code == 303
        assert response.headers["location"] == "https://saml-idp.example/slo?SAMLRequest=x"
        # The IdP answers at the SP SLO endpoint with its LogoutResponse.
        back = signed_in.get("/saml/slo?SAMLResponse=response")
        assert back.headers["location"] == f"{BYE}?state=st"

    def test_saml_logout_response_without_stash_goes_to_login(self, http):
        assert http.get("/saml/slo?SAMLResponse=r").headers["location"] == "/login?slo=complete"
        assert (
            http.post("/saml/slo", data={"SAMLResponse": "r"}).headers["location"]
            == "/login?slo=complete"
        )

    def test_frontchannel_iframes_load_before_the_upstream_hop(
        self, signed_in, hint, test_tenant, test_user, sign_out_connection, mocker
    ):
        from services.oidc import OidcSessionEnd

        _link(test_tenant, test_user, sign_out_connection)
        mocker.patch(
            "routers.auth.logout.end_oidc_session_quietly",
            return_value=OidcSessionEnd(frontchannel_logout_urls=["https://rp2.example/fc"]),
        )
        response = signed_in.get("/oauth2/logout", params={"id_token_hint": hint})
        assert 'src="https://rp2.example/fc"' in response.text
        assert _refresh_target(response).startswith(f"{END_SESSION}?")
        assert "Signing you out of connected applications" in response.text
