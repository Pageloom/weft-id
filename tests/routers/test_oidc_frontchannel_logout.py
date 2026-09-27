"""OIDC front-channel logout (OpenID Connect Front-Channel Logout 1.0), OP side.

Ending a WeftID session loads the ``frontchannel_logout_uri`` of every client
that received an ID token in it, on an intermediate page that then continues
to wherever the logout was going: the RP's post-logout redirect, the
signed-out page, the login page, or upstream SAML Single Logout. Covers each
path that ends a session (end_session with a verified hint, the confirmation
form, the logout button, forced re-authentication), the page itself (iframes,
refresh, CSP, caching), audit, and that a lookup failure never blocks logout.
"""

import re
import time
from urllib.parse import parse_qs, urlsplit

import database
import pytest
from routers.saml_idp._helpers import PENDING_OAUTH2_AUTHORIZE_KEY
from services.oidc import tokens as tokens_service
from utils.session import SESSION_ID_KEY

SID = "sess-under-test"
REDIRECT_URI = "https://rp.example/cb"
BYE = "https://rp.example/post_logout_redirect"
FC_URI = "https://rp.example/frontchannel_logout"


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
    """Tenant-scoped client that never follows redirects."""

    class _Client:
        def get(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.get(url, headers={"Host": test_tenant_host}, **kw)

        def post(self, url, **kw):
            kw.setdefault("follow_redirects", False)
            return client.post(url, headers={"Host": test_tenant_host}, **kw)

    return _Client()


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


@pytest.fixture
def make_client(test_tenant, test_admin_user):
    """Factory: an OIDC-enabled client, optionally with front-channel logout."""

    def _make(name, *, fc_uri=FC_URI, session_required=True, redirect_uri=REDIRECT_URI):
        client = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            name=name,
            redirect_uris=[redirect_uri],
            created_by=test_admin_user["id"],
            post_logout_redirect_uris=[BYE],
            frontchannel_logout_uri=fc_uri,
            frontchannel_logout_session_required=session_required,
        )
        database.oauth2.update_client_oidc_settings(
            test_tenant["id"], client["client_id"], oidc_enabled=True, available_to_all=True
        )
        return client

    return _make


@pytest.fixture
def issue(test_tenant, test_tenant_host):
    """Factory: an ID token for ``user`` issued to ``client`` in session ``sid``."""

    def _issue(client, user, *, sid=SID) -> str:
        return tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=f"https://{test_tenant_host}",
            client_uuid=str(client["id"]),
            client_id=client["client_id"],
            user_id=str(user["id"]),
            scopes={"openid"},
            sid=sid,
        )

    return _issue


def _iframe_srcs(html: str) -> list[str]:
    return [src.replace("&amp;", "&") for src in re.findall(r'<iframe src="([^"]+)"', html)]


def _continue_url(html: str) -> str:
    match = re.search(r'<meta http-equiv="refresh" content="0; url=([^"]+)">', html)
    assert match, "no refresh"
    return match.group(1).replace("&amp;", "&")


def _last_signed_out(test_tenant) -> dict:
    return next(
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=20)
        if e["event_type"] == "user_signed_out"
    )


def _assert_interstitial(response, *, continue_url: str, iframe_count: int = 1) -> list[str]:
    assert response.status_code == 200, response.text
    html = response.text
    assert 'id="logout-frontchannel"' in html
    assert _continue_url(html) == continue_url
    link = re.search(r'id="logout-frontchannel-continue" href="([^"]+)"', html)
    assert link and link.group(1).replace("&amp;", "&") == continue_url
    assert response.headers["cache-control"] == "no-store"
    srcs = _iframe_srcs(html)
    assert len(srcs) == iframe_count
    return srcs


# ============================================================================
# end_session with a verified hint
# ============================================================================


class TestEndSession:
    def test_iframe_then_post_logout_redirect_with_state(
        self, signed_in, make_client, issue, test_user, test_tenant_host, session_data
    ):
        rp = make_client("RP")
        hint = issue(rp, test_user)

        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": hint, "post_logout_redirect_uri": BYE, "state": "st"},
        )

        (src,) = _assert_interstitial(response, continue_url=f"{BYE}?state=st")
        assert src.startswith(FC_URI + "?")
        assert parse_qs(urlsplit(src).query) == {
            "iss": [f"https://{test_tenant_host}"],
            "sid": [SID],
        }
        assert session_data == {}

    def test_csp_frames_only_the_rp_origin(self, signed_in, make_client, issue, test_user):
        rp = make_client("RP")
        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": issue(rp, test_user), "post_logout_redirect_uri": BYE},
        )
        csp = response.headers["content-security-policy"]
        assert "frame-src 'self' https://rp.example;" in csp
        assert "frame-ancestors 'none'" in csp

    def test_without_redirect_uri_continues_to_signed_out_page(
        self, signed_in, make_client, issue, test_user
    ):
        rp = make_client("RP")
        response = signed_in.get("/oauth2/logout", params={"id_token_hint": issue(rp, test_user)})
        _assert_interstitial(response, continue_url="/oauth2/logout/done")

    def test_every_client_in_the_session_is_notified(
        self, signed_in, make_client, issue, test_user
    ):
        rp = make_client("RP")
        other = make_client(
            "Other",
            fc_uri="https://other.example/fc",
            session_required=False,
            redirect_uri="https://other.example/cb",
        )
        issue(other, test_user)
        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": issue(rp, test_user), "post_logout_redirect_uri": BYE},
        )
        srcs = _assert_interstitial(response, continue_url=BYE, iframe_count=2)
        # First-issued order: "Other" received its token first.
        assert srcs[0] == "https://other.example/fc"
        assert srcs[1].startswith(FC_URI + "?")
        csp = response.headers["content-security-policy"]
        assert "frame-src 'self' https://other.example https://rp.example;" in csp

    def test_clients_from_other_sessions_are_not_notified(
        self, signed_in, make_client, issue, test_user
    ):
        rp = make_client("RP", fc_uri=None)
        other = make_client("Other")
        issue(other, test_user, sid="another-session")
        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": issue(rp, test_user), "post_logout_redirect_uri": BYE},
        )
        assert response.status_code == 303
        assert response.headers["location"] == BYE

    def test_audit_counts_frontchannel_urls(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        rp = make_client("RP")
        signed_in.get("/oauth2/logout", params={"id_token_hint": issue(rp, test_user)})
        event = _last_signed_out(test_tenant)
        assert event["metadata"]["frontchannel_logout_count"] == 1
        assert event["metadata"]["reason"] == "rp_initiated_logout"

    def test_no_session_means_no_iframes(self, http, make_client, issue, test_user):
        """Nothing to end: the verified hint just redirects."""
        rp = make_client("RP")
        response = http.get(
            "/oauth2/logout",
            params={"id_token_hint": issue(rp, test_user), "post_logout_redirect_uri": BYE},
        )
        assert response.status_code == 303
        assert response.headers["location"] == BYE

    def test_lookup_failure_never_blocks_logout(
        self, signed_in, make_client, issue, test_user, session_data, mocker
    ):
        rp = make_client("RP")
        hint = issue(rp, test_user)
        mocker.patch(
            "services.oidc.end_oidc_session", side_effect=RuntimeError("database unavailable")
        )
        response = signed_in.get(
            "/oauth2/logout", params={"id_token_hint": hint, "post_logout_redirect_uri": BYE}
        )
        assert response.status_code == 303
        assert response.headers["location"] == BYE
        assert session_data == {}


# ============================================================================
# The confirmation form
# ============================================================================


class TestConfirm:
    def test_confirm_loads_iframes_then_signed_out_page(
        self, signed_in, make_client, issue, test_user, session_data
    ):
        rp = make_client("RP")
        issue(rp, test_user)
        response = signed_in.post("/oauth2/logout/confirm")
        _assert_interstitial(response, continue_url="/oauth2/logout/done")
        assert session_data == {}


# ============================================================================
# The logout button
# ============================================================================


class TestLocalLogout:
    def test_iframes_then_login_page(
        self, signed_in, make_client, issue, test_user, test_tenant, session_data
    ):
        rp = make_client("RP")
        issue(rp, test_user)
        response = signed_in.post("/logout")
        _assert_interstitial(response, continue_url="/login")
        assert session_data == {}
        assert _last_signed_out(test_tenant)["metadata"]["frontchannel_logout_count"] == 1

    def test_without_frontchannel_clients_redirects_as_before(self, signed_in, test_tenant):
        response = signed_in.post("/logout")
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert _last_signed_out(test_tenant)["metadata"]["frontchannel_logout_count"] == 0

    def test_iframes_then_upstream_saml_slo(
        self, signed_in, make_client, issue, test_user, session_data, mocker
    ):
        rp = make_client("RP")
        issue(rp, test_user)
        session_data.update({"saml_idp_id": "idp-1", "saml_name_id": "user@idp"})
        slo = "https://idp.example/slo?SAMLRequest=abc"
        mocker.patch("services.saml.initiate_sp_logout", return_value=slo)

        response = signed_in.post("/logout")
        _assert_interstitial(response, continue_url=slo)


# ============================================================================
# Forced re-authentication (prompt=login, max_age)
# ============================================================================


class TestReauthentication:
    def _authorize(self, signed_in, rp, **extra):
        return signed_in.get(
            "/oauth2/authorize",
            params={
                "client_id": rp["client_id"],
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
                **extra,
            },
        )

    def test_other_clients_notified_on_the_way_to_login(
        self, signed_in, make_client, issue, test_user, test_tenant, session_data
    ):
        asking = make_client("Asking")
        other = make_client(
            "Other", fc_uri="https://other.example/fc", redirect_uri="https://other.example/cb"
        )
        issue(asking, test_user)
        issue(other, test_user)

        response = self._authorize(signed_in, asking, prompt="login")

        (src,) = _assert_interstitial(
            response,
            continue_url=f"/login?prefill_email={test_user['email'].replace('@', '%40')}",
        )
        assert src.startswith("https://other.example/fc?")
        assert "user_id" not in session_data
        assert session_data[PENDING_OAUTH2_AUTHORIZE_KEY].startswith("/oauth2/authorize?")
        event = _last_signed_out(test_tenant)
        assert event["metadata"]["reason"] == "reauthentication"
        assert event["metadata"]["frontchannel_logout_count"] == 1

    def test_only_the_asking_client_means_a_plain_redirect(
        self, signed_in, make_client, issue, test_user, test_tenant
    ):
        """The RP mid-login is never sent a logout; its record is still removed."""
        asking = make_client("Asking")
        issue(asking, test_user)

        response = self._authorize(signed_in, asking, prompt="login")

        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")
        assert _last_signed_out(test_tenant)["metadata"]["frontchannel_logout_count"] == 0
        assert database.oauth2.delete_session_clients(test_tenant["id"], SID) == []


# ============================================================================
# The ID token from the real flow is recorded against the session
# ============================================================================


def test_token_endpoint_records_the_session(
    signed_in, client, make_client, test_tenant, test_tenant_host, test_user
):
    rp = make_client("RP")
    database.oauth2.upsert_consent_grant(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        client_id=str(rp["id"]),
        user_id=str(test_user["id"]),
        scopes=["openid"],
    )
    authorize = signed_in.get(
        "/oauth2/authorize",
        params={
            "client_id": rp["client_id"],
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid",
        },
    )
    code = parse_qs(urlsplit(authorize.headers["location"]).query)["code"][0]
    token = client.post(
        "/oauth2/token",
        headers={"Host": test_tenant_host},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": rp["client_id"],
            "client_secret": rp["client_secret"],
        },
    )
    assert token.status_code == 200, token.text

    response = signed_in.post("/logout")
    (src,) = _assert_interstitial(response, continue_url="/login")
    assert parse_qs(urlsplit(src).query)["sid"] == [SID]


# ============================================================================
# The page helper
# ============================================================================


def test_csp_never_carries_anything_but_plain_origins(mocker):
    """A registered URI is validated, but the header builder does not rely on it."""
    from routers.auth.logout import frontchannel_logout_response

    request = mocker.MagicMock()
    request.state = type("State", (), {})()
    mocker.patch("routers.auth.logout.templates.TemplateResponse", return_value=mocker.MagicMock())
    mocker.patch("routers.auth.logout.get_csp_nonce", return_value="n")

    frontchannel_logout_response(
        request,
        [
            "https://ok.example:8443/fc",
            "https://ok.example:8443/other",
            "https://bad;script-src *.example/fc",
            "https://user:pw@creds.example/fc",
        ],
        "/login",
    )
    assert request.state.csp_frame_src_origins == ["https://ok.example:8443"]
