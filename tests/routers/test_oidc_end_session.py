"""OIDC end_session endpoint (OpenID Connect RP-Initiated Logout 1.0).

Covers what the conformance suite's RP-Initiated OP plan exercises at
``/oauth2/logout``: a verified hint ends the session and returns to the
registered ``post_logout_redirect_uri`` with ``state``; every unverifiable
request asks the user first and never redirects to the RP; POST behaves like
GET; the confirmation form is CSRF-protected; ``sid`` flows from the session
into the ID token.
"""

import time
from urllib.parse import parse_qs, urlsplit

import database
import jwt
import pytest
from services.oidc import tokens as tokens_service
from utils.session import SESSION_ID_KEY

ISSUER_HOST_SCHEME = "https://"
BYE = "https://rp.example/post_logout_redirect"
REDIRECT_URI = "https://rp.example/cb"


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
            SESSION_ID_KEY: "sess-under-test",
        }
    )
    return http


@pytest.fixture
def rp_client(test_tenant, test_admin_user):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Logout RP",
        redirect_uris=[REDIRECT_URI],
        created_by=test_admin_user["id"],
        post_logout_redirect_uris=[BYE],
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], client["client_id"], oidc_enabled=True, available_to_all=True
    )
    return client


@pytest.fixture
def hint(test_tenant, test_tenant_host, rp_client):
    """Factory: an ID token for ``user`` issued to ``rp_client`` on this tenant."""

    def _hint(user) -> str:
        return tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=f"{ISSUER_HOST_SCHEME}{test_tenant_host}",
            client_uuid=str(rp_client["id"]),
            client_id=rp_client["client_id"],
            user_id=str(user["id"]),
            scopes={"openid"},
        )

    return _hint


def _signed_out_events(test_tenant) -> list[dict]:
    return [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=20)
        if e["event_type"] == "user_signed_out"
    ]


# ============================================================================
# Verified hint: end the session without asking
# ============================================================================


class TestVerifiedLogout:
    def test_redirects_to_registered_uri_with_state(self, signed_in, hint, test_user, session_data):
        response = signed_in.get(
            "/oauth2/logout",
            params={
                "id_token_hint": hint(test_user),
                "post_logout_redirect_uri": BYE,
                "state": "s" * 128,
            },
        )
        assert response.status_code == 303
        location = response.headers["location"]
        assert location.startswith(BYE + "?")
        assert parse_qs(urlsplit(location).query) == {"state": ["s" * 128]}
        assert session_data == {}

    def test_no_state_means_no_query(self, signed_in, hint, test_user):
        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": hint(test_user), "post_logout_redirect_uri": BYE},
        )
        assert response.headers["location"] == BYE

    def test_state_joins_an_existing_query(
        self, signed_in, test_tenant, test_tenant_host, rp_client, test_user
    ):
        with_query = "https://rp.example/bye?from=weftid"
        database.oauth2.update_client(
            test_tenant["id"], rp_client["client_id"], post_logout_redirect_uris=[with_query]
        )
        token = tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=f"https://{test_tenant_host}",
            client_uuid=str(rp_client["id"]),
            client_id=rp_client["client_id"],
            user_id=str(test_user["id"]),
            scopes={"openid"},
        )
        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": token, "post_logout_redirect_uri": with_query, "state": "x"},
        )
        assert response.headers["location"] == with_query + "&state=x"

    def test_without_redirect_uri_lands_on_signed_out_page(
        self, signed_in, hint, test_user, session_data
    ):
        response = signed_in.get(
            "/oauth2/logout", params={"id_token_hint": hint(test_user), "state": "ignored"}
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/oauth2/logout/done"
        assert session_data == {}

    def test_is_audited_as_rp_initiated(self, signed_in, hint, test_user, test_tenant, rp_client):
        signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": hint(test_user), "post_logout_redirect_uri": BYE},
        )
        event = _signed_out_events(test_tenant)[0]
        assert str(event["actor_user_id"]) == str(test_user["id"])
        assert event["metadata"]["reason"] == "rp_initiated_logout"
        assert event["metadata"]["client_id"] == rp_client["client_id"]
        assert event["metadata"]["id_token_hint_verified"] is True
        assert event["metadata"]["post_logout_redirect"] is True
        assert event["metadata"]["confirmed_by_user"] is False

    def test_logout_does_not_touch_consent(
        self, signed_in, hint, test_user, test_tenant, rp_client
    ):
        database.oauth2.upsert_consent_grant(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            client_id=str(rp_client["id"]),
            user_id=str(test_user["id"]),
            scopes=["openid"],
        )
        signed_in.get("/oauth2/logout", params={"id_token_hint": hint(test_user)})
        assert database.oauth2.get_consent_grant(
            test_tenant["id"], str(rp_client["id"]), str(test_user["id"])
        )

    def test_notifies_downstream_saml_sps(self, signed_in, hint, test_user, session_data, mocker):
        propagate = mocker.patch("services.service_providers.slo.propagate_logout_to_sps")
        session_data["sso_active_sps"] = [{"sp_id": "sp-1"}]
        signed_in.get("/oauth2/logout", params={"id_token_hint": hint(test_user)})
        propagate.assert_called_once()
        assert propagate.call_args.kwargs["active_sps"] == [{"sp_id": "sp-1"}]

    def test_hint_without_session_still_redirects(self, http, hint, test_user, session_data):
        """Already signed out: nothing to end, the verified RP still gets its user back."""
        response = http.get(
            "/oauth2/logout",
            params={"id_token_hint": hint(test_user), "post_logout_redirect_uri": BYE},
        )
        assert response.status_code == 303
        assert response.headers["location"] == BYE

    def test_post_behaves_like_get(self, signed_in, client, hint, test_user, session_data):
        """RPs may POST; the endpoint is CSRF-exempt by exact path."""
        with client.without_csrf():
            response = signed_in.post(
                "/oauth2/logout",
                data={
                    "id_token_hint": hint(test_user),
                    "post_logout_redirect_uri": BYE,
                    "state": "p",
                },
            )
        assert response.status_code == 303
        assert response.headers["location"] == BYE + "?state=p"
        assert session_data == {}


# ============================================================================
# Anything unverifiable: ask first, never redirect to the RP
# ============================================================================


def _assert_confirmation_page(response, session_data):
    assert response.status_code == 200
    assert 'id="logout-confirm"' in response.text
    assert 'action="/oauth2/logout/confirm"' in response.text
    assert "user_id" in session_data  # nothing ended yet


class TestConfirmationPage:
    def test_no_parameters(self, signed_in, session_data):
        response = signed_in.get("/oauth2/logout")
        _assert_confirmation_page(response, session_data)
        assert 'role="alert"' not in response.text

    def test_only_state(self, signed_in, session_data):
        _assert_confirmation_page(
            signed_in.get("/oauth2/logout", params={"state": "s1"}), session_data
        )

    def test_redirect_uri_without_hint(self, signed_in, rp_client, session_data):
        response = signed_in.get(
            "/oauth2/logout",
            params={"client_id": rp_client["client_id"], "post_logout_redirect_uri": BYE},
        )
        _assert_confirmation_page(response, session_data)
        assert "did not identify the session" in response.text

    def test_unregistered_redirect_uri(self, signed_in, hint, test_user, session_data):
        response = signed_in.get(
            "/oauth2/logout",
            params={
                "id_token_hint": hint(test_user),
                "post_logout_redirect_uri": "https://evil.example/bye",
            },
        )
        _assert_confirmation_page(response, session_data)
        assert "post_logout_redirect_uri not registered" in response.text

    def test_query_added_to_redirect_uri(self, signed_in, hint, test_user, session_data):
        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": hint(test_user), "post_logout_redirect_uri": BYE + "?foo=bar"},
        )
        _assert_confirmation_page(response, session_data)

    def test_invalid_hint(self, signed_in, session_data):
        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": "not.a.token", "post_logout_redirect_uri": BYE},
        )
        _assert_confirmation_page(response, session_data)
        assert "could not be verified" in response.text

    def test_alg_none_hint(self, signed_in, hint, test_user, session_data):
        claims = jwt.decode(hint(test_user), options={"verify_signature": False})
        unsigned = jwt.encode(claims, key=None, algorithm="none")
        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": unsigned, "post_logout_redirect_uri": BYE},
        )
        _assert_confirmation_page(response, session_data)

    def test_unknown_client_id(self, signed_in, session_data):
        response = signed_in.get("/oauth2/logout", params={"client_id": "no-such-client"})
        _assert_confirmation_page(response, session_data)
        assert "not registered" in response.text

    def test_hint_for_another_user(self, signed_in, hint, test_admin_user, session_data):
        """A valid token for someone else must not sign this user out unasked."""
        response = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": hint(test_admin_user), "post_logout_redirect_uri": BYE},
        )
        _assert_confirmation_page(response, session_data)
        assert "different account" in response.text

    def test_unverifiable_request_without_session_goes_to_signed_out_page(self, http, session_data):
        response = http.get("/oauth2/logout", params={"post_logout_redirect_uri": BYE})
        assert response.status_code == 303
        assert response.headers["location"] == "/oauth2/logout/done"

    def test_over_long_parameter_is_rejected(self, signed_in):
        response = signed_in.get("/oauth2/logout", params={"state": "x" * 2049})
        assert response.status_code == 422


class TestConfirm:
    def test_confirm_ends_session_and_never_redirects_to_rp(
        self, signed_in, test_tenant, test_user, session_data
    ):
        signed_in.get("/oauth2/logout", params={"post_logout_redirect_uri": BYE})
        response = signed_in.post("/oauth2/logout/confirm", data={"confirm": "yes"})
        assert response.status_code == 303
        assert response.headers["location"] == "/oauth2/logout/done"
        assert session_data == {}
        event = _signed_out_events(test_tenant)[0]
        assert event["metadata"]["reason"] == "rp_initiated_logout"
        assert event["metadata"]["confirmed_by_user"] is True
        assert event["metadata"]["post_logout_redirect"] is False

    def test_confirm_requires_csrf(self, signed_in, client, session_data):
        with client.without_csrf():
            response = signed_in.post("/oauth2/logout/confirm", data={"confirm": "yes"})
        assert response.status_code == 403
        assert "user_id" in session_data

    def test_confirm_without_session(self, http, test_tenant, session_data):
        before = len(_signed_out_events(test_tenant))
        response = http.post("/oauth2/logout/confirm", data={"confirm": "yes"})
        assert response.status_code == 303
        assert response.headers["location"] == "/oauth2/logout/done"
        assert len(_signed_out_events(test_tenant)) == before


class TestSignedOutPage:
    def test_renders_when_signed_out(self, http):
        response = http.get("/oauth2/logout/done")
        assert response.status_code == 200
        assert 'id="logout-done"' in response.text
        assert "You have signed out" in response.text
        assert 'href="/login"' in response.text

    def test_signed_in_user_goes_to_dashboard(self, signed_in):
        response = signed_in.get("/oauth2/logout/done")
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"


# ============================================================================
# sid: from the session, via the code, into the ID token
# ============================================================================


class TestSid:
    def _code(self, signed_in, test_tenant, test_user, rp_client) -> str:
        database.oauth2.upsert_consent_grant(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            client_id=str(rp_client["id"]),
            user_id=str(test_user["id"]),
            scopes=["openid"],
        )
        response = signed_in.get(
            "/oauth2/authorize",
            params={
                "client_id": rp_client["client_id"],
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "openid",
            },
        )
        assert response.status_code == 303, response.text
        return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]

    def _id_token(self, client, test_tenant_host, rp_client, code) -> dict:
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": rp_client["client_id"],
                "client_secret": rp_client["client_secret"],
            },
        )
        assert response.status_code == 200, response.text
        return jwt.decode(response.json()["id_token"], options={"verify_signature": False})

    def test_id_token_carries_the_session_sid(
        self, signed_in, client, test_tenant, test_tenant_host, test_user, rp_client
    ):
        code = self._code(signed_in, test_tenant, test_user, rp_client)
        claims = self._id_token(client, test_tenant_host, rp_client, code)
        assert claims["sid"] == "sess-under-test"

    def test_legacy_session_gets_a_sid_that_sticks(
        self, signed_in, client, test_tenant, test_tenant_host, test_user, rp_client, session_data
    ):
        del session_data[SESSION_ID_KEY]
        first = self._id_token(
            client,
            test_tenant_host,
            rp_client,
            self._code(signed_in, test_tenant, test_user, rp_client),
        )
        assert first["sid"] == session_data[SESSION_ID_KEY]
        second = self._id_token(
            client,
            test_tenant_host,
            rp_client,
            self._code(signed_in, test_tenant, test_user, rp_client),
        )
        assert second["sid"] == first["sid"]

    def test_hint_from_the_real_flow_logs_out(
        self, signed_in, client, test_tenant, test_tenant_host, test_user, rp_client, session_data
    ):
        """End to end at the router level: the ID token the RP received is a
        usable id_token_hint."""
        code = self._code(signed_in, test_tenant, test_user, rp_client)
        response = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": rp_client["client_id"],
                "client_secret": rp_client["client_secret"],
            },
        )
        id_token = response.json()["id_token"]
        logout = signed_in.get(
            "/oauth2/logout",
            params={"id_token_hint": id_token, "post_logout_redirect_uri": BYE, "state": "z"},
        )
        assert logout.headers["location"] == BYE + "?state=z"
        assert session_data == {}
