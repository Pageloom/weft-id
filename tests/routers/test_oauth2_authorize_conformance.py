"""Authorization-endpoint conformance (OpenID Connect Core 1.0, section 3.1.2).

Covers the behaviour the OpenID Foundation conformance suite's Basic OP plan
exercises at ``/oauth2/authorize``: validation order (client and redirect_uri
before any redirect or login bounce), error redirects with ``state``, the POST
binding, request-object rejection, ``prompt``, ``max_age``, ``login_hint``,
``id_token_hint``, and the parameters that are accepted and ignored.
"""

import time
from urllib.parse import parse_qs, urlsplit

import pytest
from routers.oauth2 import SESSION_CONSENT_KEY, AuthorizeParams
from routers.saml_idp._helpers import PENDING_OAUTH2_AUTHORIZE_KEY, get_post_auth_redirect
from services import oidc as oidc_service

REDIRECT_URI = "http://localhost:3000/callback"


def _base_params(client_row: dict, **extra: str) -> dict[str, str]:
    params = {
        "client_id": client_row["client_id"],
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "state": "st-1",
    }
    params.update(extra)
    return params


def _location_query(response) -> dict[str, list[str]]:
    location = response.headers["location"]
    assert location.startswith(REDIRECT_URI + "?"), location
    return parse_qs(urlsplit(location).query)


@pytest.fixture
def session_data(mocker) -> dict:
    """A plain dict standing in for the Starlette session, so tests can seed
    ``session_start``/consent and inspect the stash or the clear."""
    data: dict = {}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: data),
    )
    return data


@pytest.fixture
def anon(client, test_tenant, test_tenant_host, session_data):
    """Unauthenticated tenant-scoped client (no session user)."""

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

    return _Client()


@pytest.fixture
def authed(anon, test_user, override_auth, session_data):
    """Authenticated client whose session was established just now."""
    override_auth(test_user)
    session_data["user_id"] = str(test_user["id"])
    session_data["session_start"] = int(time.time())
    return anon


# ============================================================================
# 1. client_id / redirect_uri are validated before anything else
# ============================================================================


class TestClientAndRedirectUriValidatedFirst:
    def test_unregistered_redirect_uri_unauthenticated_renders_error_page(
        self, anon, normal_oauth2_client, session_data
    ):
        """No login bounce, no stash, no redirect: the suite must see the page."""
        response = anon.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, redirect_uri="http://evil.example/cb"),
        )
        assert response.status_code == 200
        assert "Invalid redirect_uri" in response.text
        assert PENDING_OAUTH2_AUTHORIZE_KEY not in session_data

    def test_missing_redirect_uri_renders_error_page(self, anon, normal_oauth2_client):
        params = _base_params(normal_oauth2_client)
        del params["redirect_uri"]
        response = anon.get("/oauth2/authorize", params=params)
        assert response.status_code == 200
        assert "redirect_uri" in response.text
        assert "Authorization Error" in response.text

    def test_missing_client_id_renders_error_page(self, anon, normal_oauth2_client):
        params = _base_params(normal_oauth2_client)
        del params["client_id"]
        response = anon.get("/oauth2/authorize", params=params)
        assert response.status_code == 200
        assert "Invalid client_id" in response.text

    def test_unknown_client_unauthenticated_renders_error_page(self, anon, session_data):
        response = anon.get(
            "/oauth2/authorize",
            params={
                "client_id": "nope",
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
            },
        )
        assert response.status_code == 200
        assert "Invalid client_id" in response.text
        assert PENDING_OAUTH2_AUTHORIZE_KEY not in session_data

    def test_unregistered_redirect_uri_never_receives_error_redirect(
        self, anon, normal_oauth2_client
    ):
        """Even a request that is otherwise broken must not redirect to an
        unregistered URI (open-redirect guard)."""
        response = anon.get(
            "/oauth2/authorize",
            params={
                "client_id": normal_oauth2_client["client_id"],
                "redirect_uri": "http://evil.example/cb",
                # no response_type: would be an error redirect if the URI were trusted
            },
        )
        assert response.status_code == 200
        assert "location" not in response.headers


# ============================================================================
# 2. Parameter errors redirect to the verified redirect_uri with state
# ============================================================================


class TestParameterErrorRedirects:
    def test_missing_response_type_is_invalid_request(self, authed, normal_oauth2_client):
        params = _base_params(normal_oauth2_client)
        del params["response_type"]
        response = authed.get("/oauth2/authorize", params=params)
        assert response.status_code == 303
        query = _location_query(response)
        assert query["error"] == ["invalid_request"]
        assert query["state"] == ["st-1"]
        assert "code" not in query

    def test_unsupported_response_type(self, authed, normal_oauth2_client):
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, response_type="token")
        )
        query = _location_query(response)
        assert query["error"] == ["unsupported_response_type"]
        assert query["state"] == ["st-1"]

    def test_error_redirect_without_state_omits_it(self, authed, normal_oauth2_client):
        params = _base_params(normal_oauth2_client, response_type="id_token")
        del params["state"]
        response = authed.get("/oauth2/authorize", params=params)
        query = _location_query(response)
        assert query["error"] == ["unsupported_response_type"]
        assert "state" not in query

    def test_error_redirect_percent_encodes_state(self, authed, normal_oauth2_client):
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, response_type="token", state="a b&c=d"),
        )
        assert "a b" not in response.headers["location"]
        assert _location_query(response)["state"] == ["a b&c=d"]

    def test_unauthenticated_parameter_error_redirects_without_login(
        self, anon, normal_oauth2_client, session_data
    ):
        """Parameter validation precedes the session check."""
        response = anon.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, response_type="token")
        )
        assert _location_query(response)["error"] == ["unsupported_response_type"]
        assert PENDING_OAUTH2_AUTHORIZE_KEY not in session_data

    def test_request_parameter_rejected(self, authed, normal_oauth2_client):
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, request="eyJ.abc.def")
        )
        query = _location_query(response)
        assert query["error"] == ["request_not_supported"]
        assert query["state"] == ["st-1"]

    def test_request_uri_parameter_rejected(self, authed, normal_oauth2_client):
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, request_uri="https://rp.example/req"),
        )
        query = _location_query(response)
        assert query["error"] == ["request_uri_not_supported"]

    def test_request_object_rejected_before_response_type_check(self, authed, normal_oauth2_client):
        """The suite sends the real parameters inside the request object; the
        rejection must be request_not_supported, not a complaint about the
        bare query."""
        params = _base_params(normal_oauth2_client, request="eyJ.abc.def")
        del params["response_type"]
        response = authed.get("/oauth2/authorize", params=params)
        assert _location_query(response)["error"] == ["request_not_supported"]

    def test_invalid_max_age_is_invalid_request(self, authed, normal_oauth2_client):
        for bad in ("abc", "-1", "1.5", ""):
            response = authed.get(
                "/oauth2/authorize", params=_base_params(normal_oauth2_client, max_age=bad)
            )
            assert _location_query(response)["error"] == ["invalid_request"], bad

    def test_prompt_none_with_other_value_is_invalid_request(self, authed, normal_oauth2_client):
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, prompt="none login")
        )
        assert _location_query(response)["error"] == ["invalid_request"]


# ============================================================================
# 3. POST binding behaves exactly like GET
# ============================================================================


class TestPostBinding:
    def test_post_authenticated_renders_consent_page(self, authed, normal_oauth2_client):
        response = authed.post("/oauth2/authorize", data=_base_params(normal_oauth2_client))
        assert response.status_code == 200
        assert 'name="auth_request_id"' in response.text
        assert 'action="/oauth2/authorize/decision"' in response.text

    def test_post_needs_no_csrf_token(self, authed, normal_oauth2_client):
        """A relying party posting cross-site has no WeftID CSRF token."""
        response = authed.post("/oauth2/authorize", data=_base_params(normal_oauth2_client))
        assert response.status_code == 200

    def test_post_unauthenticated_stashes_form_parameters(
        self, anon, normal_oauth2_client, session_data
    ):
        response = anon.post(
            "/oauth2/authorize",
            data=_base_params(normal_oauth2_client, scope="openid profile", nonce="n1"),
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        stashed = session_data[PENDING_OAUTH2_AUTHORIZE_KEY]
        assert "://" not in stashed
        query = parse_qs(urlsplit(stashed).query)
        assert query["redirect_uri"] == [REDIRECT_URI]
        assert query["scope"] == ["openid profile"]
        assert query["nonce"] == ["n1"]
        assert query["response_type"] == ["code"]
        assert get_post_auth_redirect({PENDING_OAUTH2_AUTHORIZE_KEY: stashed}) == stashed

    def test_post_parameter_error_redirects(self, authed, normal_oauth2_client):
        response = authed.post(
            "/oauth2/authorize", data=_base_params(normal_oauth2_client, response_type="token")
        )
        assert _location_query(response)["error"] == ["unsupported_response_type"]

    def test_post_invalid_redirect_uri_renders_error_page(self, authed, normal_oauth2_client):
        response = authed.post(
            "/oauth2/authorize",
            data=_base_params(normal_oauth2_client, redirect_uri="http://evil.example/cb"),
        )
        assert response.status_code == 200
        assert "Invalid redirect_uri" in response.text

    def test_post_with_empty_body_renders_error_page(self, authed):
        response = authed.post("/oauth2/authorize")
        assert response.status_code == 200
        assert "Invalid client_id" in response.text

    def test_consent_decision_still_requires_csrf(self, client, authed, normal_oauth2_client):
        """Moving the decision form to its own path must not drop CSRF."""
        page = authed.get("/oauth2/authorize", params=_base_params(normal_oauth2_client))
        assert page.status_code == 200
        with client.without_csrf():
            response = authed.post(
                "/oauth2/authorize/decision",
                data={"auth_request_id": "whatever", "action": "allow"},
            )
        assert response.status_code == 403


# ============================================================================
# 4. prompt=none
# ============================================================================


class TestPromptNone:
    def test_not_logged_in_is_login_required(self, anon, normal_oauth2_client, session_data):
        response = anon.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, prompt="none")
        )
        assert response.status_code == 303
        query = _location_query(response)
        assert query["error"] == ["login_required"]
        assert query["state"] == ["st-1"]
        assert "code" not in query
        assert PENDING_OAUTH2_AUTHORIZE_KEY not in session_data

    def test_logged_in_without_consent_is_consent_required(self, authed, normal_oauth2_client):
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, prompt="none", scope="openid"),
        )
        query = _location_query(response)
        assert query["error"] == ["consent_required"]
        assert query["state"] == ["st-1"]

    def test_logged_in_with_session_consent_issues_code_without_ui(
        self, authed, normal_oauth2_client, session_data
    ):
        session_data[SESSION_CONSENT_KEY] = {
            normal_oauth2_client["client_id"]: ["openid", "profile"]
        }
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, prompt="none", scope="openid"),
        )
        assert response.status_code == 303
        query = _location_query(response)
        assert query["code"][0]
        assert query["state"] == ["st-1"]
        assert "error" not in query

    def test_session_consent_must_cover_every_requested_scope(
        self, authed, normal_oauth2_client, session_data
    ):
        session_data[SESSION_CONSENT_KEY] = {normal_oauth2_client["client_id"]: ["openid"]}
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, prompt="none", scope="openid email"),
        )
        assert _location_query(response)["error"] == ["consent_required"]

    def test_allow_remembers_consent_for_the_session(
        self, authed, normal_oauth2_client, session_data
    ):
        """The full loop: consent once, then prompt=none succeeds silently."""
        page = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, scope="openid email")
        )
        assert page.status_code == 200
        auth_request_id = next(iter(session_data["oauth2_auth_requests"]))
        csrf = session_data["_csrf_token"]
        decided = authed.post(
            "/oauth2/authorize/decision",
            data={"auth_request_id": auth_request_id, "action": "allow", "csrf_token": csrf},
        )
        assert decided.status_code == 303
        assert session_data[SESSION_CONSENT_KEY] == {
            normal_oauth2_client["client_id"]: ["email", "openid"]
        }

        silent = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, prompt="none", scope="email openid"),
        )
        assert silent.status_code == 303
        assert "code" in _location_query(silent)

    def test_deny_does_not_remember_consent(self, authed, normal_oauth2_client, session_data):
        page = authed.get("/oauth2/authorize", params=_base_params(normal_oauth2_client))
        assert page.status_code == 200
        auth_request_id = next(iter(session_data["oauth2_auth_requests"]))
        csrf = session_data["_csrf_token"]
        authed.post(
            "/oauth2/authorize/decision",
            data={"auth_request_id": auth_request_id, "action": "deny", "csrf_token": csrf},
        )
        assert SESSION_CONSENT_KEY not in session_data

    def test_prompt_none_with_reauth_needed_is_login_required(
        self, authed, normal_oauth2_client, session_data
    ):
        session_data["session_start"] = int(time.time()) - 3600
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, prompt="none", max_age="60"),
        )
        assert _location_query(response)["error"] == ["login_required"]
        # No session termination for a silent request.
        assert session_data.get("user_id")

    def test_prompt_none_with_forced_profile_is_interaction_required(
        self, anon, normal_oauth2_client, test_user, override_auth, session_data
    ):
        override_auth({**test_user, "force_profile_completion": True})
        response = anon.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, prompt="none")
        )
        assert _location_query(response)["error"] == ["interaction_required"]

    def test_prompt_none_access_denied_redirects(
        self, authed, test_tenant, test_admin_user, session_data
    ):
        from tests.routers.test_oauth2 import _make_oidc_client

        oidc_client = _make_oidc_client(test_tenant, test_admin_user, available_to_all=False)
        session_data[SESSION_CONSENT_KEY] = {oidc_client["client_id"]: ["openid"]}
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(oidc_client, prompt="none", scope="openid"),
        )
        assert _location_query(response)["error"] == ["access_denied"]


# ============================================================================
# 5. prompt=login / select_account and max_age force a fresh login
# ============================================================================


class TestReauthentication:
    @pytest.mark.parametrize("prompt", ["login", "select_account", "consent login"])
    def test_prompt_forces_fresh_login(
        self, authed, normal_oauth2_client, session_data, test_user, mocker, prompt
    ):
        log_event = mocker.patch("routers.oauth2.log_event")
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, prompt=prompt, scope="openid"),
        )
        assert response.status_code == 303
        location = response.headers["location"]
        assert location.startswith("/login?prefill_email=")
        assert test_user["email"].split("@")[0] in location

        # Session terminated, only the stash remains.
        assert "user_id" not in session_data
        assert "session_start" not in session_data
        stashed = session_data[PENDING_OAUTH2_AUTHORIZE_KEY]
        query = parse_qs(urlsplit(stashed).query)
        assert query["client_id"] == [normal_oauth2_client["client_id"]]
        assert query["scope"] == ["openid"]
        assert query["state"] == ["st-1"]
        # The re-auth demand is stripped so the resumed request does not loop.
        assert query.get("prompt") == (["consent"] if "consent" in prompt else None)
        assert get_post_auth_redirect({PENDING_OAUTH2_AUTHORIZE_KEY: stashed}) == stashed

        log_event.assert_called_once()
        kwargs = log_event.call_args.kwargs
        assert kwargs["event_type"] == "user_signed_out"
        assert kwargs["actor_user_id"] == str(test_user["id"])
        assert kwargs["metadata"]["reason"] == "reauthentication"
        assert kwargs["metadata"]["trigger"] == "prompt"
        assert kwargs["metadata"]["client_id"] == normal_oauth2_client["client_id"]

    def test_expired_max_age_forces_fresh_login(
        self, authed, normal_oauth2_client, session_data, mocker
    ):
        log_event = mocker.patch("routers.oauth2.log_event")
        session_data["session_start"] = int(time.time()) - 120
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, max_age="60")
        )
        assert response.status_code == 303
        assert response.headers["location"].startswith("/login")
        assert "user_id" not in session_data
        stashed = session_data[PENDING_OAUTH2_AUTHORIZE_KEY]
        assert "max_age" not in parse_qs(urlsplit(stashed).query)
        assert log_event.call_args.kwargs["metadata"]["trigger"] == "max_age"

    def test_max_age_zero_forces_fresh_login(self, authed, normal_oauth2_client, session_data):
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, max_age="0")
        )
        assert response.headers["location"].startswith("/login")
        assert "user_id" not in session_data

    def test_satisfied_max_age_shows_consent(self, authed, normal_oauth2_client, session_data):
        session_data["session_start"] = int(time.time()) - 5
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, max_age="10000")
        )
        assert response.status_code == 200
        assert 'name="auth_request_id"' in response.text
        assert session_data["user_id"]

    def test_session_without_auth_time_cannot_satisfy_max_age(
        self, authed, normal_oauth2_client, session_data
    ):
        del session_data["session_start"]
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, max_age="10000")
        )
        assert response.headers["location"].startswith("/login")

    def test_reauth_stash_resumes_without_looping(self, authed, normal_oauth2_client, session_data):
        """Replaying the stashed request on a fresh session shows consent."""
        first = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, prompt="login")
        )
        assert first.status_code == 303
        stashed = session_data.pop(PENDING_OAUTH2_AUTHORIZE_KEY)
        # Simulate login completion: a fresh authenticated session.
        session_data.clear()
        session_data["user_id"] = "x"
        session_data["session_start"] = int(time.time())
        resumed = authed.get(stashed)
        assert resumed.status_code == 200
        assert 'name="auth_request_id"' in resumed.text

    def test_code_issued_after_reauth_uses_fresh_auth_time(
        self, authed, normal_oauth2_client, session_data, mocker
    ):
        """auth_time comes from session_start, which a real login refreshes."""
        create_code = mocker.patch(
            "routers.oauth2.oauth2_service.create_authorization_code", return_value="c0de"
        )
        now = int(time.time())
        session_data["session_start"] = now
        session_data[SESSION_CONSENT_KEY] = {normal_oauth2_client["client_id"]: []}
        authed.get("/oauth2/authorize", params=_base_params(normal_oauth2_client, prompt="none"))
        assert int(create_code.call_args.kwargs["auth_time"].timestamp()) == now


# ============================================================================
# 6. login_hint
# ============================================================================


class TestLoginHint:
    def test_login_hint_prefills_login_page(self, anon, normal_oauth2_client, session_data):
        response = anon.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, login_hint="alice@example.com"),
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/login?prefill_email=alice%40example.com"
        # The hint is also stashed with the request (harmless on resume).
        assert "login_hint" in session_data[PENDING_OAUTH2_AUTHORIZE_KEY]

    def test_login_hint_cannot_redirect_elsewhere(self, anon, normal_oauth2_client):
        response = anon.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, login_hint="https://evil.example/x"),
        )
        location = response.headers["location"]
        assert location.startswith("/login?prefill_email=")
        assert "://" not in location

    def test_blank_login_hint_ignored(self, anon, normal_oauth2_client):
        response = anon.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, login_hint="  ")
        )
        assert response.headers["location"] == "/login"

    def test_login_hint_ignored_with_session(self, authed, normal_oauth2_client):
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, login_hint="bob@example.com"),
        )
        assert response.status_code == 200

    def test_login_hint_over_length_rejected(self, anon, normal_oauth2_client):
        response = anon.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, login_hint="a" * 321)
        )
        assert response.status_code == 422

    def test_login_page_renders_prefill(self, anon):
        response = anon.get("/login", params={"prefill_email": "alice@example.com"})
        assert response.status_code == 200
        assert 'value="alice@example.com"' in response.text


# ============================================================================
# 7. id_token_hint
# ============================================================================


def _mint_hint(test_tenant, test_tenant_host, client_row, user_id: str) -> str:
    return oidc_service.issue_id_token(
        tenant_id=str(test_tenant["id"]),
        issuer=f"https://{test_tenant_host}",
        client_uuid=str(client_row["id"]),
        client_id=client_row["client_id"],
        user_id=user_id,
        scopes={"openid"},
    )


class TestIdTokenHint:
    def test_hint_for_session_user_shows_consent(
        self, authed, normal_oauth2_client, test_tenant, test_tenant_host, test_user
    ):
        hint = _mint_hint(test_tenant, test_tenant_host, normal_oauth2_client, str(test_user["id"]))
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, id_token_hint=hint)
        )
        assert response.status_code == 200
        assert 'name="auth_request_id"' in response.text

    def test_hint_for_other_user_with_prompt_none_is_login_required(
        self, authed, normal_oauth2_client, test_tenant, test_tenant_host, test_admin_user
    ):
        hint = _mint_hint(
            test_tenant, test_tenant_host, normal_oauth2_client, str(test_admin_user["id"])
        )
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, id_token_hint=hint, prompt="none"),
        )
        assert _location_query(response)["error"] == ["login_required"]

    def test_hint_for_other_user_forces_fresh_login(
        self,
        authed,
        normal_oauth2_client,
        test_tenant,
        test_tenant_host,
        test_admin_user,
        session_data,
        mocker,
    ):
        log_event = mocker.patch("routers.oauth2.log_event")
        hint = _mint_hint(
            test_tenant, test_tenant_host, normal_oauth2_client, str(test_admin_user["id"])
        )
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, id_token_hint=hint)
        )
        assert response.headers["location"].startswith("/login")
        assert "user_id" not in session_data
        assert log_event.call_args.kwargs["metadata"]["trigger"] == "id_token_hint"
        # The hint stays in the stash: it is still true after the fresh login.
        assert "id_token_hint" in session_data[PENDING_OAUTH2_AUTHORIZE_KEY]

    def test_garbage_hint_is_invalid_request(self, authed, normal_oauth2_client):
        response = authed.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, id_token_hint="not.a.jwt"),
        )
        query = _location_query(response)
        assert query["error"] == ["invalid_request"]
        assert "id_token_hint" in query["error_description"][0]

    def test_hint_for_other_client_is_invalid_request(
        self, authed, normal_oauth2_client, test_tenant, test_tenant_host, test_user
    ):
        other = {**normal_oauth2_client, "client_id": "some-other-client"}
        hint = _mint_hint(test_tenant, test_tenant_host, other, str(test_user["id"]))
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, id_token_hint=hint)
        )
        assert _location_query(response)["error"] == ["invalid_request"]

    def test_hint_checked_before_session_when_unauthenticated(
        self, anon, normal_oauth2_client, test_tenant, test_tenant_host, test_user, session_data
    ):
        """A valid hint with no session still enters the login flow."""
        hint = _mint_hint(test_tenant, test_tenant_host, normal_oauth2_client, str(test_user["id"]))
        response = anon.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, id_token_hint=hint)
        )
        assert response.headers["location"] == "/login"
        assert PENDING_OAUTH2_AUTHORIZE_KEY in session_data


# ============================================================================
# 8. Accepted-and-ignored parameters; regression for the plain request
# ============================================================================


class TestAcceptedAndIgnored:
    @pytest.mark.parametrize(
        "extra",
        [
            {"display": "page"},
            {"display": "popup"},
            {"ui_locales": "sv-SE en"},
            {"claims_locales": "sv-SE"},
            {"acr_values": "urn:example:high"},
            {"response_mode": "query"},
            {"prompt": "consent"},
            {"prompt": "unknown_value"},
            {"extra_unknown_parameter": "foo"},
            {"scope": "openid profile email groups"},
        ],
    )
    def test_parameter_accepted_and_consent_shown(self, authed, normal_oauth2_client, extra):
        response = authed.get(
            "/oauth2/authorize", params=_base_params(normal_oauth2_client, **extra)
        )
        assert response.status_code == 200
        assert 'name="auth_request_id"' in response.text

    def test_plain_request_unchanged(self, authed, normal_oauth2_client, session_data):
        """The pre-Iteration-2 shape (client_id, redirect_uri, response_type,
        state) still renders consent and stores the request in the session."""
        response = authed.get("/oauth2/authorize", params=_base_params(normal_oauth2_client))
        assert response.status_code == 200
        stored = next(iter(session_data["oauth2_auth_requests"].values()))
        assert stored["client_id"] == normal_oauth2_client["client_id"]
        assert stored["redirect_uri"] == REDIRECT_URI
        assert stored["state"] == "st-1"
        csp = response.headers["Content-Security-Policy"]
        assert "form-action 'self' http://localhost:3000" in csp

    def test_stash_preserves_ignored_parameters(self, anon, normal_oauth2_client, session_data):
        anon.get(
            "/oauth2/authorize",
            params=_base_params(normal_oauth2_client, ui_locales="sv", response_mode="query"),
        )
        query = parse_qs(urlsplit(session_data[PENDING_OAUTH2_AUTHORIZE_KEY]).query)
        assert query["ui_locales"] == ["sv"]
        assert query["response_mode"] == ["query"]


class TestAuthorizeParamsAsQuery:
    def test_request_alias_and_ordering(self):
        pairs = AuthorizeParams(
            client_id="c", request_object="obj", prompt="login consent", max_age="5"
        ).as_query()
        assert pairs == [
            ("client_id", "c"),
            ("prompt", "login consent"),
            ("max_age", "5"),
            ("request", "obj"),
        ]

    def test_strip_reauth(self):
        pairs = AuthorizeParams(prompt="login consent", max_age="5", state="s").as_query(
            strip_reauth=True
        )
        assert pairs == [("state", "s"), ("prompt", "consent")]

    def test_strip_reauth_drops_empty_prompt(self):
        assert AuthorizeParams(prompt="select_account").as_query(strip_reauth=True) == []
