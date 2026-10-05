"""Sign in with Apple through the routes: the form_post callback hop, the
server-side login state, the admin form and key card, and the API.

Apple's token endpoint is patched; ID tokens are signed with the fixture key
in ``tests/fixtures/apple.py``.
"""

import os
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from main import app

from tests.fixtures import apple as fx
from tests.fixtures.oidc_login import login_session
from tests.helpers.client import TestClient


@pytest.fixture(autouse=True)
def setup_app_directory():
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def tenant_client(test_tenant):
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_tenant["id"])
    yield TestClient(app)


@pytest.fixture
def super_admin_session(client, test_tenant_host, test_super_admin_user, override_auth):
    override_auth(test_super_admin_user, level="super_admin")
    yield client


def _last_event(tenant_id, event_type):
    import database

    return next(
        e
        for e in database.event_log.list_events(tenant_id, limit=50)
        if e["event_type"] == event_type
    )


def _events(tenant_id, event_type):
    import database

    return [
        e
        for e in database.event_log.list_events(tenant_id, limit=50)
        if e["event_type"] == event_type
    ]


def _patched_apple(nonce):
    """Patch Apple's token endpoint and keys for one sign-in."""
    from contextlib import ExitStack

    stack = ExitStack()
    exchange = stack.enter_context(
        patch(
            "services.oidc_upstream.exchange_code",
            return_value={"access_token": "at", "id_token": fx.id_token(nonce=nonce)},
        )
    )
    stack.enter_context(patch("services.oidc_upstream.jwks._fetch_jwks", return_value=fx.jwks()))
    return stack, exchange


def _start(tenant_client, conn):
    from services.oidc_upstream.login_state import load_login_state

    response = tenant_client.get(
        f"/auth/oidc/{conn['id']}/login?via=login_button", follow_redirects=False
    )
    assert response.status_code == 303
    params = parse_qs(urlparse(response.headers["location"]).query)
    state = params["state"][0]
    return params, state, load_login_state(state)


# =============================================================================
# Sign-in
# =============================================================================


class TestLogin:
    def test_redirects_to_apple_with_form_post(self, tenant_client, test_tenant, test_user):
        conn = fx.make_apple_row(test_tenant, test_user["id"], show_on_login=True)
        params, state, stored = _start(tenant_client, conn)
        assert params["response_mode"] == ["form_post"]
        assert params["client_id"] == [fx.CLIENT_ID]
        assert params["scope"] == ["openid name email"]
        assert params["nonce"] == [stored.nonce]
        assert "code_challenge" not in params
        assert params["redirect_uri"][0].endswith(f"/auth/oidc/{conn['id']}/callback")
        # The rest of the sign-in lives in the store; the session holds only state.
        assert stored.tenant_id == str(test_tenant["id"])
        assert stored.connection_id == str(conn["id"])
        assert stored.entry == "login_button"
        assert tenant_client.session_cookie() == {f"oidc_auth:{conn['id']}:state": state}


class TestFormPostFlow:
    def test_first_sign_in_creates_named_user(self, tenant_client, test_tenant, test_user):
        import database

        conn = fx.make_apple_row(
            test_tenant, test_user["id"], jit_provisioning=True, show_on_login=True
        )
        _, state, stored = _start(tenant_client, conn)

        # Apple posts from its own site: no session cookie arrives.
        apple_side = TestClient(app)
        posted = apple_side.post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": state, "code": "code-1", "user": fx.USER_FIELD},
            follow_redirects=False,
        )
        assert posted.status_code == 303
        assert posted.headers["location"] == f"/auth/oidc/{conn['id']}/callback?state={state}"
        assert "set-cookie" not in posted.headers

        stack, exchange = _patched_apple(stored.nonce)
        with stack:
            response = tenant_client.get(posted.headers["location"], follow_redirects=False)

        assert response.status_code == 303
        assert exchange.call_args.kwargs["code"] == "code-1"
        assert exchange.call_args.kwargs["code_verifier"] is None
        user_id = database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), fx.SUBJECT
        )
        user = database.users.get_user_by_id(test_tenant["id"], str(user_id))
        assert (user["first_name"], user["last_name"]) == ("Ada", "Lovelace")
        event = _last_event(test_tenant["id"], "oidc_user_jit_provisioned")
        assert event["metadata"]["entry"] == "login_button"
        # Single use: the stored sign-in is gone.
        from services.oidc_upstream.login_state import load_login_state

        assert load_login_state(state) is None

    def test_cancel_at_apple_is_logged(self, tenant_client, test_tenant, test_user):
        conn = fx.make_apple_row(test_tenant, test_user["id"])
        _, state, _ = _start(tenant_client, conn)
        posted = TestClient(app).post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": state, "error": "user_cancelled_authorize"},
            follow_redirects=False,
        )
        response = tenant_client.get(posted.headers["location"], follow_redirects=False)
        assert response.headers["location"].endswith("/login?error=auth_failed")
        event = _last_event(test_tenant["id"], "oidc_login_failed")
        assert event["metadata"]["reason"] == "idp_error"
        assert event["metadata"]["detail"] == "user_cancelled_authorize"

    def test_posted_fields_beat_query_string(self, tenant_client, test_tenant, test_user):
        conn = fx.make_apple_row(test_tenant, test_user["id"], jit_provisioning=True)
        _, state, stored = _start(tenant_client, conn)
        TestClient(app).post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": state, "code": "posted-code"},
            follow_redirects=False,
        )
        stack, exchange = _patched_apple(stored.nonce)
        with stack:
            tenant_client.get(
                f"/auth/oidc/{conn['id']}/callback?state={state}&code=forged-code",
                follow_redirects=False,
            )
        assert exchange.call_args.kwargs["code"] == "posted-code"

    def test_other_browser_cannot_finish(self, tenant_client, test_tenant, test_user):
        from services.oidc_upstream.login_state import load_login_state

        conn = fx.make_apple_row(test_tenant, test_user["id"])
        _, state, _ = _start(tenant_client, conn)
        posted = TestClient(app).post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": state, "code": "code-1"},
            follow_redirects=False,
        )
        # A browser without the session's state (an attacker's victim).
        response = TestClient(app).get(posted.headers["location"], follow_redirects=False)
        assert response.headers["location"].endswith("/login?error=auth_failed")
        assert _last_event(test_tenant["id"], "oidc_login_failed")["metadata"]["reason"] == (
            "state_mismatch"
        )
        # Not consumed: the real browser can still finish.
        assert load_login_state(state) is not None


class TestPostCallbackRefusals:
    def test_unknown_state(self, tenant_client, test_tenant, test_user):
        conn = fx.make_apple_row(test_tenant, test_user["id"])
        response = TestClient(app).post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": "never-issued", "code": "code-1"},
            follow_redirects=False,
        )
        assert response.headers["location"].endswith("/login?error=auth_failed")
        event = _last_event(test_tenant["id"], "oidc_login_failed")
        assert event["metadata"]["reason"] == "state_mismatch"
        assert event["metadata"]["entry"] == "routed"

    def test_missing_state(self, tenant_client, test_tenant, test_user):
        conn = fx.make_apple_row(test_tenant, test_user["id"])
        response = TestClient(app).post(
            f"/auth/oidc/{conn['id']}/callback", data={"code": "c"}, follow_redirects=False
        )
        assert response.headers["location"].endswith("/login?error=auth_failed")

    def test_second_post_refused(self, tenant_client, test_tenant, test_user):
        from services.oidc_upstream.login_state import load_login_state

        conn = fx.make_apple_row(test_tenant, test_user["id"])
        login_session(conn, entry="login_button")
        client = TestClient(app)
        first = client.post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": "state-1", "code": "first"},
            follow_redirects=False,
        )
        assert first.status_code == 303
        second = client.post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": "state-1", "code": "second"},
            follow_redirects=False,
        )
        assert second.headers["location"].endswith("/login?error=auth_failed")
        assert _last_event(test_tenant["id"], "oidc_login_failed")["metadata"]["entry"] == (
            "login_button"
        )
        assert load_login_state("state-1").callback_fields == {"code": "first"}

    def test_state_of_another_connection_refused(self, tenant_client, test_tenant, test_user):
        conn = fx.make_apple_row(test_tenant, test_user["id"])
        other = fx.make_apple_row(test_tenant, test_user["id"], name="Apple 2")
        login_session(other)
        response = TestClient(app).post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": "state-1", "code": "c"},
            follow_redirects=False,
        )
        assert response.headers["location"].endswith("/login?error=auth_failed")

    def test_state_of_another_tenant_refused(self, tenant_client, test_tenant, test_user):
        from services.oidc_upstream.login_state import LoginState, save_login_state

        conn = fx.make_apple_row(test_tenant, test_user["id"])
        save_login_state(
            "state-x",
            LoginState(
                tenant_id="00000000-0000-0000-0000-000000000001",
                connection_id=str(conn["id"]),
                nonce="n",
                code_verifier="v",
                entry="routed",
            ),
        )
        response = tenant_client.post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": "state-x", "code": "c"},
            follow_redirects=False,
        )
        assert response.headers["location"].endswith("/login?error=auth_failed")

    def test_disabled_connection(self, tenant_client, test_tenant, test_user):
        conn = fx.make_apple_row(test_tenant, test_user["id"], is_enabled=False)
        response = TestClient(app).post(
            f"/auth/oidc/{conn['id']}/callback", data={"state": "s"}, follow_redirects=False
        )
        assert response.headers["location"].endswith("/login?error=idp_disabled")

    def test_unknown_connection(self, tenant_client):
        response = tenant_client.post(
            "/auth/oidc/not-a-uuid/callback", data={"state": "s"}, follow_redirects=False
        )
        assert response.headers["location"].endswith("/login?error=idp_not_found")

    def test_rate_limited(self, tenant_client, test_tenant, test_user):
        from services.exceptions import RateLimitError

        conn = fx.make_apple_row(test_tenant, test_user["id"])
        with patch(
            "routers.oidc_upstream.authentication.ratelimit.prevent",
            side_effect=RateLimitError(message="slow down", code="rate_limited"),
        ):
            response = TestClient(app).post(
                f"/auth/oidc/{conn['id']}/callback", data={"state": "s"}, follow_redirects=False
            )
        assert response.headers["location"].endswith("/login?error=too_many_requests")

    def test_over_long_field_rejected(self, tenant_client, test_tenant, test_user):
        conn = fx.make_apple_row(test_tenant, test_user["id"])
        response = TestClient(app).post(
            f"/auth/oidc/{conn['id']}/callback",
            data={"state": "s", "user": "x" * 5000},
            follow_redirects=False,
        )
        assert response.status_code == 422


class TestStoreUnavailable:
    def test_login_fails_closed(self, tenant_client, test_tenant, test_user, monkeypatch):
        from utils import cache

        conn = fx.make_apple_row(test_tenant, test_user["id"])
        monkeypatch.setattr(cache, "get_client", lambda: None)
        response = tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
        assert response.headers["location"].endswith("/login?error=auth_failed")
        assert _last_event(test_tenant["id"], "oidc_login_failed")["metadata"]["reason"] == (
            "state_store"
        )
        assert _events(test_tenant["id"], "oidc_login_started") == []


class TestLoginButton:
    def test_apple_button_style(self, tenant_client, test_tenant, test_user):
        conn = fx.make_apple_row(test_tenant, test_user["id"], show_on_login=True)
        page = tenant_client.get("/login").text
        assert f'href="/auth/oidc/{conn["id"]}/login?via=login_button"' in page
        assert "Continue with Apple" in page
        assert "dark:bg-black" in page


# =============================================================================
# Admin
# =============================================================================


class TestAdmin:
    def test_form_offers_apple_key_fields(self, super_admin_session):
        page = super_admin_session.get("/identity-providers/oidc/new").text
        assert '<option value="apple">Apple</option>' in page
        assert 'name="apple_team_id"' in page
        assert 'name="apple_key_id"' in page
        assert 'name="apple_private_key"' in page

    def test_form_explains_email_verification(self, super_admin_session):
        page = super_admin_session.get("/identity-providers/oidc/new").text
        assert 'id="login-email-verified"' in page
        assert 'id="login-email-code"' in page

    def test_create(self, super_admin_session, test_tenant):
        import database

        response = super_admin_session.post(
            "/identity-providers/oidc/new",
            data={
                "name": "Apple",
                "provider_type": "apple",
                "client_id": fx.CLIENT_ID,
                "apple_team_id": fx.TEAM_ID,
                "apple_key_id": fx.KEY_ID,
                "apple_private_key": fx.auth_key_pem(),
                "show_on_login": "true",
            },
            follow_redirects=False,
        )
        assert "/details?success=created" in response.headers["location"]
        row = next(
            c
            for c in database.oidc_upstream.list_connections(test_tenant["id"])
            if c["provider_type"] == "apple"
        )
        assert row["apple_team_id"] == fx.TEAM_ID
        assert row["apple_private_key_enc"]
        assert row["client_secret_enc"] is None

    def test_create_bad_key(self, super_admin_session):
        response = super_admin_session.post(
            "/identity-providers/oidc/new",
            data={
                "name": "Apple",
                "provider_type": "apple",
                "client_id": fx.CLIENT_ID,
                "apple_private_key": "not a key",
            },
            follow_redirects=False,
        )
        assert "The private key must be the .p8 file" in unquote(response.headers["location"])

    def test_create_bad_team_id(self, super_admin_session):
        response = super_admin_session.post(
            "/identity-providers/oidc/new",
            data={"name": "Apple", "provider_type": "apple", "apple_team_id": "nope"},
            follow_redirects=False,
        )
        assert "error=invalid_input" in response.headers["location"]

    def test_details_tab(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = fx.make_apple_row(test_tenant, test_super_admin_user["id"])
        page = super_admin_session.get(f"/identity-providers/oidc/{conn['id']}/details").text
        assert "Apple Signing Key" in page
        assert fx.TEAM_ID in page
        assert fx.KEY_ID in page
        assert "BEGIN PRIVATE KEY" not in page
        assert 'id="edit-apple-key-modal"' in page
        # Apple has no client secret row; trusted email, so no code step.
        assert "Client Secret</dt>" not in page
        assert 'id="login-email-verified"' in page
        assert "check the Services ID, team ID, key ID and private key with Apple" in page

    def test_details_tab_other_providers_have_no_key_card(
        self, super_admin_session, test_tenant, test_super_admin_user
    ):
        conn = fx.make_apple_row(test_tenant, test_super_admin_user["id"], name="Not Apple")
        import database

        database.execute(
            test_tenant["id"],
            "update oidc_idp_connections set provider_type = 'facebook' where id = :id",
            {"id": conn["id"]},
        )
        page = super_admin_session.get(f"/identity-providers/oidc/{conn['id']}/details").text
        assert "Apple Signing Key" not in page
        assert 'id="login-email-code"' in page

    def test_edit_key(self, super_admin_session, test_tenant, test_super_admin_user):
        import database

        conn = fx.make_apple_row(test_tenant, test_super_admin_user["id"])
        before = conn["apple_private_key_enc"]
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-apple-key",
            data={"apple_team_id": "TEAM000002", "apple_key_id": "", "apple_private_key": ""},
            follow_redirects=False,
        )
        assert response.headers["location"].endswith("/details?success=apple_key_updated")
        row = database.oidc_upstream.get_connection(test_tenant["id"], str(conn["id"]))
        assert row["apple_team_id"] == "TEAM000002"
        assert row["apple_key_id"] == fx.KEY_ID
        assert row["apple_private_key_enc"] == before
        page = super_admin_session.get(response.headers["location"]).text
        assert "Apple key settings updated." in page

    def test_edit_key_invalid_id(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = fx.make_apple_row(test_tenant, test_super_admin_user["id"])
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-apple-key",
            data={"apple_team_id": "bad"},
            follow_redirects=False,
        )
        assert "Team ID and key ID are 10 upper-case" in unquote(response.headers["location"])

    def test_edit_key_invalid_key(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = fx.make_apple_row(test_tenant, test_super_admin_user["id"])
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-apple-key",
            data={"apple_private_key": "junk"},
            follow_redirects=False,
        )
        assert "The private key must be the .p8 file" in unquote(response.headers["location"])

    def test_edit_key_not_apple(self, super_admin_session, test_tenant, test_super_admin_user):
        import database

        conn = fx.make_apple_row(test_tenant, test_super_admin_user["id"])
        database.execute(
            test_tenant["id"],
            "update oidc_idp_connections set provider_type = 'google' where id = :id",
            {"id": conn["id"]},
        )
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-apple-key",
            data={"apple_team_id": fx.TEAM_ID},
            follow_redirects=False,
        )
        assert "Apple connections only" in unquote(response.headers["location"])

    def test_edit_key_not_found(self, super_admin_session):
        response = super_admin_session.post(
            "/identity-providers/oidc/00000000-0000-0000-0000-000000000000/edit-apple-key",
            data={"apple_team_id": fx.TEAM_ID},
            follow_redirects=False,
        )
        assert response.headers["location"].endswith("/identity-providers/oidc?error=not_found")

    def test_edit_key_requires_super_admin(
        self, client, test_tenant_host, test_admin_user, override_auth, test_tenant
    ):
        conn = fx.make_apple_row(test_tenant, test_admin_user["id"])
        override_auth(test_admin_user, level="admin")
        response = client.post(
            f"/identity-providers/oidc/{conn['id']}/edit-apple-key",
            data={"apple_team_id": "TEAM000002"},
            follow_redirects=False,
        )
        assert response.status_code in (303, 403)
        assert "success=apple_key_updated" not in response.headers.get("location", "")

    def test_test_connection(self, super_admin_session, test_tenant, test_super_admin_user):
        from services.oidc_upstream.token_exchange import TokenExchangeError

        conn = fx.make_apple_row(test_tenant, test_super_admin_user["id"])
        with (
            patch("services.oidc_upstream.discovery.run_discovery", return_value=conn),
            patch("services.oidc_upstream.jwks.refresh_jwks"),
            patch(
                "services.oidc_upstream.apple.exchange_code",
                side_effect=TokenExchangeError("x", error="invalid_grant"),
            ),
        ):
            response = super_admin_session.post(
                f"/identity-providers/oidc/{conn['id']}/test-connection",
                follow_redirects=False,
            )
        assert response.headers["location"].endswith("/details?test=success")
        page = super_admin_session.get(response.headers["location"]).text
        assert "Apple accepted the client secret signed with your key." in page
