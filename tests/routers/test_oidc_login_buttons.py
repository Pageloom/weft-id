"""Tests for the sign-in page's "Continue with ..." buttons.

Covers: the buttons on the email step (shown, ordered, labelled, hidden when
none or when disabled, absent on the password step), the button entry point
recorded on login start, callback success and failure events, and the admin
"Show on Sign-In Page" setting on the create form and details tab.
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from main import app

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


def _make_connection(test_tenant, created_by, name="Test OIDC", **overrides):
    import database
    from services.oidc_upstream.connections import _encrypt_secret

    kwargs = {
        "provider_type": "generic",
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks",
        "client_id": "client-123",
        "client_secret_enc": _encrypt_secret("super-secret-value"),
        "is_enabled": True,
        "show_on_login": True,
    }
    kwargs.update(overrides)
    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=name,
        created_by=str(created_by["id"]),
        **kwargs,
    )


def _last_event(tenant_id, event_type):
    import database

    return next(
        e
        for e in database.event_log.list_events(tenant_id, limit=50)
        if e["event_type"] == event_type
    )


def _signed_id_token():
    from datetime import UTC, datetime, timedelta

    import jwt

    from tests.fixtures.oidc import load_fixture_text

    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": "https://idp.example.com",
            "aud": "client-123",
            "sub": "subject-123",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "nonce": "n-1",
            "email": "button-user@example.com",
            "email_verified": True,
            "given_name": "Button",
            "family_name": "User",
        },
        load_fixture_text("private_key.pem"),
        algorithm="RS256",
        headers={"kid": "oidc-upstream-fixture-key"},
    )


# =============================================================================
# Sign-in page
# =============================================================================


class TestLoginPageButtons:
    def test_no_buttons_when_none_shown(self, tenant_client, test_tenant, test_user):
        _make_connection(test_tenant, test_user, show_on_login=False)
        response = tenant_client.get("/login")
        assert response.status_code == 200
        assert 'id="login-buttons"' not in response.text
        assert "Continue with" not in response.text
        assert 'id="emailForm"' in response.text

    def test_buttons_above_email_form(self, tenant_client, test_tenant, test_user):
        google = _make_connection(
            test_tenant,
            test_user,
            name="Google sign-in",
            provider_type="google",
            issuer="https://accounts.google.com",
        )
        acme = _make_connection(test_tenant, test_user, name="Acme Login")

        html = tenant_client.get("/login").text

        assert html.index('id="login-buttons"') < html.index('id="emailForm"')
        # Ordered by connection name; generic carries its name, presets their brand.
        assert html.index("Continue with Acme Login") < html.index("Continue with Google")
        assert f'href="/auth/oidc/{google["id"]}/login?via=login_button"' in html
        assert f'href="/auth/oidc/{acme["id"]}/login?via=login_button"' in html
        assert "#4285F4" in html  # the Google logo

    def test_disabled_connection_has_no_button(self, tenant_client, test_tenant, test_user):
        _make_connection(test_tenant, test_user, is_enabled=False)
        assert "Continue with" not in tenant_client.get("/login").text

    def test_no_buttons_on_password_step(self, tenant_client, test_tenant, test_user):
        _make_connection(test_tenant, test_user)
        html = tenant_client.get("/login?prefill_email=a%40example.com&show_password=true").text
        assert "Continue with" not in html
        assert 'id="loginForm"' in html


# =============================================================================
# Entry point on the login and callback audit events
# =============================================================================


class TestButtonEntry:
    def _start(self, tenant_client, conn, query=""):
        session: dict = {}
        with patch(
            "starlette.requests.Request.session",
            new_callable=lambda: property(lambda self: session),
        ):
            response = tenant_client.get(
                f"/auth/oidc/{conn['id']}/login{query}", follow_redirects=False
            )
        assert response.status_code == 303
        assert response.headers["location"].startswith("https://idp.example.com/authorize?")
        return session

    @staticmethod
    def _stored_entry(session, conn):
        from services.oidc_upstream.login_state import load_login_state

        login_state = load_login_state(session[f"oidc_auth:{conn['id']}:state"])
        assert login_state is not None
        assert set(session) == {f"oidc_auth:{conn['id']}:state"}
        return login_state.entry

    def test_button_start_is_recorded(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        session = self._start(tenant_client, conn, "?via=login_button")
        assert self._stored_entry(session, conn) == "login_button"
        event = _last_event(test_tenant["id"], "oidc_login_started")
        assert event["metadata"]["entry"] == "login_button"

    def test_plain_start_is_routed(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        session = self._start(tenant_client, conn)
        assert self._stored_entry(session, conn) == "routed"
        assert _last_event(test_tenant["id"], "oidc_login_started")["metadata"]["entry"] == (
            "routed"
        )

    def test_button_param_ignored_for_connection_not_on_login_page(
        self, tenant_client, test_tenant, test_user
    ):
        conn = _make_connection(test_tenant, test_user, show_on_login=False)
        session = self._start(tenant_client, conn, "?via=login_button")
        assert self._stored_entry(session, conn) == "routed"

    def test_button_start_is_rate_limited(self, tenant_client, test_tenant, test_user):
        from services.exceptions import RateLimitError

        conn = _make_connection(test_tenant, test_user)
        with patch(
            "routers.oidc_upstream.authentication.ratelimit.prevent",
            side_effect=RateLimitError(message="slow down", code="rate_limited"),
        ):
            response = tenant_client.get(
                f"/auth/oidc/{conn['id']}/login?via=login_button", follow_redirects=False
            )
        assert response.headers["location"].endswith("/login?error=too_many_requests")

    def _callback(self, tenant_client, conn, entry, query="state=state-1&code=code-1"):
        from tests.fixtures.oidc import load_fixture

        session = login_session(conn, entry=entry or "routed")
        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: session),
            ),
            patch(
                "services.oidc_upstream.exchange_code",
                return_value={"access_token": "at", "id_token": _signed_id_token()},
            ),
            patch("services.oidc_upstream.jwks._fetch_jwks", return_value=load_fixture("jwks")),
        ):
            response = tenant_client.get(
                f"/auth/oidc/{conn['id']}/callback?{query}", follow_redirects=False
            )
        assert f"oidc_auth:{conn['id']}:state" not in session
        return response

    def test_button_sign_in_jit_success(self, tenant_client, test_tenant, test_user):
        import database

        conn = _make_connection(test_tenant, test_user, jit_provisioning=True)
        response = self._callback(tenant_client, conn, "login_button")

        assert response.status_code == 303
        user_id = database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "subject-123"
        )
        assert user_id is not None
        event = _last_event(test_tenant["id"], "oidc_user_jit_provisioned")
        assert str(event["artifact_id"]) == str(user_id)
        assert event["metadata"]["entry"] == "login_button"

    def test_button_sign_in_failure(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)  # no JIT, unknown user
        response = self._callback(tenant_client, conn, "login_button")
        assert response.headers["location"].endswith("/login?error=oidc_user_not_found")
        event = _last_event(test_tenant["id"], "oidc_login_failed")
        assert event["metadata"]["reason"] == "user_not_found"
        assert event["metadata"]["entry"] == "login_button"

    def test_callback_without_entry_is_routed(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        self._callback(tenant_client, conn, None, query="state=state-1&error=access_denied")
        event = _last_event(test_tenant["id"], "oidc_login_failed")
        assert event["metadata"]["entry"] == "routed"

    def test_unknown_entry_value_is_routed(self, tenant_client, test_tenant, test_user):
        conn = _make_connection(test_tenant, test_user)
        self._callback(tenant_client, conn, "forged", query="state=state-1&error=access_denied")
        assert _last_event(test_tenant["id"], "oidc_login_failed")["metadata"]["entry"] == "routed"


# =============================================================================
# Admin setting
# =============================================================================


class TestAdminSetting:
    def test_new_form_offers_the_setting(self, super_admin_session, test_tenant_host):
        html = super_admin_session.get(
            "/identity-providers/oidc/new", headers={"Host": test_tenant_host}
        ).text
        assert 'name="show_on_login"' in html

    def test_create_with_setting(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
    ):
        import database

        response = super_admin_session.post(
            "/identity-providers/oidc/new",
            data={
                "name": "Google",
                "provider_type": "google",
                "client_id": "client-123",
                "client_secret": "super-secret-value",
                "show_on_login": "on",
            },
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )
        assert "success=created" in response.headers["location"]
        [row] = database.oidc_upstream.list_connections(test_tenant["id"])
        assert row["show_on_login"] is True

    def test_settings_turn_button_on_and_off(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
    ):
        import database

        conn = _make_connection(test_tenant, test_super_admin_user, show_on_login=False)
        url = f"/identity-providers/oidc/{conn['id']}/edit-settings"
        super_admin_session.post(
            url,
            data={"is_enabled": "on", "show_on_login": "on"},
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )
        row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
        assert row["show_on_login"] is True
        event = _last_event(test_tenant["id"], "oidc_idp_connection_updated")
        assert "show_on_login" in event["metadata"]["updated_fields"]

        super_admin_session.post(
            url,
            data={"is_enabled": "on"},
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )
        row = database.oidc_upstream.get_connection(test_tenant["id"], conn["id"])
        assert row["show_on_login"] is False

    def test_details_tab_shows_setting(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
    ):
        conn = _make_connection(test_tenant, test_super_admin_user)
        html = super_admin_session.get(
            f"/identity-providers/oidc/{conn['id']}/details", headers={"Host": test_tenant_host}
        ).text
        assert 'id="show_on_login"' in html
        assert "The provider is disabled, so the button is not shown." not in html

    def test_details_tab_warns_when_shown_but_disabled(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
    ):
        conn = _make_connection(test_tenant, test_super_admin_user, is_enabled=False)
        html = super_admin_session.get(
            f"/identity-providers/oidc/{conn['id']}/details", headers={"Host": test_tenant_host}
        ).text
        assert "The provider is disabled, so the button is not shown." in html
