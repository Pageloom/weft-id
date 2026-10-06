"""Route tests for Discord and Facebook connections.

Sign-in: the login redirect to each provider and the callback end to end
against the API fixtures. Admin: the create form, the details tab and Test
Connection. API: create and test. The email confirmation that follows a
Facebook JIT sign-in is covered in test_oidc_email_confirmation.py.
"""

import os
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from main import app

from tests.fixtures.discord import TOKEN_PATH as DISCORD_TOKEN_PATH
from tests.fixtures.discord import USERS_ME_PATH, discord_api
from tests.fixtures.facebook import ME_PATH, facebook_api
from tests.fixtures.facebook import TOKEN_PATH as FACEBOOK_TOKEN_PATH
from tests.fixtures.oidc_login import login_session
from tests.helpers.client import TestClient

PROVIDERS = {
    "discord": {
        "issuer": "https://discord.com",
        "scopes": "identify email",
        "authorize": "https://discord.com/oauth2/authorize",
        "api": discord_api,
        "sub": "80351110224678912",
        "email": "nelly@example.com",
    },
    "facebook": {
        "issuer": "https://www.facebook.com",
        "scopes": "public_profile email",
        "authorize": "https://www.facebook.com/v25.0/dialog/oauth",
        "api": facebook_api,
        "sub": "10158000000000001",
        "email": "ada@example.com",
    },
}


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


@pytest.fixture
def api_headers(test_tenant_host, test_tenant, normal_oauth2_client, test_super_admin_user):
    import database

    _, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
    )
    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
        parent_token_id=refresh_token_id,
    )
    return {"Host": test_tenant_host, "Authorization": f"Bearer {access_token}"}


def _make(test_tenant, created_by, provider_type, **overrides):
    import database
    from services.oidc_upstream.connections import _encrypt_secret

    kwargs = {
        "provider_type": provider_type,
        "issuer": PROVIDERS[provider_type]["issuer"],
        "client_id": "client-1",
        "client_secret_enc": _encrypt_secret("secret-1"),
        "scopes": PROVIDERS[provider_type]["scopes"],
        "is_enabled": True,
        "show_on_login": True,
    }
    kwargs.update(overrides)
    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=provider_type.title(),
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


def _callback(tenant_client, conn, overrides=None):
    session = login_session(conn, entry="login_button")
    api = PROVIDERS[conn["provider_type"]]["api"]
    with (
        patch(
            "starlette.requests.Request.session",
            new_callable=lambda: property(lambda self: session),
        ),
        patch("routers.oidc_upstream.authentication.send_email_possession_code"),
        api(overrides) as requests,
    ):
        response = tenant_client.get(
            f"/auth/oidc/{conn['id']}/callback?state=state-1&code=code-1",
            follow_redirects=False,
        )
    return response, requests, session


class TestSignIn:
    @pytest.mark.parametrize("provider_type", ["discord", "facebook"])
    def test_login_redirects_to_provider(
        self, tenant_client, test_tenant, test_user, provider_type
    ):
        conn = _make(test_tenant, test_user, provider_type)
        session: dict = {}
        with patch(
            "starlette.requests.Request.session",
            new_callable=lambda: property(lambda self: session),
        ):
            response = tenant_client.get(
                f"/auth/oidc/{conn['id']}/login?via=login_button", follow_redirects=False
            )

        assert response.status_code == 303
        location = urlparse(response.headers["location"])
        assert (
            f"{location.scheme}://{location.netloc}{location.path}"
            == (PROVIDERS[provider_type]["authorize"])
        )
        params = parse_qs(location.query)
        assert params["client_id"] == ["client-1"]
        assert params["scope"] == [PROVIDERS[provider_type]["scopes"]]
        assert params["response_type"] == ["code"]
        assert params["state"] == [session[f"oidc_auth:{conn['id']}:state"]]
        assert params["code_challenge_method"] == ["S256"]
        assert "nonce" not in params

    def test_discord_callback_jit_completes(self, tenant_client, test_tenant, test_user):
        import database

        conn = _make(test_tenant, test_user, "discord", jit_provisioning=True)
        response, requests, session = _callback(tenant_client, conn)

        assert response.status_code == 303
        location = response.headers["location"]
        assert "/login?error" not in location
        # Discord vouches for the address: no confirmation step.
        assert "confirm-email" not in location
        user_id = database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "80351110224678912"
        )
        primary = database.user_emails.get_primary_email_for_resend(test_tenant["id"], user_id)
        assert primary["verified_at"] is not None
        assert [r.url.path for r in requests] == [DISCORD_TOKEN_PATH, USERS_ME_PATH]

    def test_discord_unverified_email_cannot_jit(self, tenant_client, test_tenant, test_user):
        from tests.fixtures.discord import load

        conn = _make(test_tenant, test_user, "discord", jit_provisioning=True)
        user = {**load("users_me"), "verified": False}
        response, _, _ = _callback(tenant_client, conn, {USERS_ME_PATH: user})

        assert response.headers["location"].endswith("/login?error=auth_failed")
        event = _last_event(test_tenant["id"], "oidc_login_failed")
        assert event["metadata"]["reason"] == "auth_failed"

    def test_facebook_callback_jit_asks_for_confirmation(
        self, tenant_client, test_tenant, test_user
    ):
        import database

        conn = _make(test_tenant, test_user, "facebook", jit_provisioning=True)
        response, requests, session = _callback(tenant_client, conn)

        assert response.status_code == 303
        assert response.headers["location"] == "/auth/oidc/confirm-email"
        user_id = database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "10158000000000001"
        )
        assert session["pending_oidc_email_confirmation"]["user_id"] == user_id
        assert [r.url.path for r in requests] == [FACEBOOK_TOKEN_PATH, ME_PATH]

    @pytest.mark.parametrize(
        ("provider_type", "path", "reason"),
        [("discord", USERS_ME_PATH, "discord_api"), ("facebook", ME_PATH, "facebook_api")],
    )
    def test_api_failure(self, tenant_client, test_tenant, test_user, provider_type, path, reason):
        conn = _make(test_tenant, test_user, provider_type, jit_provisioning=True)
        response, _, _ = _callback(tenant_client, conn, {path: httpx.Response(500)})

        assert response.headers["location"].endswith("/login?error=auth_failed")
        event = _last_event(test_tenant["id"], "oidc_login_failed")
        assert event["metadata"]["reason"] == reason
        assert event["metadata"]["entry"] == "login_button"

    @pytest.mark.parametrize(
        ("provider_type", "label", "colour"),
        [("discord", "Discord", "#5865F2"), ("facebook", "Facebook", "#0866FF")],
    )
    def test_login_button(
        self, tenant_client, test_tenant, test_user, provider_type, label, colour
    ):
        _make(test_tenant, test_user, provider_type)
        html = tenant_client.get("/login").text
        assert f"Continue with {label}" in html
        assert f'fill="{colour}"' in html


class TestAdmin:
    def test_form_offers_both(self, super_admin_session):
        html = super_admin_session.get("/identity-providers/oidc/new").text
        assert '<option value="discord">Discord</option>' in html
        assert '<option value="facebook">Facebook</option>' in html
        assert 'id="jit-email-confirmation"' in html

    @pytest.mark.parametrize("provider_type", ["discord", "facebook"])
    def test_create_from_form(self, super_admin_session, test_tenant, provider_type):
        import database

        response = super_admin_session.post(
            "/identity-providers/oidc/new",
            data={
                "name": f"{provider_type} sign-in",
                "provider_type": provider_type,
                # The form submits the hidden preset values.
                "issuer": PROVIDERS[provider_type]["issuer"],
                "correlation_claim": "sub",
                "scopes": PROVIDERS[provider_type]["scopes"],
                "client_id": "client-1",
                "client_secret": "secret",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "success=created" in response.headers["location"]
        row = next(
            r
            for r in database.oidc_upstream.list_connections(test_tenant["id"])
            if r["name"] == f"{provider_type} sign-in"
        )
        assert row["provider_type"] == provider_type
        assert row["discovery_url"] is None

    def test_facebook_details_tab(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = _make(test_tenant, test_super_admin_user, "facebook")
        html = super_admin_session.get(f"/identity-providers/oidc/{conn['id']}/details").text

        assert "Check the client ID and client secret with Facebook." in html
        assert "Not available for Facebook" in html
        assert 'id="jit-email-confirmation"' in html
        assert "JWKS URI" not in html

    def test_discord_details_tab(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = _make(test_tenant, test_super_admin_user, "discord")
        html = super_admin_session.get(f"/identity-providers/oidc/{conn['id']}/details").text

        assert "Check the client ID and client secret with Discord." in html
        assert 'id="email-linking-unsupported"' not in html
        assert 'id="jit-email-confirmation"' not in html
        assert "Allowed Organizations" not in html

    @pytest.mark.parametrize(
        ("provider_type", "path", "response", "ok"),
        [
            (
                "discord",
                DISCORD_TOKEN_PATH,
                httpx.Response(400, json={"error": "invalid_grant"}),
                True,
            ),
            (
                "discord",
                DISCORD_TOKEN_PATH,
                httpx.Response(401, json={"error": "invalid_client"}),
                False,
            ),
            ("facebook", FACEBOOK_TOKEN_PATH, {"access_token": "a", "token_type": "bearer"}, True),
            ("facebook", FACEBOOK_TOKEN_PATH, httpx.Response(400, json={"error": {}}), False),
        ],
    )
    def test_test_connection(
        self,
        super_admin_session,
        test_tenant,
        test_super_admin_user,
        provider_type,
        path,
        response,
        ok,
    ):
        conn = _make(test_tenant, test_super_admin_user, provider_type)
        with PROVIDERS[provider_type]["api"]({path: response}):
            result = super_admin_session.post(
                f"/identity-providers/oidc/{conn['id']}/test-connection", follow_redirects=False
            )
        assert result.status_code == 303
        location = result.headers["location"]
        assert ("error" not in location) is ok


class TestAPI:
    URL = "/api/v1/oidc-upstream/connections"

    @pytest.mark.parametrize(("provider_type", "trusted"), [("discord", True), ("facebook", False)])
    def test_create(self, client, api_headers, provider_type, trusted):
        response = client.post(
            self.URL,
            headers=api_headers,
            json={
                "name": provider_type,
                "provider_type": provider_type,
                "client_id": "client-1",
                "client_secret": "secret",
                "jit_provisioning": True,
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["issuer"] == PROVIDERS[provider_type]["issuer"]
        assert body["uses_discovery"] is False
        assert body["email_linking_trusted"] is trusted

    def test_facebook_email_linking_rejected(self, client, api_headers):
        response = client.post(
            self.URL,
            headers=api_headers,
            json={"name": "Facebook", "provider_type": "facebook", "allow_email_linking": True},
        )
        assert response.status_code == 400

    def test_discord_rejects_discovery_url(self, client, api_headers):
        response = client.post(
            self.URL,
            headers=api_headers,
            json={
                "name": "Discord",
                "provider_type": "discord",
                "discovery_url": "https://discord.com/.well-known/openid-configuration",
            },
        )
        assert response.status_code == 400

    def test_test_endpoint(self, client, api_headers):
        created = client.post(
            self.URL,
            headers=api_headers,
            json={
                "name": "Facebook",
                "provider_type": "facebook",
                "client_id": "client-1",
                "client_secret": "secret",
            },
        ).json()
        with facebook_api({FACEBOOK_TOKEN_PATH: {"access_token": "a", "token_type": "bearer"}}):
            ok = client.post(f"{self.URL}/{created['id']}/test", headers=api_headers)
        assert ok.status_code == 200

        with facebook_api({FACEBOOK_TOKEN_PATH: httpx.Response(400, json={"error": {}})}):
            bad = client.post(f"{self.URL}/{created['id']}/test", headers=api_headers)
        assert bad.status_code == 400
        assert "rejected the app ID or app secret" in bad.text
