"""Route tests for GitHub connections.

Sign-in: the login redirect to GitHub, and the callback end to end against
the GitHub API fixtures (JIT, allowed-organization refusal, API failure).
Admin: the create form, the details tab, the allowed-organizations edit,
Test Connection and the list. API: create, patch and test.
"""

import os
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlparse

import pytest
from main import app

from tests.fixtures.github import github_api
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


class _ApiClient:
    """The test client with a super admin's bearer token on every call."""

    def __init__(self, client, headers):
        self._client = client
        self._headers = headers

    def __getattr__(self, method):
        call = getattr(self._client, method)
        return lambda url, **kwargs: call(url, headers=self._headers, **kwargs)


@pytest.fixture
def api_client_super_admin(
    client, test_tenant_host, test_tenant, normal_oauth2_client, test_super_admin_user
):
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
    return _ApiClient(client, {"Host": test_tenant_host, "Authorization": f"Bearer {access_token}"})


def _make_github(test_tenant, created_by, name="GitHub", **overrides):
    import database
    from services.oidc_upstream.connections import _encrypt_secret

    kwargs = {
        "provider_type": "github",
        "issuer": "https://github.com",
        "client_id": "Iv1.client",
        "client_secret_enc": _encrypt_secret("gh-secret"),
        "scopes": "read:user user:email read:org",
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


# =============================================================================
# Sign-in
# =============================================================================


class TestSignIn:
    def test_login_redirects_to_github(self, tenant_client, test_tenant, test_user):
        conn = _make_github(test_tenant, test_user)
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
        assert f"{location.scheme}://{location.netloc}{location.path}" == (
            "https://github.com/login/oauth/authorize"
        )
        params = parse_qs(location.query)
        assert params["client_id"] == ["Iv1.client"]
        assert params["scope"] == ["read:user user:email read:org"]
        assert params["state"] == [session[f"oidc_auth:{conn['id']}:state"]]
        assert params["redirect_uri"][0].endswith(f"/auth/oidc/{conn['id']}/callback")
        assert params["code_challenge_method"] == ["S256"]
        assert _last_event(test_tenant["id"], "oidc_login_started")["metadata"]["entry"] == (
            "login_button"
        )

    def _callback(self, tenant_client, conn, overrides=None):
        session = {
            f"oidc_auth:{conn['id']}:state": "state-1",
            f"oidc_auth:{conn['id']}:nonce": "n-1",
            f"oidc_auth:{conn['id']}:code_verifier": "verifier-1",
            f"oidc_auth:{conn['id']}:entry": "login_button",
        }
        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: session),
            ),
            github_api(overrides) as requests,
        ):
            response = tenant_client.get(
                f"/auth/oidc/{conn['id']}/callback?state=state-1&code=code-1",
                follow_redirects=False,
            )
        return response, requests, session

    def test_callback_jit(self, tenant_client, test_tenant, test_user):
        import database

        conn = _make_github(test_tenant, test_user, jit_provisioning=True)
        response, requests, session = self._callback(tenant_client, conn)

        assert response.status_code == 303
        assert "/login?error" not in response.headers["location"]
        user_id = database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "583231"
        )
        assert user_id is not None
        event = _last_event(test_tenant["id"], "oidc_user_jit_provisioned")
        assert event["metadata"]["email"] == "octocat@example.com"
        assert event["metadata"]["entry"] == "login_button"
        # No ID token, so nothing stashed for upstream logout.
        assert not any(key.startswith("upstream_oidc") for key in session)

    def test_callback_org_not_allowed(self, tenant_client, test_tenant, test_user):
        conn = _make_github(
            test_tenant, test_user, jit_provisioning=True, github_allowed_orgs=["globex"]
        )
        response, _, _ = self._callback(tenant_client, conn)

        assert response.headers["location"].endswith("/login?error=github_org_not_allowed")
        event = _last_event(test_tenant["id"], "oidc_login_failed")
        assert event["metadata"]["reason"] == "github_org_not_allowed"
        assert event["metadata"]["entry"] == "login_button"
        assert "octocat" in event["metadata"]["detail"]

    def test_callback_api_failure(self, tenant_client, test_tenant, test_user):
        import httpx

        conn = _make_github(test_tenant, test_user, jit_provisioning=True)
        response, _, _ = self._callback(
            tenant_client, conn, {"/user": httpx.Response(401, json={})}
        )
        assert response.headers["location"].endswith("/login?error=auth_failed")
        assert _last_event(test_tenant["id"], "oidc_login_failed")["metadata"]["reason"] == (
            "github_api"
        )

    def test_login_page_message(self, tenant_client):
        response = tenant_client.get("/login?error=github_org_not_allowed")
        assert "not a member of an organization that can sign in here" in response.text

    def test_login_button(self, tenant_client, test_tenant, test_user):
        _make_github(test_tenant, test_user)
        html = tenant_client.get("/login").text
        assert "Continue with GitHub" in html
        assert 'fill="currentColor" d="M12 .297' in html


# =============================================================================
# Admin
# =============================================================================


class TestAdmin:
    def test_form_offers_github(self, super_admin_session):
        html = super_admin_session.get("/identity-providers/oidc/new").text
        assert '<option value="github">GitHub</option>' in html
        assert 'id="github-orgs-field"' in html
        assert '"uses_discovery": false' in html

    def test_create_from_form(self, super_admin_session, test_tenant):
        import database

        response = super_admin_session.post(
            "/identity-providers/oidc/new",
            data={
                "name": "GitHub Sign-In",
                "provider_type": "github",
                # The form submits the hidden preset values.
                "issuer": "https://github.com",
                "correlation_claim": "sub",
                "scopes": "read:user user:email read:org",
                "client_id": "Iv1.client",
                "client_secret": "secret",
                "github_allowed_orgs": "Acme, globex\ninitech",
            },
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "success=created" in response.headers["location"]
        row = next(
            r
            for r in database.oidc_upstream.list_connections(test_tenant["id"])
            if r["name"] == "GitHub Sign-In"
        )
        assert row["provider_type"] == "github"
        assert row["github_allowed_orgs"] == ["acme", "globex", "initech"]

    def test_create_with_blank_orgs(self, super_admin_session, test_tenant):
        import database

        super_admin_session.post(
            "/identity-providers/oidc/new",
            data={"name": "GitHub Open", "provider_type": "github", "github_allowed_orgs": " "},
            follow_redirects=False,
        )
        row = next(
            r
            for r in database.oidc_upstream.list_connections(test_tenant["id"])
            if r["name"] == "GitHub Open"
        )
        assert row["github_allowed_orgs"] is None

    def test_create_with_bad_org_name(self, super_admin_session):
        response = super_admin_session.post(
            "/identity-providers/oidc/new",
            data={
                "name": "GitHub",
                "provider_type": "github",
                "github_allowed_orgs": "acme, -bad",
            },
            follow_redirects=False,
        )
        assert response.headers["location"].endswith("/new?error=invalid_input")

    def test_details_tab(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = _make_github(test_tenant, test_super_admin_user, github_allowed_orgs=["acme"])
        html = super_admin_session.get(f"/identity-providers/oidc/{conn['id']}/details").text

        assert "Allowed Organizations" in html
        assert ">acme</li>" in html
        assert 'id="edit-orgs-modal"' in html
        assert "Check the client ID, client secret and callback URL with GitHub." in html
        # Discovery-only parts are hidden.
        assert "Back-Channel Logout URL" not in html
        assert "Post-Logout Redirect URI" not in html
        assert "JWKS URI" not in html
        assert "Correlation Claim" not in html
        assert 'id="sign_out_at_idp"' not in html
        assert "Callback URL" in html

    def test_details_tab_any_account(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = _make_github(test_tenant, test_super_admin_user)
        html = super_admin_session.get(f"/identity-providers/oidc/{conn['id']}/details").text
        assert "Any GitHub account" in html

    def test_details_tab_oidc_unchanged(
        self, super_admin_session, test_tenant, test_super_admin_user
    ):
        conn = _make_github(
            test_tenant,
            test_super_admin_user,
            provider_type="google",
            issuer="https://accounts.google.com",
        )
        html = super_admin_session.get(f"/identity-providers/oidc/{conn['id']}/details").text
        assert "Back-Channel Logout URL" in html
        assert "Correlation Claim" in html
        assert "Allowed Organizations" not in html

    def test_claim_mapping_hint(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = _make_github(test_tenant, test_super_admin_user)
        html = super_admin_session.get(f"/identity-providers/oidc/{conn['id']}/claim-mapping").text
        assert "to sync the user's GitHub organizations" in html

    def test_edit_orgs(self, super_admin_session, test_tenant, test_super_admin_user):
        import database

        conn = _make_github(test_tenant, test_super_admin_user)
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-github-orgs",
            data={"github_allowed_orgs": "Acme\nGlobex"},
            follow_redirects=False,
        )
        assert response.headers["location"].endswith("/details?success=orgs_updated")
        row = database.oidc_upstream.get_connection(test_tenant["id"], str(conn["id"]))
        assert row["github_allowed_orgs"] == ["acme", "globex"]

        page = super_admin_session.get(response.headers["location"]).text
        assert "Allowed organizations updated." in page

        super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-github-orgs",
            data={"github_allowed_orgs": ""},
            follow_redirects=False,
        )
        row = database.oidc_upstream.get_connection(test_tenant["id"], str(conn["id"]))
        assert row["github_allowed_orgs"] is None

    def test_edit_orgs_invalid(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = _make_github(test_tenant, test_super_admin_user)
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-github-orgs",
            data={"github_allowed_orgs": "acme bad_name"},
            follow_redirects=False,
        )
        location = unquote(response.headers["location"])
        assert "/details?error=Organization names may hold only" in location

    def test_edit_orgs_not_github(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = _make_github(
            test_tenant,
            test_super_admin_user,
            provider_type="google",
            issuer="https://accounts.google.com",
        )
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-github-orgs",
            data={"github_allowed_orgs": "acme"},
            follow_redirects=False,
        )
        assert "GitHub connections only" in unquote(response.headers["location"])

    def test_edit_orgs_not_found(self, super_admin_session):
        response = super_admin_session.post(
            "/identity-providers/oidc/00000000-0000-0000-0000-000000000000/edit-github-orgs",
            data={"github_allowed_orgs": "acme"},
            follow_redirects=False,
        )
        assert response.headers["location"].endswith("/identity-providers/oidc?error=not_found")

    def test_edit_orgs_requires_super_admin(
        self, client, test_tenant_host, test_admin_user, override_auth, test_tenant
    ):
        conn = _make_github(test_tenant, test_admin_user)
        override_auth(test_admin_user, level="admin")
        response = client.post(
            f"/identity-providers/oidc/{conn['id']}/edit-github-orgs",
            data={"github_allowed_orgs": "acme"},
            follow_redirects=False,
        )
        assert response.status_code in (303, 403)
        assert "success=orgs_updated" not in response.headers.get("location", "")

    def test_test_connection(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = _make_github(test_tenant, test_super_admin_user)
        with github_api({"/login/oauth/access_token": {"error": "bad_verification_code"}}):
            response = super_admin_session.post(
                f"/identity-providers/oidc/{conn['id']}/test-connection",
                follow_redirects=False,
            )
        assert response.headers["location"].endswith("/details?test=success")
        page = super_admin_session.get(response.headers["location"]).text
        assert "GitHub accepted the client credentials." in page

    def test_test_connection_failure(self, super_admin_session, test_tenant, test_super_admin_user):
        conn = _make_github(test_tenant, test_super_admin_user)
        with github_api({"/login/oauth/access_token": {"error": "incorrect_client_credentials"}}):
            response = super_admin_session.post(
                f"/identity-providers/oidc/{conn['id']}/test-connection",
                follow_redirects=False,
            )
        location = unquote(response.headers["location"])
        assert "test=error" in location
        assert "GitHub rejected the client ID or client secret." in location

    def test_list_shows_not_applicable(
        self, super_admin_session, test_tenant, test_super_admin_user
    ):
        _make_github(test_tenant, test_super_admin_user)
        html = super_admin_session.get("/identity-providers/oidc").text
        assert "Not applicable" in html


# =============================================================================
# API
# =============================================================================


class TestAPI:
    URL = "/api/v1/oidc-upstream/connections"

    def test_create(self, api_client_super_admin):
        response = api_client_super_admin.post(
            self.URL,
            json={
                "name": "GitHub",
                "provider_type": "github",
                "client_id": "Iv1.client",
                "client_secret": "secret",
                "github_allowed_orgs": ["Acme"],
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["provider_label"] == "GitHub"
        assert body["issuer"] == "https://github.com"
        assert body["uses_discovery"] is False
        assert body["github_allowed_orgs"] == ["acme"]
        assert body["email_linking_trusted"] is True

        listed = api_client_super_admin.get(self.URL).json()["items"]
        assert [(i["provider_type"], i["uses_discovery"]) for i in listed] == [("github", False)]

    @pytest.mark.parametrize("orgs", [["-acme"], ["a" * 40], ["acme_corp"], ["acme"] * 101])
    def test_create_invalid_orgs(self, api_client_super_admin, orgs):
        response = api_client_super_admin.post(
            self.URL,
            json={"name": "GitHub", "provider_type": "github", "github_allowed_orgs": orgs},
        )
        assert response.status_code == 422

    def test_create_rejects_discovery_url(self, api_client_super_admin):
        response = api_client_super_admin.post(
            self.URL,
            json={
                "name": "GitHub",
                "provider_type": "github",
                "discovery_url": "https://github.com/.well-known/openid-configuration",
            },
        )
        assert response.status_code == 400

    def test_orgs_on_other_type(self, api_client_super_admin):
        response = api_client_super_admin.post(
            self.URL,
            json={"name": "Google", "provider_type": "google", "github_allowed_orgs": ["acme"]},
        )
        assert response.status_code == 400

    def test_patch_orgs(self, api_client_super_admin):
        created = api_client_super_admin.post(
            self.URL, json={"name": "GitHub", "provider_type": "github"}
        ).json()
        response = api_client_super_admin.patch(
            f"{self.URL}/{created['id']}", json={"github_allowed_orgs": ["Globex"]}
        )
        assert response.status_code == 200
        assert response.json()["github_allowed_orgs"] == ["globex"]

        response = api_client_super_admin.patch(
            f"{self.URL}/{created['id']}", json={"github_allowed_orgs": []}
        )
        assert response.json()["github_allowed_orgs"] == []

    def test_test_endpoint(self, api_client_super_admin):
        created = api_client_super_admin.post(
            self.URL,
            json={
                "name": "GitHub",
                "provider_type": "github",
                "client_id": "Iv1.client",
                "client_secret": "secret",
            },
        ).json()
        with github_api({"/login/oauth/access_token": {"error": "bad_verification_code"}}):
            ok = api_client_super_admin.post(f"{self.URL}/{created['id']}/test")
        assert ok.status_code == 200

        with github_api({"/login/oauth/access_token": {"error": "redirect_uri_mismatch"}}):
            bad = api_client_super_admin.post(f"{self.URL}/{created['id']}/test")
        assert bad.status_code == 400
        assert "callback URL" in bad.text
