"""Post-login resume of a pending OAuth2/OIDC authorization request.

An unauthenticated GET /oauth2/authorize stashes its own URL in the session and
bounces to /login. Login completion must carry that stash across session
regeneration and honour it (only a safe rooted /oauth2/authorize path), so the
relying party's authorization request resumes instead of ending on /dashboard.
The forward-auth stash shares the mechanism and is covered here too, since it
was previously lost when the session was regenerated.
"""

from fastapi.testclient import TestClient
from main import app
from routers.saml_idp._helpers import (
    PENDING_FORWARD_AUTH_KEY,
    PENDING_OAUTH2_AUTHORIZE_KEY,
    extract_pending_returns,
    get_post_auth_redirect,
)

AUTHORIZE = "/oauth2/authorize?client_id=abc&redirect_uri=https%3A%2F%2Frp.example%2Fcb&state=s1"


class TestGetPostAuthRedirect:
    def test_pending_oauth2_authorize_honored_and_consumed(self):
        session = {PENDING_OAUTH2_AUTHORIZE_KEY: AUTHORIZE}
        assert get_post_auth_redirect(session) == AUTHORIZE
        assert PENDING_OAUTH2_AUTHORIZE_KEY not in session

    def test_pending_sso_takes_priority_over_oauth2(self):
        session = {
            "pending_sso_sp_entity_id": "sp1",
            PENDING_OAUTH2_AUTHORIZE_KEY: AUTHORIZE,
        }
        assert get_post_auth_redirect(session) == "/saml/idp/consent"

    def test_forward_auth_takes_priority_over_oauth2(self):
        session = {
            PENDING_FORWARD_AUTH_KEY: "/forward-auth/authorize?domain=a",
            PENDING_OAUTH2_AUTHORIZE_KEY: AUTHORIZE,
        }
        assert get_post_auth_redirect(session) == "/forward-auth/authorize?domain=a"

    def test_unsafe_oauth2_values_ignored_and_consumed(self):
        for bad in (
            "https://evil.example/oauth2/authorize",
            "//evil.example/oauth2/authorize",
            "/dashboard",
            "/oauth2/authorize\nLocation: https://evil",
            "/oauth2/authorize\rhttps://evil",
            "/oauth2/authorize?next=http://x",  # scheme inside the query
            42,
        ):
            session = {PENDING_OAUTH2_AUTHORIZE_KEY: bad}
            assert get_post_auth_redirect(session) == "/dashboard", bad
            # Never replayed on a later login, valid or not.
            assert PENDING_OAUTH2_AUTHORIZE_KEY not in session


class TestExtractPendingReturns:
    def test_returns_only_present_string_keys(self):
        session = {
            PENDING_OAUTH2_AUTHORIZE_KEY: AUTHORIZE,
            PENDING_FORWARD_AUTH_KEY: "",
            "user_id": "u1",
        }
        assert extract_pending_returns(session) == {PENDING_OAUTH2_AUTHORIZE_KEY: AUTHORIZE}

    def test_empty_when_nothing_pending(self):
        assert extract_pending_returns({"user_id": "u1"}) == {}


class TestLoginCompletionCarriesPendingAuthorize:
    """Drive /mfa/verify with a real session dict so regeneration runs for real."""

    def _complete_login(self, test_tenant, mocker, session_data: dict) -> str:
        from dependencies import get_tenant_id_from_request

        app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]
        mocker.patch(
            "starlette.requests.Request.session",
            new_callable=lambda: property(lambda self: session_data),
        )
        mocker.patch("routers.mfa.ratelimit.prevent")
        mocker.patch("routers.mfa.get_totp_secret", return_value="secret")
        mocker.patch("routers.mfa.verify_totp_code", return_value=True)
        mocker.patch("services.event_log.log_event")
        mocker.patch("routers.auth._login_completion.log_event")
        mocker.patch(
            "routers.auth._login_completion.settings_service.get_session_settings",
            return_value=None,
        )
        user = {"id": "test-user-id", "tz": None, "locale": None, "mfa_method": "totp"}
        mocker.patch("routers.mfa.users_service.get_user_by_id_raw", return_value=user)
        mocker.patch(
            "routers.auth._login_completion.users_service.get_user_by_id_raw", return_value=user
        )
        mocker.patch("routers.auth._login_completion.users_service.update_last_login")
        mocker.patch("routers.mfa.users_service.user_must_enroll_enhanced", return_value=False)
        try:
            response = TestClient(app).post(
                "/mfa/verify", data={"code": "123456"}, follow_redirects=False
            )
        finally:
            app.dependency_overrides.clear()
        assert response.status_code == 303
        return response.headers["location"]

    def test_oauth2_authorize_resumes_after_real_session_regeneration(self, test_tenant, mocker):
        session_data: dict = {
            "pending_mfa_user_id": "test-user-id",
            "pending_mfa_method": "totp",
            "csrf_token": "pre-auth-garbage",
            PENDING_OAUTH2_AUTHORIZE_KEY: AUTHORIZE,
        }
        location = self._complete_login(test_tenant, mocker, session_data)
        assert location == AUTHORIZE
        # Regeneration happened (pre-auth keys gone, user bound) and the stash
        # was consumed rather than left for replay.
        assert session_data["user_id"] == "test-user-id"
        assert "pending_mfa_user_id" not in session_data
        assert "csrf_token" not in session_data
        assert PENDING_OAUTH2_AUTHORIZE_KEY not in session_data

    def test_forward_auth_resumes_after_real_session_regeneration(self, test_tenant, mocker):
        target = "/forward-auth/authorize?domain=acme.com&portal_host=auth.acme.com&rd=%2Fx"
        session_data: dict = {
            "pending_mfa_user_id": "test-user-id",
            "pending_mfa_method": "totp",
            PENDING_FORWARD_AUTH_KEY: target,
        }
        assert self._complete_login(test_tenant, mocker, session_data) == target
        assert PENDING_FORWARD_AUTH_KEY not in session_data

    def test_dashboard_when_nothing_pending(self, test_tenant, mocker):
        session_data: dict = {
            "pending_mfa_user_id": "test-user-id",
            "pending_mfa_method": "totp",
        }
        assert self._complete_login(test_tenant, mocker, session_data) == "/dashboard"
