"""End-to-end CSRF enforcement against the real application.

The middleware is unit-tested on a throwaway app in tests/middleware/. These
tests exist because that was not enough: for eleven months the middleware was
registered on the wrong side of the session middleware in app/main.py and
silently passed every request, while every unit test stayed green. The only
guard that catches that class of bug is a bare POST to a real form route on
``main.app`` that must come back 403.
"""

import pytest
from middleware.csrf import CSRF_HEADER_NAME, CSRF_SESSION_KEY

from tests.helpers.client import TEST_CSRF_TOKEN

# A session-cookie form route that needs no login: it redirects to /login.
FORM_ROUTE = "/logout"


@pytest.fixture
def host(test_tenant_host):
    return {"Host": test_tenant_host}


class TestRealAppRejectsUntokenedRequests:
    def test_bare_post_is_rejected(self, client, host):
        with client.without_csrf():
            response = client.post(FORM_ROUTE, headers=host, follow_redirects=False)
        assert response.status_code == 403
        assert "CSRF" in response.text

    def test_post_with_wrong_header_is_rejected(self, client, host):
        response = client.post(
            FORM_ROUTE,
            headers={**host, CSRF_HEADER_NAME: "not-the-token"},
            follow_redirects=False,
        )
        assert response.status_code == 403

    def test_post_with_wrong_form_field_is_rejected(self, client, host):
        client.seed_csrf_token()
        with client.without_csrf():
            response = client.post(
                FORM_ROUTE,
                headers=host,
                data={"csrf_token": "not-the-token"},
                follow_redirects=False,
            )
        assert response.status_code == 403

    def test_token_in_session_but_not_in_request_is_rejected(self, client, host):
        client.seed_csrf_token()
        with client.without_csrf():
            response = client.post(FORM_ROUTE, headers=host, follow_redirects=False)
        assert response.status_code == 403

    def test_token_in_request_but_not_in_session_is_rejected(self, client, host):
        with client.without_csrf():
            response = client.post(
                FORM_ROUTE,
                headers={**host, CSRF_HEADER_NAME: TEST_CSRF_TOKEN},
                follow_redirects=False,
            )
        assert response.status_code == 403

    def test_json_clients_get_a_json_403(self, client, host):
        with client.without_csrf():
            response = client.post(
                FORM_ROUTE,
                headers={**host, "Accept": "application/json"},
                follow_redirects=False,
            )
        assert response.status_code == 403
        assert response.json() == {"detail": "CSRF token validation failed"}


class TestRealAppAcceptsTokenedRequests:
    def test_header_token_is_accepted(self, client, host):
        response = client.post(FORM_ROUTE, headers=host, follow_redirects=False)
        assert response.status_code == 303

    def test_urlencoded_form_token_is_accepted(self, client, host):
        client.seed_csrf_token()
        with client.without_csrf():
            response = client.post(
                FORM_ROUTE,
                headers=host,
                data={"csrf_token": TEST_CSRF_TOKEN},
                follow_redirects=False,
            )
        assert response.status_code == 303

    def test_multipart_form_token_is_accepted(self, client, host):
        client.seed_csrf_token()
        with client.without_csrf():
            response = client.post(
                FORM_ROUTE,
                headers=host,
                files={"csrf_token": (None, TEST_CSRF_TOKEN)},
                follow_redirects=False,
            )
        assert response.status_code == 303

    def test_handler_still_receives_the_form_after_token_parsing(self, client, host, mocker):
        """A route with Form() parameters must not 422 once the middleware parsed the body.

        Browsers send the token in the form, not a header, so this is the
        production path. BaseHTTPMiddleware replays the body only when it was
        read with ``request.body()``; the first E2E run after enabling CSRF
        turned every form POST into a 422 because only ``form()`` was called.
        """
        login = "routers.auth.login"
        mocker.patch(
            f"{login}.settings_service.requires_email_verification_for_login", return_value=True
        )
        mocker.patch(f"{login}.ratelimit")
        mocker.patch(f"{login}.get_trust_cookie_name", return_value="email_trust_abc")
        mocker.patch(f"{login}.send_email_possession_code", return_value=True)
        mocker.patch(f"{login}.generate_verification_code", return_value="123456")
        mocker.patch(f"{login}.create_verification_cookie", return_value="cookie-val")
        client.seed_csrf_token()
        with client.without_csrf():
            response = client.post(
                "/login/send-code",
                headers=host,
                data={"email": "someone@example.com", "csrf_token": TEST_CSRF_TOKEN},
                follow_redirects=False,
            )
        assert response.status_code not in (403, 422), response.text
        assert response.status_code == 303

    def test_safe_methods_need_no_token(self, client, host):
        with client.without_csrf():
            response = client.get("/login", headers=host, follow_redirects=False)
        assert response.status_code != 403

    def test_api_routes_are_exempt(self, client, host):
        """Bearer-authenticated API routes never see the middleware (401, not 403)."""
        with client.without_csrf():
            response = client.post("/api/v1/users", headers=host, json={})
        assert response.status_code == 401


class TestCsrfAwareTestClient:
    """The helper itself, since the whole suite now leans on it."""

    def test_seeding_preserves_existing_session_state(self, client):
        client.set_session_cookie({"user_id": "abc", "session_start": 1})
        client.seed_csrf_token()
        assert client.session_cookie() == {
            "user_id": "abc",
            "session_start": 1,
            CSRF_SESSION_KEY: TEST_CSRF_TOKEN,
        }

    def test_without_csrf_is_restored_after_the_block(self, client, host):
        with client.without_csrf():
            assert client.post(FORM_ROUTE, headers=host, follow_redirects=False).status_code == 403
        assert client.post(FORM_ROUTE, headers=host, follow_redirects=False).status_code == 303

    def test_explicit_header_wins_over_the_automatic_one(self, client, host):
        response = client.post(
            FORM_ROUTE,
            headers={**host, CSRF_HEADER_NAME: "explicit-wrong"},
            follow_redirects=False,
        )
        assert response.status_code == 403

    def test_ad_hoc_apps_are_left_alone(self):
        """Only main.app is touched; a throwaway app gets plain TestClient behaviour."""
        from fastapi import FastAPI, Request

        from tests.helpers.client import TestClient

        app = FastAPI()

        @app.post("/echo")
        async def echo(request: Request):
            return {"header": request.headers.get(CSRF_HEADER_NAME)}

        response = TestClient(app).post("/echo")
        assert response.json() == {"header": None}
