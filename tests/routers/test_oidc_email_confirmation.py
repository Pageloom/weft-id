"""Route tests for the sign-in email confirmation step.

A sign-in through a provider that does not prove the user's address
(Facebook here) stops at /auth/oidc/confirm-email until the user enters the
code mailed to it, then resumes: platform MFA if the connection requires it,
otherwise login completion.
"""

import os
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from main import app

from tests.fixtures.facebook import facebook_api
from tests.helpers.client import TestClient

CONFIRM = "/auth/oidc/confirm-email"
SEND = "routers.oidc_upstream.authentication.send_email_possession_code"


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


def _make_facebook(test_tenant, created_by, **overrides):
    import database
    from services.oidc_upstream.connections import _encrypt_secret

    kwargs = {
        "provider_type": "facebook",
        "issuer": "https://www.facebook.com",
        "client_id": "client-1",
        "client_secret_enc": _encrypt_secret("secret-1"),
        "scopes": "public_profile email",
        "is_enabled": True,
        "jit_provisioning": True,
    }
    kwargs.update(overrides)
    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Facebook",
        created_by=str(created_by["id"]),
        **kwargs,
    )


class _Flow:
    """One browser: a shared session, the client's cookies, the codes mailed."""

    def __init__(self, client, conn):
        self.client = client
        self.conn = conn
        self.session: dict = {}
        self.codes: list[str] = []

    def _record(self, email, code, **kwargs):
        self.codes.append(code)
        return True

    @contextmanager
    def active(self):
        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda _: self.session),
            ),
            patch(SEND, side_effect=self._record) as send,
        ):
            self.send = send
            yield self

    def callback(self):
        cid = self.conn["id"]
        self.session.update(
            {
                f"oidc_auth:{cid}:state": "state-1",
                f"oidc_auth:{cid}:nonce": "n-1",
                f"oidc_auth:{cid}:code_verifier": "verifier-1",
            }
        )
        with facebook_api():
            return self.client.get(
                f"/auth/oidc/{cid}/callback?state=state-1&code=code-1", follow_redirects=False
            )

    def confirm(self, code):
        return self.client.post(CONFIRM, data={"code": code}, follow_redirects=False)


def _user_id(test_tenant, conn):
    import database

    return database.oidc_upstream.get_user_id_by_sub(
        test_tenant["id"], str(conn["id"]), "10158000000000001"
    )


def _verified(test_tenant, user_id):
    import database

    row = database.user_emails.get_primary_email_for_resend(test_tenant["id"], user_id)
    return row["verified_at"] is not None


class TestConfirmation:
    def test_full_flow(self, tenant_client, test_tenant, test_user):
        conn = _make_facebook(test_tenant, test_user)
        with _Flow(tenant_client, conn).active() as flow:
            response = flow.callback()
            assert response.headers["location"] == CONFIRM
            assert flow.send.call_args.args[0] == "ada@example.com"
            assert "oidc_email_confirm" in tenant_client.cookies
            user_id = _user_id(test_tenant, conn)
            assert not _verified(test_tenant, user_id)
            # Not signed in yet.
            assert "user_id" not in flow.session

            page = tenant_client.get(CONFIRM)
            assert page.status_code == 200
            assert "ada@example.com" in page.text
            assert "Confirm your email address to finish signing in." in page.text
            assert f'action="{CONFIRM}"' in page.text
            assert f'action="{CONFIRM}/resend"' in page.text
            assert "Back to sign in" in page.text

            response = flow.confirm(flow.codes[-1])

        assert response.status_code == 303
        assert "/login" not in response.headers["location"]
        assert _verified(test_tenant, user_id)
        assert flow.session.get("user_id") == user_id
        assert "pending_oidc_email_confirmation" not in flow.session
        assert "oidc_email_confirm" not in tenant_client.cookies

    def test_wrong_code(self, tenant_client, test_tenant, test_user):
        conn = _make_facebook(test_tenant, test_user)
        with _Flow(tenant_client, conn).active() as flow:
            flow.callback()
            wrong = "000000" if flow.codes[-1] != "000000" else "111111"
            response = flow.confirm(wrong)
            page = tenant_client.get(response.headers["location"])

        assert response.headers["location"] == f"{CONFIRM}?error=invalid_code"
        assert "Invalid code" in page.text
        assert not _verified(test_tenant, _user_id(test_tenant, conn))
        assert "user_id" not in flow.session

    def test_then_platform_mfa(self, tenant_client, test_tenant, test_user):
        conn = _make_facebook(test_tenant, test_user, require_platform_mfa=True)
        with (
            _Flow(tenant_client, conn).active() as flow,
            patch("routers.oidc_upstream.authentication.send_mfa_code_email") as mfa_mail,
        ):
            flow.callback()
            # Confirmation comes first; MFA only after it.
            mfa_mail.assert_not_called()
            assert "pending_mfa_user_id" not in flow.session
            response = flow.confirm(flow.codes[-1])

        assert response.headers["location"] == "/mfa/verify"
        assert flow.session["pending_mfa_user_id"] == _user_id(test_tenant, conn)
        mfa_mail.assert_called_once()
        assert mfa_mail.call_args.args[0] == "ada@example.com"

    def test_next_sign_in_asks_again(self, tenant_client, test_tenant, test_user):
        conn = _make_facebook(test_tenant, test_user)
        with _Flow(tenant_client, conn).active() as flow:
            flow.callback()
        # Abandoned; a fresh browser signs in again through the existing link.
        tenant_client.cookies.clear()
        with _Flow(tenant_client, conn).active() as flow:
            response = flow.callback()
        assert response.headers["location"] == CONFIRM
        flow.send.assert_called_once()

    def test_confirmed_user_signs_in_directly(self, tenant_client, test_tenant, test_user):
        conn = _make_facebook(test_tenant, test_user)
        with _Flow(tenant_client, conn).active() as flow:
            flow.callback()
            flow.confirm(flow.codes[-1])
        tenant_client.cookies.clear()
        with _Flow(tenant_client, conn).active() as flow:
            response = flow.callback()
        assert response.headers["location"] != CONFIRM
        assert "/login?error" not in response.headers["location"]
        flow.send.assert_not_called()

    def test_resend(self, tenant_client, test_tenant, test_user):
        conn = _make_facebook(test_tenant, test_user)
        with _Flow(tenant_client, conn).active() as flow:
            flow.callback()
            first = flow.codes[-1]
            response = tenant_client.post(f"{CONFIRM}/resend", follow_redirects=False)
            assert response.headers["location"] == f"{CONFIRM}?success=code_sent"
            assert len(flow.codes) == 2
            if flow.codes[-1] != first:
                # The earlier code no longer matches the new cookie.
                assert flow.confirm(first).headers["location"].endswith("error=invalid_code")
            assert flow.confirm(flow.codes[-1]).status_code == 303
        assert _verified(test_tenant, _user_id(test_tenant, conn))

    def test_nothing_pending(self, tenant_client):
        with patch(
            "starlette.requests.Request.session",
            new_callable=lambda: property(lambda _: {}),
        ):
            page = tenant_client.get(CONFIRM, follow_redirects=False)
            post = tenant_client.post(CONFIRM, data={"code": "123456"}, follow_redirects=False)
            resend = tenant_client.post(f"{CONFIRM}/resend", follow_redirects=False)
        for response in (page, post, resend):
            assert response.headers["location"].endswith("/login?error=session_expired")

    def test_missing_cookie(self, tenant_client, test_tenant, test_user):
        conn = _make_facebook(test_tenant, test_user)
        with _Flow(tenant_client, conn).active() as flow:
            flow.callback()
            tenant_client.cookies.clear()
            response = flow.confirm("123456")
        assert response.headers["location"].endswith("/login?error=session_expired")
        assert "pending_oidc_email_confirmation" not in flow.session

    def test_disabled_connection_abandons(self, tenant_client, test_tenant, test_user):
        import database

        conn = _make_facebook(test_tenant, test_user)
        with _Flow(tenant_client, conn).active() as flow:
            flow.callback()
            database.oidc_upstream.set_connection_enabled(test_tenant["id"], str(conn["id"]), False)
            response = flow.confirm(flow.codes[-1])
        assert response.headers["location"].endswith("/login?error=session_expired")
        assert not _verified(test_tenant, _user_id(test_tenant, conn))

    def test_tampered_session_user(self, tenant_client, test_tenant, test_user):
        conn = _make_facebook(test_tenant, test_user)
        with _Flow(tenant_client, conn).active() as flow:
            flow.callback()
            # Point the parked sign-in at another (verified) user.
            flow.session["pending_oidc_email_confirmation"]["user_id"] = str(test_user["id"])
            response = flow.confirm(flow.codes[-1])
        assert response.headers["location"].endswith("/login?error=session_expired")
        assert "user_id" not in flow.session

    def test_confirm_rate_limited(self, tenant_client, test_tenant, test_user):
        from services.exceptions import RateLimitError
        from utils.ratelimit import ratelimit

        conn = _make_facebook(test_tenant, test_user)
        real_prevent = ratelimit.prevent

        def prevent(key, *args, **kwargs):
            if key.startswith("oidc_email_confirm:ip"):
                raise RateLimitError("limited")
            return real_prevent(key, *args, **kwargs)

        with _Flow(tenant_client, conn).active() as flow:
            flow.callback()
            with patch.object(ratelimit, "prevent", side_effect=prevent):
                response = flow.confirm(flow.codes[-1])
            page = tenant_client.get(response.headers["location"])
        assert response.headers["location"] == f"{CONFIRM}?error=too_many_attempts"
        assert "Too many attempts" in page.text
        assert not _verified(test_tenant, _user_id(test_tenant, conn))

    def test_send_rate_limited(self, tenant_client, test_tenant, test_user):
        from services.exceptions import RateLimitError
        from utils.ratelimit import ratelimit

        conn = _make_facebook(test_tenant, test_user)
        real_prevent = ratelimit.prevent

        def prevent(key, *args, **kwargs):
            if key.startswith("oidc_email_confirm_send"):
                raise RateLimitError("limited")
            return real_prevent(key, *args, **kwargs)

        with (
            _Flow(tenant_client, conn).active() as flow,
            patch.object(ratelimit, "prevent", side_effect=prevent),
        ):
            response = flow.callback()
        assert response.headers["location"].endswith("/login?error=too_many_requests")
        flow.send.assert_not_called()

    def test_login_page_messages(self, tenant_client):
        assert "Your sign-in expired" in tenant_client.get("/login?error=session_expired").text
        assert "Too many attempts" in tenant_client.get("/login?error=too_many_requests").text
