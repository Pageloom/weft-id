"""Rate-limit enforcement regression tests.

Unlike the per-router tests that mock ``ratelimit.prevent`` to force the
"exceeded" branch, these drive real requests through the real limiter against
the per-test in-memory cache backend (see ``memory_cache`` in
``tests/conftest.py``). They fail if a limit is dropped, its key pattern
changes so that requests stop sharing a bucket, or its window is
misconfigured.

Every request from the TestClient comes from the same client address, so
per-IP buckets are exercised naturally.
"""

import os
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app
from services.exceptions import ValidationError


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def tenant_client(test_tenant):
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_tenant["id"])
    return TestClient(app)


# =============================================================================
# Login
# =============================================================================


def test_login_hard_block_after_20_attempts(tenant_client, mocker):
    """POST /login: 20 attempts per ip+email in 15 minutes, then blocked."""
    mocker.patch(
        "routers.auth.login.verify_login_with_status",
        return_value={"status": "invalid_credentials", "user": None},
    )
    data = {"email": "Target@Example.com", "password": "wrong"}

    for _ in range(20):
        response = tenant_client.post("/login", data=data)
        assert response.status_code == 200
        assert "Too many sign-in attempts" not in response.text

    response = tenant_client.post("/login", data=data)
    assert response.status_code == 200
    assert "Too many sign-in attempts" in response.text

    # The bucket is keyed on the normalized email, so case variants share it.
    response = tenant_client.post("/login", data={**data, "email": "target@example.com"})
    assert "Too many sign-in attempts" in response.text

    # A different email has its own bucket.
    response = tenant_client.post("/login", data={**data, "email": "other@example.com"})
    assert "Too many sign-in attempts" not in response.text


def test_login_direct_routing_limit(tenant_client, mocker):
    """POST /login/send-code without email verification: 30 per ip+tenant / 5 min."""
    from fastapi.responses import RedirectResponse

    mocker.patch(
        "routers.auth.login.settings_service.requires_email_verification_for_login",
        return_value=False,
    )
    mocker.patch(
        "routers.auth.login._route_without_verification",
        return_value=RedirectResponse(url="/login/password", status_code=303),
    )

    for _ in range(30):
        response = tenant_client.post(
            "/login/send-code", data={"email": "user@example.com"}, follow_redirects=False
        )
        assert response.status_code == 303
        assert "too_many_requests" not in response.headers["location"]

    response = tenant_client.post(
        "/login/send-code", data={"email": "user@example.com"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "error=too_many_requests" in response.headers["location"]


def test_email_send_limit_per_email(tenant_client, mocker):
    """POST /login/send-code with verification: 5 codes per email / 10 min."""
    mocker.patch(
        "routers.auth.login.settings_service.requires_email_verification_for_login",
        return_value=True,
    )
    mocker.patch("routers.auth.login.get_trust_cookie_name", return_value="email_trust_abc")
    mocker.patch("routers.auth.login.send_email_possession_code", return_value=True)
    mocker.patch("routers.auth.login.generate_verification_code", return_value="123456")
    mocker.patch("routers.auth.login.create_verification_cookie", return_value="cookie-val")

    for _ in range(5):
        response = tenant_client.post(
            "/login/send-code", data={"email": "user@example.com"}, follow_redirects=False
        )
        assert response.status_code == 303
        assert "/login/verify" in response.headers["location"]

    response = tenant_client.post(
        "/login/send-code", data={"email": "user@example.com"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "error=too_many_requests" in response.headers["location"]

    # Another email is still under its own limit (the per-IP limit is 10/hour).
    response = tenant_client.post(
        "/login/send-code", data={"email": "someone-else@example.com"}, follow_redirects=False
    )
    assert "/login/verify" in response.headers["location"]


# =============================================================================
# Password change (API and web form share one bucket)
# =============================================================================


def test_password_change_limit_shared_by_api_and_form(
    test_user, override_api_auth, override_auth, mocker
):
    """5 password changes per user per hour, counted across API and web form."""
    override_api_auth(test_user, level="user")
    override_auth(test_user, level="user")
    mocker.patch("routers.api.v1.users.users_service.change_password")
    mocker.patch("routers.account.users_service.change_password")

    client = TestClient(app)
    body = {"current_password": "old_password", "new_password": "new_strong_password!"}

    for _ in range(5):
        response = client.put("/api/v1/users/me/password", json=body)
        assert response.status_code == 204

    response = client.put("/api/v1/users/me/password", json=body)
    assert response.status_code == 429

    # The web form keys on the same user id, so it is blocked too.
    response = client.post(
        "/account/password",
        data={
            "current_password": "old_password",
            "new_password": "new_strong_password!",
            "new_password_confirm": "new_strong_password!",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=too_many_attempts" in response.headers["location"]


# =============================================================================
# OIDC upstream login + callback
# =============================================================================


def _make_oidc_connection(test_tenant, test_user):
    import database
    from services.oidc_upstream.connections import _encrypt_secret

    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test OIDC",
        provider_type="generic",
        issuer="https://idp.example.com",
        created_by=str(test_user["id"]),
        authorization_endpoint="https://idp.example.com/authorize",
        token_endpoint="https://idp.example.com/token",
        jwks_uri="https://idp.example.com/jwks",
        client_id="client-123",
        client_secret_enc=_encrypt_secret("super-secret-value"),
        is_enabled=True,
    )


def test_oidc_login_limit(tenant_client, test_tenant, test_user, memory_cache):
    """GET /auth/oidc/{id}/login: 20 per tenant+ip / 5 min, then the window resets."""
    conn = _make_oidc_connection(test_tenant, test_user)
    url = f"/auth/oidc/{conn['id']}/login"
    base = memory_cache.clock()
    memory_cache.clock = lambda: base

    for _ in range(20):
        response = tenant_client.get(url, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("https://idp.example.com/authorize?")

    response = tenant_client.get(url, follow_redirects=False)
    assert response.status_code == 303
    assert "/login?error=too_many_requests" in response.headers["location"]

    # The limit is checked before the connection lookup, so an unknown
    # connection id is refused for the same reason (no enumeration oracle).
    response = tenant_client.get(f"/auth/oidc/{uuid4()}/login", follow_redirects=False)
    assert "/login?error=too_many_requests" in response.headers["location"]

    # After the 5 minute window the bucket has expired.
    memory_cache.clock = lambda: base + 300
    response = tenant_client.get(url, follow_redirects=False)
    assert response.headers["location"].startswith("https://idp.example.com/authorize?")


def test_oidc_callback_limit(tenant_client, test_tenant, test_user):
    """GET /auth/oidc/{id}/callback: 20 per tenant+ip / 5 min, independent of login."""
    conn = _make_oidc_connection(test_tenant, test_user)
    url = f"/auth/oidc/{conn['id']}/callback?state=wrong&code=abc"

    for _ in range(20):
        response = tenant_client.get(url, follow_redirects=False)
        assert response.status_code == 303
        assert "/login?error=auth_failed" in response.headers["location"]

    response = tenant_client.get(url, follow_redirects=False)
    assert response.status_code == 303
    assert "/login?error=too_many_requests" in response.headers["location"]

    # The login route has its own bucket and is unaffected.
    response = tenant_client.get(f"/auth/oidc/{conn['id']}/login", follow_redirects=False)
    assert response.headers["location"].startswith("https://idp.example.com/authorize?")


# =============================================================================
# SAML ACS (per-IdP and legacy share one bucket)
# =============================================================================


def test_saml_acs_limit_shared_by_per_idp_and_legacy(tenant_client):
    """POST /saml/acs[/{idp_id}]: 20 per tenant+ip / 5 min, then 429."""
    data = {"SAMLResponse": "base64data", "RelayState": "/dashboard"}
    with (
        patch(
            "routers.saml.authentication.saml_service.process_saml_response",
            side_effect=ValidationError("Missing attribute"),
        ),
        patch(
            "routers.saml.authentication.store_saml_debug_and_respond",
            return_value=HTMLResponse(content="<html>error</html>"),
        ),
    ):
        for _ in range(20):
            response = tenant_client.post(f"/saml/acs/{uuid4()}", data=data)
            assert response.status_code == 200

        response = tenant_client.post(f"/saml/acs/{uuid4()}", data=data)
        assert response.status_code == 429
        assert "too many" in response.text.lower()

        # The legacy ACS keys on the same tenant+ip bucket.
        response = tenant_client.post("/saml/acs", data=data)
        assert response.status_code == 429

        # The admin test flow deliberately bypasses the limit.
        with patch(
            "routers.saml.authentication._handle_saml_test_response",
            return_value=HTMLResponse(content="<html>test</html>"),
        ):
            response = tenant_client.post("/saml/acs", data={**data, "RelayState": "__test__:abc"})
            assert response.status_code == 200
