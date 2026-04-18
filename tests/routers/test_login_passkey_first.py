"""Tests for the login page's passkey-first variant rendering.

See `app/routers/auth/login.py::login_page`. When the email-first flow lands a
user on the password form AND the user has a registered passkey, the template
renders a passkey-first variant that auto-starts `navigator.credentials.get()`.
These tests exercise the server-side decision to render that variant without
actually running JavaScript.
"""

from urllib.parse import quote

from fastapi.testclient import TestClient
from main import app


def _override_tenant(tenant_id: str) -> None:
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(tenant_id)


def test_login_page_shows_passkey_first_for_eligible_user(test_tenant, mocker):
    """When the user has a passkey, the passkey-first variant is rendered."""
    _override_tenant(test_tenant["id"])
    mocker.patch(
        "routers.auth.login.webauthn_service.user_has_passkey_for_email",
        return_value=True,
    )
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    email = "passkey-user@example.com"
    response = client.get(f"/login?show_password=true&prefill_email={quote(email)}")

    assert response.status_code == 200
    # The template contains the passkey-first flow markers when active.
    body = response.text
    assert 'id="passkey-flow"' in body
    assert 'id="passkey-page-data"' in body
    # The embedded page-data JSON carries the begin URL.
    assert "/login/passkey/begin" in body


def test_login_page_hides_passkey_for_user_without_passkey(test_tenant, mocker):
    """Password-only user falls through to the plain password form."""
    _override_tenant(test_tenant["id"])
    mocker.patch(
        "routers.auth.login.webauthn_service.user_has_passkey_for_email",
        return_value=False,
    )
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    response = client.get("/login?show_password=true&prefill_email=no-passkey%40example.com")

    assert response.status_code == 200
    assert 'id="passkey-flow"' not in response.text
    assert 'id="passkey-page-data"' not in response.text


def test_login_page_hides_passkey_for_nonexistent_email(test_tenant, mocker):
    """Anti-enumeration: nonexistent email behaves identically to a password-only user."""
    _override_tenant(test_tenant["id"])
    mocker.patch(
        "routers.auth.login.webauthn_service.user_has_passkey_for_email",
        return_value=False,
    )
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    response = client.get("/login?show_password=true&prefill_email=ghost%40example.com")

    assert response.status_code == 200
    assert 'id="passkey-flow"' not in response.text


def test_login_page_degrades_gracefully_on_lookup_error(test_tenant, mocker):
    """If the passkey eligibility lookup raises, fall back to the plain password form."""
    _override_tenant(test_tenant["id"])
    mocker.patch(
        "routers.auth.login.webauthn_service.user_has_passkey_for_email",
        side_effect=RuntimeError("boom"),
    )
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    response = client.get("/login?show_password=true&prefill_email=err%40example.com")
    assert response.status_code == 200
    assert 'id="passkey-flow"' not in response.text


def test_login_page_step1_does_not_check_passkey(test_tenant, mocker):
    """Step 1 (email entry, no show_password) must not trigger a passkey lookup."""
    _override_tenant(test_tenant["id"])
    spy = mocker.patch(
        "routers.auth.login.webauthn_service.user_has_passkey_for_email",
        return_value=True,
    )
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    response = client.get("/login")
    assert response.status_code == 200
    assert 'id="passkey-flow"' not in response.text
    spy.assert_not_called()
