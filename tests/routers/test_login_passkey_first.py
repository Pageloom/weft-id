"""Tests for the login page's passkey-first variant rendering.

See ``app/routers/auth/login.py::login_page``. When the email-first flow
provides both ``show_password=true`` and ``prefill_email``, the server
unconditionally renders the passkey-first variant without any database lookup.
This removes the passkey-oracle attack surface: any email value, including
nonexistent ones, triggers the passkey-first UI.
"""

from urllib.parse import quote

from fastapi.testclient import TestClient
from main import app


def _override_tenant(tenant_id: str) -> None:
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(tenant_id)


def test_login_page_shows_passkey_first_when_both_params_present(test_tenant, mocker):
    """When show_password and prefill_email are both present, passkey-first is shown."""
    _override_tenant(test_tenant["id"])
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    email = "any-user@example.com"
    response = client.get(f"/login?show_password=true&prefill_email={quote(email)}")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.text
    assert 'id="passkey-flow"' in body
    assert 'id="passkey-page-data"' in body
    assert "/login/passkey/begin" in body


def test_login_page_shows_passkey_first_for_nonexistent_email(test_tenant, mocker):
    """Passkey-first is shown for nonexistent emails too (no oracle lookup)."""
    _override_tenant(test_tenant["id"])
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    response = client.get("/login?show_password=true&prefill_email=ghost%40example.com")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert 'id="passkey-flow"' in response.text


def test_login_page_no_passkey_first_without_prefill_email(test_tenant, mocker):
    """show_password alone (no prefill_email) does not trigger passkey-first."""
    _override_tenant(test_tenant["id"])
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    response = client.get("/login?show_password=true")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert 'id="passkey-flow"' not in response.text
    assert 'id="passkey-page-data"' not in response.text


def test_login_page_no_passkey_first_without_show_password(test_tenant, mocker):
    """prefill_email alone (no show_password) does not trigger passkey-first."""
    _override_tenant(test_tenant["id"])
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    response = client.get("/login?prefill_email=user%40example.com")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert 'id="passkey-flow"' not in response.text


def test_login_page_step1_no_passkey_first(test_tenant, mocker):
    """Step 1 (plain /login, no params) must not show the passkey-first flow."""
    _override_tenant(test_tenant["id"])
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    client = TestClient(app)
    response = client.get("/login")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert 'id="passkey-flow"' not in response.text


def test_login_page_no_database_lookup_for_passkey_first(test_tenant, mocker):
    """The server must NOT call any database/service lookup to decide passkey-first.

    This is the oracle-fix pin test: if a webauthn service call is introduced
    for the passkey-first decision, this test will fail.
    """
    _override_tenant(test_tenant["id"])
    mocker.patch("routers.auth.login.get_current_user", return_value=None)

    # If any webauthn service function is called, we want the test to detect it.
    spy = mocker.MagicMock(side_effect=RuntimeError("unexpected DB lookup for passkey-first"))
    mocker.patch("services.webauthn.user_has_passkey_for_email", spy)

    client = TestClient(app)
    email = "some-user@example.com"
    response = client.get(f"/login?show_password=true&prefill_email={quote(email)}")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert 'id="passkey-flow"' in response.text
    spy.assert_not_called()
