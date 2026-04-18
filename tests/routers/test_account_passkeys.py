"""Tests for routers.account_passkeys (HTML)."""

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app
from schemas.webauthn import (
    BeginRegistrationResponse,
    CompleteRegistrationResponse,
    PasskeyResponse,
)


def _fake_passkey() -> PasskeyResponse:
    return PasskeyResponse(
        id="11111111-1111-1111-1111-111111111111",
        name="Laptop",
        transports=["internal"],
        backup_eligible=False,
        backup_state=False,
        created_at="2026-04-17T00:00:00+00:00",
        last_used_at=None,
    )


def test_passkeys_page_renders(test_user, override_auth, mocker):
    override_auth(test_user)
    mocker.patch(
        "services.webauthn.list_credentials",
        return_value=[_fake_passkey()],
    )
    mock_template = mocker.patch("routers.account_passkeys.templates.TemplateResponse")
    mock_template.return_value = HTMLResponse(content="<html>Passkeys</html>")

    client = TestClient(app)
    response = client.get("/account/passkeys")

    assert response.status_code == 200
    mock_template.assert_called_once()


def test_begin_registration_returns_options(test_user, override_auth, mocker):
    override_auth(test_user)
    mocker.patch(
        "services.webauthn.begin_registration",
        return_value=BeginRegistrationResponse(public_key={"rp": {"id": "host"}}),
    )

    client = TestClient(app)
    response = client.post("/account/passkeys/begin-registration")

    assert response.status_code == 200
    assert response.json() == {"publicKey": {"rp": {"id": "host"}}}


def test_complete_registration_persists(test_user, override_auth, mocker):
    override_auth(test_user)
    mocker.patch(
        "services.webauthn.complete_registration",
        return_value=CompleteRegistrationResponse(
            credential=_fake_passkey(),
            backup_codes=["code-1", "code-2"],
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/account/passkeys/complete-registration",
        json={"name": "Laptop", "response": {"id": "x"}},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["credential"]["name"] == "Laptop"
    assert body["backup_codes"] == ["code-1", "code-2"]


def test_complete_registration_invalid_json(test_user, override_auth):
    override_auth(test_user)
    client = TestClient(app)
    response = client.post(
        "/account/passkeys/complete-registration",
        content="not-json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400


def test_rename_passkey_redirects(test_user, override_auth, mocker):
    override_auth(test_user)
    mocker.patch(
        "services.webauthn.rename_credential",
        return_value=_fake_passkey(),
    )
    client = TestClient(app)
    response = client.post(
        "/account/passkeys/abc/rename",
        data={"name": "NewName"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/account/passkeys?success=renamed"


def test_rename_passkey_not_found(test_user, override_auth, mocker):
    from services.exceptions import NotFoundError

    override_auth(test_user)
    mocker.patch(
        "services.webauthn.rename_credential",
        side_effect=NotFoundError(message="not found"),
    )
    client = TestClient(app)
    response = client.post(
        "/account/passkeys/abc/rename",
        data={"name": "NewName"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/account/passkeys?error=not_found"


def test_delete_passkey_redirects(test_user, override_auth, mocker):
    override_auth(test_user)
    mocker.patch("services.webauthn.delete_credential", return_value=None)
    client = TestClient(app)
    response = client.post(
        "/account/passkeys/abc/delete",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/account/passkeys?success=deleted"


def test_delete_passkey_not_found(test_user, override_auth, mocker):
    from services.exceptions import NotFoundError

    override_auth(test_user)
    mocker.patch(
        "services.webauthn.delete_credential",
        side_effect=NotFoundError(message="not found"),
    )
    client = TestClient(app)
    response = client.post(
        "/account/passkeys/abc/delete",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/account/passkeys?error=not_found"


def test_passkeys_page_requires_auth(test_tenant, test_tenant_host):
    """Unauthenticated requests must redirect to login."""
    client = TestClient(app)
    response = client.get(
        "/account/passkeys",
        headers={"host": test_tenant_host},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
