"""Tests for routers.api.v1.users_passkeys (admin passkey endpoints)."""

from main import app
from schemas.webauthn import PasskeyResponse
from services.exceptions import ForbiddenError, NotFoundError
from starlette.testclient import TestClient


def _fake_passkey(name: str = "Target key") -> PasskeyResponse:
    return PasskeyResponse(
        id="22222222-2222-2222-2222-222222222222",
        name=name,
        transports=["internal"],
        backup_eligible=False,
        backup_state=False,
        created_at="2026-04-17T00:00:00+00:00",
        last_used_at=None,
    )


def test_list_user_passkeys_admin(make_user_dict, override_api_auth, mocker):
    admin = make_user_dict(role="admin")
    override_api_auth(admin, level="user")
    mocker.patch(
        "services.webauthn.admin_list_credentials",
        return_value=[_fake_passkey()],
    )

    client = TestClient(app)
    response = client.get("/api/v1/users/11111111-1111-1111-1111-111111111111/passkeys")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["name"] == "Target key"


def test_list_user_passkeys_forbidden(make_user_dict, override_api_auth, mocker):
    member = make_user_dict(role="member")
    override_api_auth(member, level="user")
    mocker.patch(
        "services.webauthn.admin_list_credentials",
        side_effect=ForbiddenError(message="Admin access required"),
    )

    client = TestClient(app)
    response = client.get("/api/v1/users/11111111-1111-1111-1111-111111111111/passkeys")
    assert response.status_code == 403


def test_list_user_passkeys_unauthenticated(test_tenant, test_tenant_host):
    client = TestClient(app)
    response = client.get(
        "/api/v1/users/11111111-1111-1111-1111-111111111111/passkeys",
        headers={"host": test_tenant_host},
    )
    assert response.status_code == 401


def test_revoke_user_passkey_admin(make_user_dict, override_api_auth, mocker):
    admin = make_user_dict(role="admin")
    override_api_auth(admin, level="user")
    revoke = mocker.patch("services.webauthn.admin_revoke_credential", return_value=None)

    client = TestClient(app)
    response = client.delete(
        "/api/v1/users/11111111-1111-1111-1111-111111111111"
        "/passkeys/22222222-2222-2222-2222-222222222222"
    )
    assert response.status_code == 204
    assert revoke.called


def test_revoke_user_passkey_forbidden(make_user_dict, override_api_auth, mocker):
    member = make_user_dict(role="member")
    override_api_auth(member, level="user")
    mocker.patch(
        "services.webauthn.admin_revoke_credential",
        side_effect=ForbiddenError(message="Admin access required"),
    )

    client = TestClient(app)
    response = client.delete(
        "/api/v1/users/11111111-1111-1111-1111-111111111111"
        "/passkeys/22222222-2222-2222-2222-222222222222"
    )
    assert response.status_code == 403


def test_revoke_user_passkey_not_found(make_user_dict, override_api_auth, mocker):
    admin = make_user_dict(role="admin")
    override_api_auth(admin, level="user")
    mocker.patch(
        "services.webauthn.admin_revoke_credential",
        side_effect=NotFoundError(message="Passkey not found"),
    )

    client = TestClient(app)
    response = client.delete(
        "/api/v1/users/11111111-1111-1111-1111-111111111111"
        "/passkeys/22222222-2222-2222-2222-222222222222"
    )
    assert response.status_code == 404


def test_revoke_user_passkey_unauthenticated(test_tenant, test_tenant_host):
    client = TestClient(app)
    response = client.delete(
        "/api/v1/users/11111111-1111-1111-1111-111111111111"
        "/passkeys/22222222-2222-2222-2222-222222222222",
        headers={"host": test_tenant_host},
    )
    assert response.status_code == 401
