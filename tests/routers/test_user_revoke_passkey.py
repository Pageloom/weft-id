"""Tests for admin passkey revoke route (web form POST)."""

from uuid import uuid4

from fastapi.testclient import TestClient
from main import app
from services.exceptions import NotFoundError

USERS_DETAIL = "routers.users.detail"
SERVICES_USERS = "services.users"
DATABASE_SETTINGS = "database.settings"


def test_revoke_passkey_success(test_user, override_auth, mocker):
    """Admin can revoke another user's passkey."""
    test_user["role"] = "admin"
    override_auth(test_user)

    mock_revoke = mocker.patch("services.webauthn.admin_revoke_credential")
    target_id = str(uuid4())
    cred_id = str(uuid4())

    client = TestClient(app)
    response = client.post(
        f"/users/{target_id}/revoke-passkey/{cred_id}",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/users/{target_id}/profile?success=passkey_revoked" in response.headers["location"]
    mock_revoke.assert_called_once()


def test_revoke_passkey_not_found(test_user, override_auth, mocker):
    test_user["role"] = "admin"
    override_auth(test_user)

    mocker.patch(
        "services.webauthn.admin_revoke_credential",
        side_effect=NotFoundError(message="Passkey not found", code="passkey_not_found"),
    )

    target_id = str(uuid4())
    cred_id = str(uuid4())
    client = TestClient(app)
    response = client.post(
        f"/users/{target_id}/revoke-passkey/{cred_id}",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/users/{target_id}/profile?error=passkey_not_found" in response.headers["location"]


def test_revoke_passkey_member_denied(test_user, override_auth):
    test_user["role"] = "member"
    override_auth(test_user)

    client = TestClient(app)
    response = client.post(
        f"/users/{uuid4()}/revoke-passkey/{uuid4()}",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# Profile tab renders passkey list
# =============================================================================


def _fake_target_user():
    from datetime import UTC, datetime

    from schemas.api import UserDetail

    return UserDetail(
        id="user-123",
        email="t@example.com",
        first_name="T",
        last_name="U",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[],
        is_service_user=False,
    )


def test_profile_tab_renders_passkey_list(test_admin_user, mocker, override_auth):
    from fastapi.responses import HTMLResponse
    from schemas.webauthn import PasskeyResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mocker.patch(f"{SERVICES_USERS}.get_user", return_value=_fake_target_user())
    mocker.patch(f"{DATABASE_SETTINGS}.list_privileged_domains", return_value=[])
    mocker.patch(f"{USERS_DETAIL}.groups_service")
    mocker.patch(f"{USERS_DETAIL}.sp_service")

    passkey = PasskeyResponse(
        id="pk-1",
        name="YubiKey 5",
        transports=["usb"],
        backup_eligible=False,
        backup_state=False,
        created_at="2026-04-17T00:00:00+00:00",
        last_used_at="2026-04-18T00:00:00+00:00",
    )
    mocker.patch(
        f"{USERS_DETAIL}.webauthn_service.admin_list_credentials",
        return_value=[passkey],
    )

    mock_template.return_value = HTMLResponse(content="<html>ok</html>")
    client = TestClient(app)
    response = client.get("/users/user-123/profile")

    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["passkeys"] == [passkey]


def test_profile_tab_renders_empty_passkey_list(test_admin_user, mocker, override_auth):
    from fastapi.responses import HTMLResponse

    override_auth(test_admin_user)

    mock_template = mocker.patch(f"{USERS_DETAIL}.templates.TemplateResponse")
    mocker.patch(f"{SERVICES_USERS}.get_user", return_value=_fake_target_user())
    mocker.patch(f"{DATABASE_SETTINGS}.list_privileged_domains", return_value=[])
    mocker.patch(f"{USERS_DETAIL}.groups_service")
    mocker.patch(f"{USERS_DETAIL}.sp_service")
    mocker.patch(
        f"{USERS_DETAIL}.webauthn_service.admin_list_credentials",
        return_value=[],
    )

    mock_template.return_value = HTMLResponse(content="<html>ok</html>")
    client = TestClient(app)
    response = client.get("/users/user-123/profile")

    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["passkeys"] == []
