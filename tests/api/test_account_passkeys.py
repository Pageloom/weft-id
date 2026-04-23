"""Tests for routers.api.v1.account_passkeys."""

from main import app
from schemas.webauthn import (
    BeginRegistrationResponse,
    CompleteRegistrationResponse,
    PasskeyResponse,
)
from services.exceptions import NotFoundError
from starlette.testclient import TestClient


def _fake_passkey(name: str = "Laptop") -> PasskeyResponse:
    return PasskeyResponse(
        id="11111111-1111-1111-1111-111111111111",
        name=name,
        transports=["internal"],
        backup_eligible=False,
        backup_state=False,
        created_at="2026-04-17T00:00:00+00:00",
        last_used_at=None,
    )


def test_list_passkeys(make_user_dict, override_api_auth, mocker):
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")
    mocker.patch(
        "services.webauthn.list_credentials",
        return_value=[_fake_passkey()],
    )

    client = TestClient(app)
    response = client.get("/api/v1/account/passkeys")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["name"] == "Laptop"


def test_begin_registration(make_user_dict, override_api_auth, mocker):
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")
    mocker.patch(
        "services.webauthn.begin_registration",
        return_value=BeginRegistrationResponse(public_key={"rp": {"id": "host"}}),
    )

    client = TestClient(app)
    response = client.post("/api/v1/account/passkeys/begin-registration")
    assert response.status_code == 200
    assert response.json() == {"publicKey": {"rp": {"id": "host"}}}


def test_complete_registration(make_user_dict, override_api_auth, mocker):
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")
    mocker.patch(
        "services.webauthn.complete_registration",
        return_value=CompleteRegistrationResponse(
            credential=_fake_passkey(),
            backup_codes=["c1", "c2"],
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/api/v1/account/passkeys/complete-registration",
        json={"name": "Laptop", "response": {"id": "x"}},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["credential"]["name"] == "Laptop"
    assert body["backup_codes"] == ["c1", "c2"]


def test_rename_passkey(make_user_dict, override_api_auth, mocker):
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")
    mocker.patch(
        "services.webauthn.rename_credential",
        return_value=_fake_passkey(name="Updated"),
    )

    client = TestClient(app)
    response = client.patch(
        "/api/v1/account/passkeys/abc",
        json={"name": "Updated"},
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Updated"


def test_rename_passkey_not_found(make_user_dict, override_api_auth, mocker):
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")
    mocker.patch(
        "services.webauthn.rename_credential",
        side_effect=NotFoundError(message="Passkey not found"),
    )

    client = TestClient(app)
    response = client.patch(
        "/api/v1/account/passkeys/abc",
        json={"name": "Updated"},
    )
    assert response.status_code == 404


def test_delete_passkey(make_user_dict, override_api_auth, mocker):
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")
    mocker.patch("services.webauthn.delete_credential", return_value=None)

    client = TestClient(app)
    response = client.delete("/api/v1/account/passkeys/abc")
    assert response.status_code == 204


def test_delete_passkey_not_found(make_user_dict, override_api_auth, mocker):
    user = make_user_dict(role="member")
    override_api_auth(user, level="user")
    mocker.patch(
        "services.webauthn.delete_credential",
        side_effect=NotFoundError(message="Passkey not found"),
    )

    client = TestClient(app)
    response = client.delete("/api/v1/account/passkeys/abc")
    assert response.status_code == 404


def test_list_passkeys_unauthenticated(test_tenant, test_tenant_host):
    """Without auth, the API returns 401."""
    client = TestClient(app)
    response = client.get(
        "/api/v1/account/passkeys",
        headers={"host": test_tenant_host},
    )
    assert response.status_code == 401


def test_begin_registration_rate_limited_returns_429(make_user_dict, override_api_auth, mocker):
    """POST /api/v1/account/passkeys/begin-registration returns 429 when rate limited."""
    from services.exceptions import RateLimitError

    user = make_user_dict(role="member")
    override_api_auth(user, level="user")
    mocker.patch(
        "routers.api.v1.account_passkeys.ratelimit.prevent",
        side_effect=RateLimitError(message="rate limited", limit=10, timespan=300, retry_after=300),
    )

    client = TestClient(app)
    response = client.post("/api/v1/account/passkeys/begin-registration")

    assert response.status_code == 429


def test_complete_registration_rate_limited_returns_429(make_user_dict, override_api_auth, mocker):
    """POST /api/v1/account/passkeys/complete-registration returns 429 when rate limited."""
    from services.exceptions import RateLimitError

    user = make_user_dict(role="member")
    override_api_auth(user, level="user")
    mocker.patch(
        "routers.api.v1.account_passkeys.ratelimit.prevent",
        side_effect=RateLimitError(message="rate limited", limit=10, timespan=300, retry_after=300),
    )

    client = TestClient(app)
    response = client.post(
        "/api/v1/account/passkeys/complete-registration",
        json={"name": "Laptop", "response": {"id": "x"}},
    )

    assert response.status_code == 429
