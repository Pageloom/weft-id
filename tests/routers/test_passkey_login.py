"""Tests for routers.auth.passkey_login endpoints."""

from fastapi.testclient import TestClient
from main import app
from schemas.webauthn import BeginAuthenticationResponse


def _override_tenant(tenant_id):
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(tenant_id)


def test_begin_ineligible_returns_404(test_tenant, mocker):
    _override_tenant(test_tenant["id"])
    mocker.patch("services.webauthn.begin_authentication", return_value=None)

    client = TestClient(app)
    response = client.post(
        "/login/passkey/begin",
        json={"email": "ghost@example.com"},
    )
    assert response.status_code == 404
    assert response.json() == {"error": "not_eligible"}


def test_begin_happy_path_returns_options(test_tenant, mocker):
    _override_tenant(test_tenant["id"])
    mocker.patch(
        "services.webauthn.begin_authentication",
        return_value=BeginAuthenticationResponse(
            public_key={"rpId": "host", "challenge": "abc", "allowCredentials": []}
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/login/passkey/begin",
        json={"email": "user@example.com"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["publicKey"]["rpId"] == "host"
    assert body["publicKey"]["challenge"] == "abc"


def test_begin_rejects_missing_email(test_tenant):
    _override_tenant(test_tenant["id"])
    client = TestClient(app)
    response = client.post("/login/passkey/begin", json={})
    assert response.status_code == 422


def test_begin_rejects_long_email(test_tenant):
    _override_tenant(test_tenant["id"])
    client = TestClient(app)
    long_email = ("a" * 400) + "@example.com"
    response = client.post(
        "/login/passkey/begin",
        json={"email": long_email},
    )
    assert response.status_code == 422


def test_complete_happy_path(test_tenant, mocker):
    _override_tenant(test_tenant["id"])
    mocker.patch(
        "services.webauthn.complete_authentication",
        return_value="/dashboard",
    )

    client = TestClient(app)
    response = client.post(
        "/login/passkey/complete",
        json={
            "response": {
                "id": "abc",
                "rawId": "abc",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "x",
                    "authenticatorData": "y",
                    "signature": "z",
                },
            }
        },
    )
    assert response.status_code == 200
    assert response.json() == {"redirect_url": "/dashboard"}


def test_complete_validation_error_surfaces_code(test_tenant, mocker):
    from services.exceptions import ValidationError

    _override_tenant(test_tenant["id"])
    mocker.patch(
        "services.webauthn.complete_authentication",
        side_effect=ValidationError(message="bad", code="bad_signature"),
    )

    client = TestClient(app)
    response = client.post(
        "/login/passkey/complete",
        json={
            "response": {
                "id": "abc",
                "rawId": "abc",
                "type": "public-key",
                "response": {"clientDataJSON": "x", "authenticatorData": "y", "signature": "z"},
            }
        },
    )
    assert response.status_code == 400
    assert response.json() == {"error": "bad_signature"}


def test_complete_validation_error_clone_suspected(test_tenant, mocker):
    from services.exceptions import ValidationError

    _override_tenant(test_tenant["id"])
    mocker.patch(
        "services.webauthn.complete_authentication",
        side_effect=ValidationError(message="bad", code="clone_suspected"),
    )

    client = TestClient(app)
    response = client.post(
        "/login/passkey/complete",
        json={
            "response": {
                "id": "abc",
                "rawId": "abc",
                "type": "public-key",
                "response": {"clientDataJSON": "x", "authenticatorData": "y", "signature": "z"},
            }
        },
    )
    assert response.status_code == 400
    assert response.json() == {"error": "clone_suspected"}
