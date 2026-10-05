"""Tests for the OIDC upstream connection API endpoints."""

import json
import uuid

import pytest


@pytest.fixture
def oauth2_super_admin_access_token(test_tenant, normal_oauth2_client, test_super_admin_user):
    import database

    refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
    )
    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
        parent_token_id=refresh_token_id,
    )
    yield access_token


@pytest.fixture
def oauth2_super_admin_header(oauth2_super_admin_access_token):
    return {"Authorization": f"Bearer {oauth2_super_admin_access_token}"}


@pytest.fixture
def sample_connection_data():
    return {
        "name": "Test OIDC",
        "provider_type": "generic",
        "issuer": "https://idp.example.com",
        "client_id": "client-123",
        "client_secret": "super-secret-value",
        "is_enabled": False,
    }


@pytest.fixture
def created_connection(client, test_tenant_host, oauth2_super_admin_header, sample_connection_data):
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_connection_data,
    )
    assert response.status_code == 201
    return response.json()


def test_list_connections_as_super_admin(client, test_tenant_host, oauth2_super_admin_header):
    response = client.get(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


def test_list_connections_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.get(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 403


def test_list_connections_unauthenticated(client, test_tenant_host):
    response = client.get(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host},
    )
    assert response.status_code == 401


def test_create_connection_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, sample_connection_data
):
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_connection_data,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test OIDC"
    assert data["provider_type"] == "generic"
    assert data["issuer"] == "https://idp.example.com"
    assert data["client_id"] == "client-123"
    assert data["client_secret_set"] is True
    assert "client_secret" not in data
    assert data["callback_url"].endswith(f"/auth/oidc/{data['id']}/callback")
    assert data["backchannel_logout_url"].endswith(f"/auth/oidc/{data['id']}/backchannel-logout")
    assert data["post_logout_redirect_uri"].endswith("/logout/complete")
    assert data["sign_out_at_idp"] is False
    assert data["end_session_endpoint"] is None


def test_create_connection_with_provider_sign_out(
    client, test_tenant_host, oauth2_super_admin_header, sample_connection_data
):
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            **sample_connection_data,
            "end_session_endpoint": "https://idp.example.com/logout",
            "sign_out_at_idp": True,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["end_session_endpoint"] == "https://idp.example.com/logout"
    assert data["sign_out_at_idp"] is True


def test_create_connection_invalid_provider_type(
    client, test_tenant_host, oauth2_super_admin_header, sample_connection_data
):
    sample_connection_data["provider_type"] = "invalid"
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_connection_data,
    )
    assert response.status_code == 422


def test_create_connection_multi_tenant_entra_refused(
    client, test_tenant_host, oauth2_super_admin_header
):
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            "name": "Entra",
            "provider_type": "entra",
            "entra_tenant_id": "organizations",
            "client_id": "client-123",
            "client_secret": "secret",
        },
    )
    assert response.status_code == 400
    assert "Multi-tenant Entra authorities" in response.text


def test_create_connection_missing_required_field(
    client, test_tenant_host, oauth2_super_admin_header
):
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"name": "No issuer"},
    )
    assert response.status_code == 422


def test_get_connection_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    response = client.get(
        f"/api/v1/oidc-upstream/connections/{created_connection['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == created_connection["id"]
    assert data["client_secret_set"] is True
    assert "client_secret" not in data


def test_get_connection_not_found(client, test_tenant_host, oauth2_super_admin_header):
    response = client.get(
        f"/api/v1/oidc-upstream/connections/{uuid.uuid4()}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 404


def test_update_connection_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    response = client.patch(
        f"/api/v1/oidc-upstream/connections/{created_connection['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"name": "Renamed"},
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Renamed"


def test_update_connection_turns_on_provider_sign_out(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    url = f"/api/v1/oidc-upstream/connections/{created_connection['id']}"
    headers = {"Host": test_tenant_host, **oauth2_super_admin_header}
    response = client.patch(
        url,
        headers=headers,
        json={"sign_out_at_idp": True, "end_session_endpoint": "https://idp.example.com/bye"},
    )
    assert response.status_code == 200
    assert response.json()["sign_out_at_idp"] is True
    assert response.json()["end_session_endpoint"] == "https://idp.example.com/bye"

    off = client.patch(url, headers=headers, json={"sign_out_at_idp": False})
    assert off.json()["sign_out_at_idp"] is False
    assert off.json()["end_session_endpoint"] == "https://idp.example.com/bye"


def test_update_connection_rejects_overlong_end_session_endpoint(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    response = client.patch(
        f"/api/v1/oidc-upstream/connections/{created_connection['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"end_session_endpoint": "https://idp.example.com/" + "x" * 2048},
    )
    assert response.status_code == 422


def test_delete_connection_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, sample_connection_data
):
    create_response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_connection_data,
    )
    connection_id = create_response.json()["id"]

    response = client.delete(
        f"/api/v1/oidc-upstream/connections/{connection_id}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 204

    get_response = client.get(
        f"/api/v1/oidc-upstream/connections/{connection_id}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert get_response.status_code == 404


def test_delete_enabled_connection_conflict(
    client, test_tenant_host, oauth2_super_admin_header, sample_connection_data
):
    sample_connection_data["is_enabled"] = True
    create_response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_connection_data,
    )
    connection_id = create_response.json()["id"]

    response = client.delete(
        f"/api/v1/oidc-upstream/connections/{connection_id}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 409


def test_enable_and_disable_connection(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    enable = client.post(
        f"/api/v1/oidc-upstream/connections/{created_connection['id']}/enable",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert enable.status_code == 200
    assert enable.json()["is_enabled"] is True

    disable = client.post(
        f"/api/v1/oidc-upstream/connections/{created_connection['id']}/disable",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert disable.status_code == 200
    assert disable.json()["is_enabled"] is False


def test_set_default_connection(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    response = client.post(
        f"/api/v1/oidc-upstream/connections/{created_connection['id']}/set-default",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 200
    assert response.json()["is_default"] is True


def test_enable_connection_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_connection
):
    response = client.post(
        f"/api/v1/oidc-upstream/connections/{created_connection['id']}/enable",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 403


def test_group_claim_fields_round_trip(
    client, test_tenant_host, oauth2_super_admin_header, sample_connection_data
):
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            **sample_connection_data,
            "group_claim_source": "groups",
            "group_claim_name_key": "displayName",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["group_claim_source"] == "groups"
    assert data["group_claim_name_key"] == "displayName"

    # None leaves the settings alone; an empty string clears them.
    response = client.patch(
        f"/api/v1/oidc-upstream/connections/{data['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"name": "Renamed"},
    )
    assert response.status_code == 200
    assert response.json()["group_claim_source"] == "groups"

    response = client.patch(
        f"/api/v1/oidc-upstream/connections/{data['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"group_claim_source": "", "group_claim_name_key": ""},
    )
    assert response.status_code == 200
    assert response.json()["group_claim_source"] is None
    assert response.json()["group_claim_name_key"] is None


def test_group_claim_name_key_length_bounded(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    response = client.patch(
        f"/api/v1/oidc-upstream/connections/{created_connection['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"group_claim_name_key": "k" * 101},
    )
    assert response.status_code == 422


# =============================================================================
# Test connection (discovery + key set)
# =============================================================================


class _FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_bytes(self):
        yield b"not json" if self._body is None else json.dumps(self._body).encode()


class _FakeClient:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url, **kwargs):
        return self._response


def _patch_idp(discovery, jwks):
    from unittest.mock import patch

    from tests.fixtures.oidc import load_fixture

    discovery_body = load_fixture("discovery") if discovery == 200 else None
    jwks_body = load_fixture("jwks") if jwks == 200 else None
    return (
        patch(
            "services.oidc_upstream.discovery.build_safe_client",
            return_value=_FakeClient(_FakeResponse(discovery, discovery_body)),
        ),
        patch(
            "services.oidc_upstream.jwks.build_safe_client",
            return_value=_FakeClient(_FakeResponse(jwks, jwks_body)),
        ),
    )


def test_test_connection_success(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    discovery, jwks = _patch_idp(200, 200)
    with discovery, jwks:
        response = client.post(
            f"/api/v1/oidc-upstream/connections/{created_connection['id']}/test",
            headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["token_endpoint"] == "https://idp.example.com/token"
    assert body["discovery_error"] is None


def test_test_connection_jwks_failure(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    discovery, jwks = _patch_idp(200, 500)
    with discovery, jwks:
        response = client.post(
            f"/api/v1/oidc-upstream/connections/{created_connection['id']}/test",
            headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        )
    assert response.status_code == 400
    assert "Key set (JWKS) failed" in str(response.json())


def test_test_connection_not_found(client, test_tenant_host, oauth2_super_admin_header):
    response = client.post(
        f"/api/v1/oidc-upstream/connections/{uuid.uuid4()}/test",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert response.status_code == 404


def test_test_connection_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_connection
):
    response = client.post(
        f"/api/v1/oidc-upstream/connections/{created_connection['id']}/test",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("provider_type", "issuer", "label"),
    [
        (
            "microsoft",
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
            "Microsoft (personal accounts)",
        ),
        ("linkedin", "https://www.linkedin.com/oauth", "LinkedIn"),
        ("gitlab", "https://gitlab.com", "GitLab"),
    ],
)
def test_create_social_preset_connection(
    client, test_tenant_host, oauth2_super_admin_header, provider_type, issuer, label
):
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            "name": f"{provider_type} sign-in",
            "provider_type": provider_type,
            "client_id": "client-123",
            "client_secret": "super-secret-value",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["provider_type"] == provider_type
    assert data["provider_label"] == label
    assert data["issuer"] == issuer
    assert data["correlation_claim"] == "sub"
    assert data["scopes"] == "openid profile email"

    listing = client.get(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    ).json()
    item = next(i for i in listing["items"] if i["id"] == data["id"])
    assert item["provider_label"] == label


def test_create_self_managed_gitlab(client, test_tenant_host, oauth2_super_admin_header):
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            "name": "Acme GitLab",
            "provider_type": "gitlab",
            "issuer": "https://gitlab.acme.example",
        },
    )
    assert response.status_code == 201
    assert response.json()["discovery_url"] is None


def test_create_unknown_provider_type_rejected(client, test_tenant_host, oauth2_super_admin_header):
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"name": "MySpace", "provider_type": "myspace"},
    )
    assert response.status_code == 422


def test_create_connection_with_show_on_login(
    client, test_tenant_host, oauth2_super_admin_header, sample_connection_data
):
    headers = {"Host": test_tenant_host, **oauth2_super_admin_header}
    response = client.post(
        "/api/v1/oidc-upstream/connections",
        headers=headers,
        json={**sample_connection_data, "show_on_login": True},
    )
    assert response.status_code == 201
    assert response.json()["show_on_login"] is True

    listed = client.get("/api/v1/oidc-upstream/connections", headers=headers).json()
    assert listed["items"][0]["show_on_login"] is True


def test_show_on_login_defaults_off_and_patches(
    client, test_tenant_host, oauth2_super_admin_header, created_connection
):
    assert created_connection["show_on_login"] is False
    url = f"/api/v1/oidc-upstream/connections/{created_connection['id']}"
    headers = {"Host": test_tenant_host, **oauth2_super_admin_header}

    on = client.patch(url, headers=headers, json={"show_on_login": True})
    assert on.status_code == 200
    assert on.json()["show_on_login"] is True
    assert client.get(url, headers=headers).json()["show_on_login"] is True

    off = client.patch(url, headers=headers, json={"show_on_login": False})
    assert off.json()["show_on_login"] is False
