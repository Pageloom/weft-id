"""Tests for the OIDC upstream connection API endpoints."""

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
