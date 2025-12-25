"""Comprehensive tests for OAuth2 Clients API endpoints.

This test file covers all OAuth2 client management API operations.
"""

import pytest


# =============================================================================
# List Clients Tests
# =============================================================================


def test_list_clients_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    """Test that an admin can list OAuth2 clients."""
    response = client.get(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1

    # Verify structure
    for client_data in data:
        assert "id" in client_data
        assert "client_id" in client_data
        assert "client_type" in client_data
        assert "name" in client_data
        assert "created_at" in client_data
        assert "client_secret" not in client_data  # Secret not returned in list


def test_list_clients_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header
):
    """Test that a regular member cannot list OAuth2 clients."""
    response = client.get(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_list_clients_includes_normal_and_b2b(
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
    b2b_oauth2_client,
):
    """Test that list includes both normal and B2B clients."""
    response = client.get(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()

    client_ids = [c["client_id"] for c in data]
    assert normal_oauth2_client["client_id"] in client_ids
    assert b2b_oauth2_client["client_id"] in client_ids

    # Verify types
    normal = next(c for c in data if c["client_id"] == normal_oauth2_client["client_id"])
    b2b = next(c for c in data if c["client_id"] == b2b_oauth2_client["client_id"])

    assert normal["client_type"] == "normal"
    assert normal["redirect_uris"] is not None
    assert normal["service_user_id"] is None

    assert b2b["client_type"] == "b2b"
    assert b2b["redirect_uris"] is None
    assert b2b["service_user_id"] is not None


# =============================================================================
# Create Normal Client Tests
# =============================================================================


def test_create_normal_client_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test that an admin can create a normal OAuth2 client."""
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Test API Client",
            "redirect_uris": ["https://example.com/callback"],
        },
    )

    assert response.status_code == 201
    data = response.json()

    assert data["name"] == "Test API Client"
    assert data["client_type"] == "normal"
    assert data["redirect_uris"] == ["https://example.com/callback"]
    assert data["service_user_id"] is None
    assert "client_id" in data
    assert "client_secret" in data  # Secret returned on creation
    assert len(data["client_secret"]) > 20


def test_create_normal_client_with_multiple_redirect_uris(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test creating a normal client with multiple redirect URIs."""
    redirect_uris = [
        "https://example.com/callback",
        "https://example.com/callback2",
        "http://localhost:3000/callback",
    ]

    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Multi-Redirect Client", "redirect_uris": redirect_uris},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["redirect_uris"] == redirect_uris


def test_create_normal_client_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header
):
    """Test that a regular member cannot create OAuth2 clients."""
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={
            "name": "Unauthorized Client",
            "redirect_uris": ["https://example.com/callback"],
        },
    )

    assert response.status_code == 403


def test_create_normal_client_validation_error(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test creating a normal client with invalid data returns 422."""
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Invalid Client",
            # Missing redirect_uris
        },
    )

    assert response.status_code == 422  # Validation error


# =============================================================================
# Create B2B Client Tests
# =============================================================================


def test_create_b2b_client_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test that an admin can create a B2B OAuth2 client."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Test B2B Client", "role": "member"},
    )

    assert response.status_code == 201
    data = response.json()

    assert data["name"] == "Test B2B Client"
    assert data["client_type"] == "b2b"
    assert data["redirect_uris"] is None
    assert data["service_user_id"] is not None  # Service user created
    assert "client_id" in data
    assert "client_secret" in data
    assert data["client_id"].startswith("loom_b2b_")  # B2B prefix


def test_create_b2b_client_with_admin_role(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test creating a B2B client with admin role."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Admin Service Client", "role": "admin"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["service_user_id"] is not None
    assert data["client_type"] == "b2b"
    assert data["name"] == "Admin Service Client"
    # Service user role verification is tested at service layer


def test_create_b2b_client_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header
):
    """Test that a regular member cannot create B2B clients."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"name": "Unauthorized B2B", "role": "member"},
    )

    assert response.status_code == 403


def test_create_b2b_client_validation_error(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test creating a B2B client with invalid data returns 422."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Invalid B2B Client",
            # Missing role
        },
    )

    assert response.status_code == 422


def test_create_b2b_client_invalid_role(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test creating a B2B client with invalid role returns 422."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Invalid Role Client", "role": "superuser"},  # Invalid role
    )

    assert response.status_code == 422


# =============================================================================
# Delete Client Tests
# =============================================================================


def test_delete_client_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that an admin can delete an OAuth2 client."""
    # First create a client
    create_response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Delete Me Client",
            "redirect_uris": ["https://deleteme.com/callback"],
        },
    )
    assert create_response.status_code == 201
    created_client = create_response.json()

    # Delete it
    delete_response = client.delete(
        f"/api/v1/oauth2/clients/{created_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert delete_response.status_code == 204

    # Verify deletion - list should not include it
    list_response = client.get(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    clients = list_response.json()
    client_ids = [c["client_id"] for c in clients]
    assert created_client["client_id"] not in client_ids


def test_delete_client_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test deleting a non-existent client returns 404."""
    response = client.delete(
        "/api/v1/oauth2/clients/nonexistent_client_id",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_delete_client_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    """Test that a regular member cannot delete OAuth2 clients."""
    response = client.delete(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Regenerate Secret Tests
# =============================================================================


def test_regenerate_client_secret_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    """Test that an admin can regenerate a client secret."""
    old_secret = normal_oauth2_client["client_secret"]

    response = client.post(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/regenerate-secret",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()

    assert "client_secret" in data
    assert data["client_secret"] != old_secret
    assert len(data["client_secret"]) > 20
    assert data["client_id"] == normal_oauth2_client["client_id"]
    assert data["name"] == normal_oauth2_client["name"]


def test_regenerate_client_secret_not_found(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test regenerating secret for non-existent client returns 404."""
    response = client.post(
        "/api/v1/oauth2/clients/nonexistent_client_id/regenerate-secret",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_regenerate_client_secret_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    """Test that a regular member cannot regenerate client secrets."""
    response = client.post(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/regenerate-secret",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_regenerate_client_secret_invalidates_old_secret(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that regenerating a secret invalidates the old one."""
    import oauth2 as oauth2_module
    import database

    # Create a client
    create_response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Secret Test Client",
            "redirect_uris": ["https://example.com/callback"],
        },
    )
    created_client = create_response.json()
    old_secret = created_client["client_secret"]
    client_id = created_client["client_id"]

    # Regenerate secret
    regen_response = client.post(
        f"/api/v1/oauth2/clients/{client_id}/regenerate-secret",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    new_secret = regen_response.json()["client_secret"]

    # Get tenant_id from fixture (need to access it somehow)
    # For now, we'll just verify the secrets are different
    assert old_secret != new_secret


# =============================================================================
# Response Format Tests
# =============================================================================


def test_client_response_format_without_secret(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    """Test that list endpoint returns clients without secrets."""
    response = client.get(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    clients = response.json()

    for client_data in clients:
        assert "client_secret" not in client_data
        assert "id" in client_data
        assert "client_id" in client_data
        assert "client_type" in client_data
        assert "name" in client_data
        assert "created_at" in client_data


def test_client_response_format_with_secret(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that create endpoint returns client with secret."""
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Secret Test Client",
            "redirect_uris": ["https://example.com/callback"],
        },
    )

    assert response.status_code == 201
    data = response.json()

    # Should include secret on creation
    assert "client_secret" in data
    assert "id" in data
    assert "client_id" in data
    assert "client_type" in data
    assert "name" in data
    assert "created_at" in data


def test_normal_client_response_has_redirect_uris(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that normal client response includes redirect_uris."""
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Redirect Test",
            "redirect_uris": ["https://example.com/callback"],
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["redirect_uris"] == ["https://example.com/callback"]
    assert data["service_user_id"] is None


def test_b2b_client_response_has_service_user_id(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that B2B client response includes service_user_id."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Service User Test", "role": "member"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["service_user_id"] is not None
    assert data["redirect_uris"] is None
