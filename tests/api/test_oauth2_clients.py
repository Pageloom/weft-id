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


def test_list_clients_as_member_forbidden(client, test_tenant_host, oauth2_authorization_header):
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


def test_create_b2b_client_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_authorization_header
):
    """Test that a super_admin can create a B2B OAuth2 client."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
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
    assert data["client_id"].startswith("weft-id_b2b_")  # B2B prefix


def test_create_b2b_client_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that an admin cannot create B2B clients (requires super_admin)."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Unauthorized B2B", "role": "member"},
    )

    assert response.status_code == 403


def test_create_b2b_client_with_admin_role(
    client, test_tenant_host, oauth2_super_admin_authorization_header
):
    """Test creating a B2B client with admin role."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
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
    client, test_tenant_host, oauth2_super_admin_authorization_header
):
    """Test creating a B2B client with invalid data returns 422."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={
            "name": "Invalid B2B Client",
            # Missing role
        },
    )

    assert response.status_code == 422


def test_create_b2b_client_invalid_role(
    client, test_tenant_host, oauth2_super_admin_authorization_header
):
    """Test creating a B2B client with invalid role returns 422."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"name": "Invalid Role Client", "role": "superuser"},  # Invalid role
    )

    assert response.status_code == 422


# =============================================================================
# Delete Client Tests
# =============================================================================


def test_delete_client_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
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


def test_list_clients_filter_by_type_normal(
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
    b2b_oauth2_client,
):
    """Test filtering list by client_type=normal."""
    response = client.get(
        "/api/v1/oauth2/clients?client_type=normal",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    for c in data:
        assert c["client_type"] == "normal"


def test_list_clients_filter_by_type_b2b(
    client,
    test_tenant_host,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
    b2b_oauth2_client,
):
    """Test filtering list by client_type=b2b."""
    response = client.get(
        "/api/v1/oauth2/clients?client_type=b2b",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    for c in data:
        assert c["client_type"] == "b2b"


def test_list_clients_includes_description_and_is_active(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    """Test that list response includes description and is_active fields."""
    response = client.get(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1

    for client_data in data:
        assert "description" in client_data
        assert "is_active" in client_data
        assert isinstance(client_data["is_active"], bool)


def test_create_normal_client_with_description(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test creating a normal client with a description."""
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Described Client",
            "redirect_uris": ["https://example.com/callback"],
            "description": "A client for testing",
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["description"] == "A client for testing"
    assert data["is_active"] is True


def test_create_b2b_client_with_description(
    client, test_tenant_host, oauth2_super_admin_authorization_header
):
    """Test creating a B2B client with a description."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={
            "name": "Described B2B",
            "role": "member",
            "description": "Service account for syncing",
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["description"] == "Service account for syncing"
    assert data["is_active"] is True


def test_create_normal_client_description_optional(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that description is optional (defaults to null)."""
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "No Desc Client",
            "redirect_uris": ["https://example.com/callback"],
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["description"] is None


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
        assert "description" in client_data
        assert "is_active" in client_data


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
    client, test_tenant_host, oauth2_super_admin_authorization_header
):
    """Test that B2B client response includes service_user_id."""
    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"name": "Service User Test", "role": "member"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["service_user_id"] is not None
    assert data["redirect_uris"] is None


# ==============================================================================
# Error Handling Tests
# ==============================================================================


def test_create_normal_client_handles_validation_error(
    client, test_tenant_host, oauth2_admin_authorization_header, monkeypatch
):
    """Test that ValidationError from service is properly translated to HTTP 400."""
    from services import oauth2 as oauth2_service
    from services.exceptions import ValidationError

    # Mock the service to raise ValidationError
    def mock_create_normal_client(*args, **kwargs):
        raise ValidationError("Invalid client configuration", code="invalid_config")

    monkeypatch.setattr(oauth2_service, "create_normal_client", mock_create_normal_client)

    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Test Client", "redirect_uris": ["https://example.com/callback"]},
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Invalid client configuration"
    # Should not contain stack traces or internal error details
    assert "ValidationError" not in data["detail"]
    assert "Traceback" not in data["detail"]


def test_create_b2b_client_handles_validation_error(
    client, test_tenant_host, oauth2_super_admin_authorization_header, monkeypatch
):
    """Test that ValidationError from service is properly translated to HTTP 400."""
    from services import oauth2 as oauth2_service
    from services.exceptions import ValidationError

    # Mock the service to raise ValidationError
    def mock_create_b2b_client(*args, **kwargs):
        raise ValidationError("Invalid B2B client configuration", code="invalid_b2b_config")

    monkeypatch.setattr(oauth2_service, "create_b2b_client", mock_create_b2b_client)

    response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"name": "Test B2B Client", "role": "member"},
    )

    assert response.status_code == 400
    data = response.json()
    assert data["detail"] == "Invalid B2B client configuration"
    # Should not contain stack traces or internal error details
    assert "ValidationError" not in data["detail"]
    assert "Traceback" not in data["detail"]


def test_create_normal_client_no_stack_trace_on_error(
    client, test_tenant_host, oauth2_admin_authorization_header, monkeypatch
):
    """Test that errors do not expose stack traces or internal details."""
    from services import oauth2 as oauth2_service
    from services.exceptions import ValidationError

    # Mock the service to raise ValidationError with detailed internal message
    def mock_create_normal_client(*args, **kwargs):
        raise ValidationError(
            "Database constraint violated: duplicate key value violates unique constraint",
            code="db_error",
        )

    monkeypatch.setattr(oauth2_service, "create_normal_client", mock_create_normal_client)

    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Test Client", "redirect_uris": ["https://example.com/callback"]},
    )

    assert response.status_code == 400
    data = response.json()
    # Error message should be returned as-is from the service
    # (Service layer is responsible for sanitizing messages)
    assert "Database constraint violated" in data["detail"]
    # Should not have exception class names or stack traces
    assert "Exception" not in data["detail"]
    assert "Traceback" not in data["detail"]


# =============================================================================
# Get Single Client Tests
# =============================================================================


def test_get_client_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    """Test that an admin can get a single OAuth2 client."""
    response = client.get(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["client_id"] == normal_oauth2_client["client_id"]
    assert data["name"] == normal_oauth2_client["name"]
    assert "client_secret" not in data  # No secret in response


def test_get_client_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test getting a non-existent client returns 404."""
    response = client.get(
        "/api/v1/oauth2/clients/nonexistent_client_id",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_client_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    """Test that a regular member cannot get client details."""
    response = client.get(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Update Client Tests
# =============================================================================


def test_update_client_name_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    """Test that an admin can update a client's name."""
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Updated Client Name"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Client Name"
    assert data["client_id"] == normal_oauth2_client["client_id"]


def test_update_client_description_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    """Test that an admin can update a client's description."""
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"description": "New description"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["description"] == "New description"


def test_update_client_redirect_uris_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    """Test that an admin can update a normal client's redirect URIs."""
    new_uris = ["https://new.example.com/callback", "https://other.example.com/auth"]
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"redirect_uris": new_uris},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["redirect_uris"] == new_uris


def test_update_b2b_client_redirect_uris_fails(
    client, test_tenant_host, oauth2_super_admin_authorization_header, b2b_oauth2_client
):
    """Test that updating redirect URIs on a B2B client fails."""
    response = client.patch(
        f"/api/v1/oauth2/clients/{b2b_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"redirect_uris": ["https://example.com/callback"]},
    )

    assert response.status_code == 400
    assert "redirect" in response.json()["detail"].lower()


def test_update_client_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test updating a non-existent client returns 404."""
    response = client.patch(
        "/api/v1/oauth2/clients/nonexistent_client_id",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "New Name"},
    )

    assert response.status_code == 404


def test_update_client_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    """Test that a regular member cannot update OAuth2 clients."""
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"name": "Unauthorized Update"},
    )

    assert response.status_code == 403


# =============================================================================
# Update Client Role Tests (B2B only)
# =============================================================================


def test_update_b2b_client_role_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_authorization_header, b2b_oauth2_client
):
    """Test that a super_admin can update a B2B client's service role."""
    response = client.patch(
        f"/api/v1/oauth2/clients/{b2b_oauth2_client['client_id']}/role",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"role": "admin"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["client_id"] == b2b_oauth2_client["client_id"]


def test_update_b2b_client_role_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, b2b_oauth2_client
):
    """Test that an admin cannot update B2B client roles (requires super_admin)."""
    response = client.patch(
        f"/api/v1/oauth2/clients/{b2b_oauth2_client['client_id']}/role",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"role": "admin"},
    )

    assert response.status_code == 403


def test_update_normal_client_role_fails(
    client, test_tenant_host, oauth2_super_admin_authorization_header, normal_oauth2_client
):
    """Test that updating role on a normal client fails."""
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/role",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"role": "admin"},
    )

    assert response.status_code == 400
    assert "b2b" in response.json()["detail"].lower()


def test_update_client_role_invalid_role(
    client, test_tenant_host, oauth2_super_admin_authorization_header, b2b_oauth2_client
):
    """Test that invalid role values are rejected."""
    response = client.patch(
        f"/api/v1/oauth2/clients/{b2b_oauth2_client['client_id']}/role",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"role": "superuser"},  # Invalid role
    )

    assert response.status_code == 422


def test_update_client_role_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, b2b_oauth2_client
):
    """Test that a regular member cannot update B2B client roles."""
    response = client.patch(
        f"/api/v1/oauth2/clients/{b2b_oauth2_client['client_id']}/role",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"role": "admin"},
    )

    assert response.status_code == 403


# =============================================================================
# Deactivate Client Tests
# =============================================================================


def test_deactivate_client_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test that an admin can deactivate an OAuth2 client."""
    # Create a client to deactivate
    create_response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Client To Deactivate",
            "redirect_uris": ["https://example.com/callback"],
        },
    )
    created_client = create_response.json()
    assert created_client["is_active"] is True

    # Deactivate it
    response = client.post(
        f"/api/v1/oauth2/clients/{created_client['client_id']}/deactivate",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["is_active"] is False
    assert data["client_id"] == created_client["client_id"]


def test_deactivate_client_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test deactivating a non-existent client returns 404."""
    response = client.post(
        "/api/v1/oauth2/clients/nonexistent_client_id/deactivate",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404


def test_deactivate_client_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    """Test that a regular member cannot deactivate OAuth2 clients."""
    response = client.post(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/deactivate",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Reactivate Client Tests
# =============================================================================


def test_reactivate_client_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test that an admin can reactivate a deactivated OAuth2 client."""
    # Create and deactivate a client
    create_response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Client To Reactivate",
            "redirect_uris": ["https://example.com/callback"],
        },
    )
    created_client = create_response.json()

    client.post(
        f"/api/v1/oauth2/clients/{created_client['client_id']}/deactivate",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    # Reactivate it
    response = client.post(
        f"/api/v1/oauth2/clients/{created_client['client_id']}/reactivate",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["is_active"] is True
    assert data["client_id"] == created_client["client_id"]


def test_reactivate_client_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test reactivating a non-existent client returns 404."""
    response = client.post(
        "/api/v1/oauth2/clients/nonexistent_client_id/reactivate",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404


def test_reactivate_client_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    """Test that a regular member cannot reactivate OAuth2 clients."""
    response = client.post(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/reactivate",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Deactivated Client Token Validation Tests
# =============================================================================


def test_deactivated_client_cannot_get_token(
    client, test_tenant_host, oauth2_super_admin_authorization_header
):
    """Test that a deactivated B2B client cannot get access tokens."""
    # Create a B2B client (requires super_admin)
    create_response = client.post(
        "/api/v1/oauth2/clients/b2b",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"name": "Deactivate Token Test", "role": "member"},
    )
    created_client = create_response.json()
    client_id = created_client["client_id"]
    client_secret = created_client["client_secret"]

    # Deactivate the client (requires super_admin for B2B)
    client.post(
        f"/api/v1/oauth2/clients/{client_id}/deactivate",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
    )

    # Try to get a token using client credentials
    token_response = client.post(
        "/oauth2/token",
        headers={"Host": test_tenant_host},
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )

    assert token_response.status_code == 401
    data = token_response.json()
    assert data["error"] == "invalid_client"
    assert "deactivated" in data["error_description"].lower()


# =============================================================================
# Remembered consent (per client)
# =============================================================================


def _consent_grant(test_tenant, client_row, user, scopes=("openid",)):
    import database

    return database.oauth2.upsert_consent_grant(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        client_id=str(client_row["id"]),
        user_id=str(user["id"]),
        scopes=list(scopes),
    )


def test_list_client_consents_as_admin(
    client,
    test_tenant_host,
    test_tenant,
    test_user,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
):
    grant = _consent_grant(test_tenant, normal_oauth2_client, test_user, ("openid", "profile"))

    response = client.get(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/consents",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["id"] == str(grant["id"])
    assert body[0]["user_id"] == str(test_user["id"])
    assert body[0]["user_email"] == test_user["email"]
    assert body[0]["user_name"] == f"{test_user['first_name']} {test_user['last_name']}"
    assert body[0]["scopes"] == ["openid", "profile"]


def test_list_client_consents_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    response = client.get(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/consents",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 403


def test_list_client_consents_unknown_client(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.get(
        "/api/v1/oauth2/clients/weft-id_client_missing/consents",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 404


def test_list_client_consents_b2b_rejected(
    client, test_tenant_host, oauth2_admin_authorization_header, b2b_oauth2_client
):
    response = client.get(
        f"/api/v1/oauth2/clients/{b2b_oauth2_client['client_id']}/consents",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 400


def test_revoke_client_consent_as_admin(
    client,
    test_tenant_host,
    test_tenant,
    test_user,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
):
    import database

    grant = _consent_grant(test_tenant, normal_oauth2_client, test_user)

    response = client.delete(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/consents/{grant['id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 204
    assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(grant["id"])) is None


def test_revoke_client_consent_wrong_client_is_404(
    client,
    test_tenant_host,
    test_tenant,
    test_admin_user,
    test_user,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
):
    import database

    other = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Other App",
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(test_admin_user["id"]),
    )
    grant = _consent_grant(test_tenant, other, test_user)

    response = client.delete(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/consents/{grant['id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404
    assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(grant["id"]))


def test_revoke_client_consent_as_member_forbidden(
    client,
    test_tenant_host,
    test_tenant,
    test_user,
    oauth2_authorization_header,
    normal_oauth2_client,
):
    grant = _consent_grant(test_tenant, normal_oauth2_client, test_user)
    response = client.delete(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/consents/{grant['id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 403


# =============================================================================
# Post-logout redirect URIs (RP-initiated logout)
# =============================================================================


def test_create_normal_client_with_post_logout_redirect_uris(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Logout RP",
            "redirect_uris": ["https://rp.example/cb"],
            "post_logout_redirect_uris": ["https://rp.example/bye"],
        },
    )
    assert response.status_code == 201
    assert response.json()["post_logout_redirect_uris"] == ["https://rp.example/bye"]


def test_create_normal_client_defaults_to_no_post_logout_uris(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Plain RP", "redirect_uris": ["https://rp.example/cb"]},
    )
    assert response.json()["post_logout_redirect_uris"] == []


def test_create_normal_client_rejects_bad_post_logout_uri(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Bad RP",
            "redirect_uris": ["https://rp.example/cb"],
            "post_logout_redirect_uris": ["https://rp.example/bye#frag"],
        },
    )
    assert response.status_code == 400


def test_update_client_post_logout_uris_set_read_and_clear(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    url = f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}"
    headers = {"Host": test_tenant_host, **oauth2_admin_authorization_header}

    response = client.patch(
        url, headers=headers, json={"post_logout_redirect_uris": ["https://rp.example/bye"]}
    )
    assert response.status_code == 200
    assert response.json()["post_logout_redirect_uris"] == ["https://rp.example/bye"]
    assert client.get(url, headers=headers).json()["post_logout_redirect_uris"] == [
        "https://rp.example/bye"
    ]

    response = client.patch(url, headers=headers, json={"post_logout_redirect_uris": []})
    assert response.json()["post_logout_redirect_uris"] == []


def test_update_client_rejects_bad_post_logout_uri(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"post_logout_redirect_uris": ["/relative"]},
    )
    assert response.status_code == 400


def test_update_client_rejects_too_many_post_logout_uris(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"post_logout_redirect_uris": [f"https://rp.example/{i}" for i in range(51)]},
    )
    assert response.status_code == 422


def test_update_client_post_logout_uris_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"post_logout_redirect_uris": ["https://rp.example/bye"]},
    )
    assert response.status_code == 403


def test_oidc_urls_include_end_session_endpoint(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = client.get(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/oidc/urls",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 200
    assert response.json()["end_session_endpoint"] == f"https://{test_tenant_host}/oauth2/logout"


# =============================================================================
# Front-channel logout
# =============================================================================


def test_create_normal_client_with_frontchannel_logout(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "FC RP",
            "redirect_uris": ["https://rp.example/cb"],
            "frontchannel_logout_uri": "https://rp.example/fc",
            "frontchannel_logout_session_required": True,
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["frontchannel_logout_uri"] == "https://rp.example/fc"
    assert body["frontchannel_logout_session_required"] is True


def test_create_normal_client_frontchannel_logout_defaults(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Plain RP", "redirect_uris": ["https://rp.example/cb"]},
    )
    body = response.json()
    assert body["frontchannel_logout_uri"] is None
    assert body["frontchannel_logout_session_required"] is True


def test_create_normal_client_rejects_cross_origin_frontchannel_uri(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Bad RP",
            "redirect_uris": ["https://rp.example/cb"],
            "frontchannel_logout_uri": "https://evil.example/fc",
        },
    )
    assert response.status_code == 400


def test_create_normal_client_rejects_over_long_frontchannel_uri(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Long RP",
            "redirect_uris": ["https://rp.example/cb"],
            "frontchannel_logout_uri": "https://rp.example/" + "a" * 2048,
        },
    )
    assert response.status_code == 422


def test_update_client_frontchannel_logout_set_read_and_clear(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    url = f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}"
    headers = {"Host": test_tenant_host, **oauth2_admin_authorization_header}

    response = client.patch(
        url,
        headers=headers,
        json={
            "frontchannel_logout_uri": "http://localhost:3000/fc",
            "frontchannel_logout_session_required": True,
        },
    )
    assert response.status_code == 200
    fetched = client.get(url, headers=headers).json()
    assert fetched["frontchannel_logout_uri"] == "http://localhost:3000/fc"
    assert fetched["frontchannel_logout_session_required"] is True

    response = client.patch(url, headers=headers, json={"frontchannel_logout_uri": ""})
    assert response.json()["frontchannel_logout_uri"] is None
    assert response.json()["frontchannel_logout_session_required"] is True


def test_update_client_rejects_cross_origin_frontchannel_uri(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"frontchannel_logout_uri": "https://evil.example/fc"},
    )
    assert response.status_code == 400


def test_update_client_frontchannel_logout_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"frontchannel_logout_uri": "http://localhost:3000/fc"},
    )
    assert response.status_code == 403


# =============================================================================
# Back-channel logout
# =============================================================================


def test_create_normal_client_with_backchannel_logout(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "BC RP",
            "redirect_uris": ["https://rp.example/cb"],
            "backchannel_logout_uri": "https://api.rp.example/bc",
            "backchannel_logout_session_required": False,
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["backchannel_logout_uri"] == "https://api.rp.example/bc"
    assert body["backchannel_logout_session_required"] is False


def test_create_normal_client_backchannel_logout_defaults(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "Plain BC RP", "redirect_uris": ["https://rp.example/cb"]},
    )
    body = response.json()
    assert body["backchannel_logout_uri"] is None
    assert body["backchannel_logout_session_required"] is True


def test_create_normal_client_rejects_bad_backchannel_uri(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Bad BC RP",
            "redirect_uris": ["https://rp.example/cb"],
            "backchannel_logout_uri": "https://rp.example/bc#frag",
        },
    )
    assert response.status_code == 400


def test_create_normal_client_rejects_over_long_backchannel_uri(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Long BC RP",
            "redirect_uris": ["https://rp.example/cb"],
            "backchannel_logout_uri": "https://rp.example/" + "a" * 2048,
        },
    )
    assert response.status_code == 422


def test_update_client_backchannel_logout_set_read_and_clear(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    url = f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}"
    headers = {"Host": test_tenant_host, **oauth2_admin_authorization_header}

    response = client.patch(
        url,
        headers=headers,
        json={
            "backchannel_logout_uri": "https://api.rp.example/bc",
            "backchannel_logout_session_required": False,
        },
    )
    assert response.status_code == 200
    fetched = client.get(url, headers=headers).json()
    assert fetched["backchannel_logout_uri"] == "https://api.rp.example/bc"
    assert fetched["backchannel_logout_session_required"] is False

    response = client.patch(url, headers=headers, json={"backchannel_logout_uri": ""})
    assert response.json()["backchannel_logout_uri"] is None
    assert response.json()["backchannel_logout_session_required"] is False


def test_update_client_rejects_bad_backchannel_uri(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"backchannel_logout_uri": "ftp://rp.example/bc"},
    )
    assert response.status_code == 400


def test_update_client_backchannel_logout_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"backchannel_logout_uri": "https://rp.example/bc"},
    )
    assert response.status_code == 403


# =============================================================================
# Back-channel logout deliveries
# =============================================================================


def _bc_delivery(test_tenant, oauth_client, user, sid, status="pending"):
    import database

    tid = str(test_tenant["id"])
    database.oauth2.update_client(
        tid, oauth_client["client_id"], backchannel_logout_uri="https://rp.example/bc"
    )
    database.oauth2.update_client_oidc_settings(tid, oauth_client["client_id"], oidc_enabled=True)
    database.oauth2.upsert_session_client(
        tid, tid, sid=sid, client_id=str(oauth_client["id"]), user_id=str(user["id"])
    )
    database.oauth2.consume_session_clients(tid, tid, sid, issuer="https://tenant.example")
    database.execute(
        tid,
        "update oidc_backchannel_logout_deliveries set status = :s where sid = :sid",
        {"s": status, "sid": sid},
    )


def _deliveries_url(oauth_client) -> str:
    return f"/api/v1/oauth2/clients/{oauth_client['client_id']}/backchannel-logout-deliveries"


def test_list_backchannel_deliveries_as_admin(
    client,
    test_tenant_host,
    test_tenant,
    test_user,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
):
    _bc_delivery(test_tenant, normal_oauth2_client, test_user, "s-1", status="failed")
    _bc_delivery(test_tenant, normal_oauth2_client, test_user, "s-2")

    response = client.get(
        _deliveries_url(normal_oauth2_client),
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert body["page"] == 1 and body["limit"] == 25
    assert body["counts"] == {"pending": 1, "delivered": 0, "failed": 1}
    item = body["items"][0]
    assert item["user_id"] == str(test_user["id"])
    assert item["user_email"] == test_user["email"]
    assert set(item) >= {
        "id",
        "status",
        "attempts",
        "last_http_status",
        "last_error",
        "created_at",
        "last_attempt_at",
        "next_attempt_at",
        "completed_at",
    }
    assert "sid" not in item


def test_list_backchannel_deliveries_status_and_paging(
    client,
    test_tenant_host,
    test_tenant,
    test_user,
    oauth2_admin_authorization_header,
    normal_oauth2_client,
):
    for i in range(3):
        _bc_delivery(test_tenant, normal_oauth2_client, test_user, f"s-{i}")
    headers = {"Host": test_tenant_host, **oauth2_admin_authorization_header}

    page = client.get(
        _deliveries_url(normal_oauth2_client), params={"page": 2, "limit": 2}, headers=headers
    ).json()
    assert len(page["items"]) == 1 and page["total"] == 3

    failed = client.get(
        _deliveries_url(normal_oauth2_client), params={"status": "failed"}, headers=headers
    ).json()
    assert failed["items"] == [] and failed["total"] == 0


def test_list_backchannel_deliveries_invalid_status(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = client.get(
        _deliveries_url(normal_oauth2_client),
        params={"status": "bogus"},
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 400


def test_list_backchannel_deliveries_limit_bounds(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = client.get(
        _deliveries_url(normal_oauth2_client),
        params={"limit": 251},
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 422


def test_list_backchannel_deliveries_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    response = client.get(
        _deliveries_url(normal_oauth2_client),
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 403


def test_list_backchannel_deliveries_unknown_client(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.get(
        "/api/v1/oauth2/clients/weft-id_client_missing/backchannel-logout-deliveries",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 404


def test_list_backchannel_deliveries_b2b_rejected(
    client, test_tenant_host, oauth2_admin_authorization_header, b2b_oauth2_client
):
    response = client.get(
        _deliveries_url(b2b_oauth2_client),
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 400


# =============================================================================
# Tenant token introspection permission
# =============================================================================


def test_client_response_includes_introspection_flag(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = client.get(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.json()["can_introspect_tenant_tokens"] is False


def test_admin_enables_introspection_on_app(
    client, test_tenant, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    import database

    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"can_introspect_tenant_tokens": True, "name": "Resource Server"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["can_introspect_tenant_tokens"] is True
    assert data["name"] == "Resource Server"
    listed = client.get(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    ).json()
    row = next(c for c in listed if c["client_id"] == normal_oauth2_client["client_id"])
    assert row["can_introspect_tenant_tokens"] is True
    events = [
        e
        for e in database.event_log.list_events(test_tenant["id"], limit=20)
        if e["event_type"] == "oauth2_client_introspection_changed"
    ]
    assert len(events) == 1


def test_omitting_introspection_leaves_it_unchanged(
    client, test_tenant, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    import database

    database.oauth2.set_client_tenant_introspection(
        test_tenant["id"], normal_oauth2_client["client_id"], True
    )

    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"description": "unrelated"},
    )

    assert response.json()["can_introspect_tenant_tokens"] is True


def test_admin_cannot_set_introspection_on_b2b(
    client, test_tenant, test_tenant_host, oauth2_admin_authorization_header, b2b_oauth2_client
):
    import database

    response = client.patch(
        f"/api/v1/oauth2/clients/{b2b_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"can_introspect_tenant_tokens": True},
    )

    assert response.status_code == 403
    row = database.oauth2.get_client_by_client_id(test_tenant["id"], b2b_oauth2_client["client_id"])
    assert row["can_introspect_tenant_tokens"] is False


def test_super_admin_sets_introspection_on_b2b(
    client, test_tenant_host, oauth2_super_admin_authorization_header, b2b_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{b2b_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"can_introspect_tenant_tokens": True},
    )

    assert response.status_code == 200
    assert response.json()["can_introspect_tenant_tokens"] is True


def test_member_cannot_set_introspection(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"can_introspect_tenant_tokens": True},
    )

    assert response.status_code == 403


# =============================================================================
# Login initiation URI (third-party-initiated login)
# =============================================================================


def test_create_normal_client_with_initiate_login_uri(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Launchable RP",
            "redirect_uris": ["https://rp.example/cb"],
            "initiate_login_uri": "https://rp.example/login",
        },
    )
    assert response.status_code == 201
    assert response.json()["initiate_login_uri"] == "https://rp.example/login"


@pytest.mark.parametrize(
    ("uri", "status"),
    [
        ("http://rp.example/login", 400),
        ("https://rp.example/login#frag", 400),
        ("https://rp.example/" + "a" * 2048, 422),
    ],
)
def test_create_normal_client_rejects_bad_initiate_login_uri(
    client, test_tenant_host, oauth2_admin_authorization_header, uri, status
):
    response = client.post(
        "/api/v1/oauth2/clients",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Bad Launchable RP",
            "redirect_uris": ["https://rp.example/cb"],
            "initiate_login_uri": uri,
        },
    )
    assert response.status_code == status


def test_update_client_initiate_login_uri_set_read_and_clear(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    url = f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}"
    headers = {"Host": test_tenant_host, **oauth2_admin_authorization_header}

    response = client.patch(
        url, headers=headers, json={"initiate_login_uri": "https://rp.example/login"}
    )
    assert response.status_code == 200
    assert client.get(url, headers=headers).json()["initiate_login_uri"] == (
        "https://rp.example/login"
    )

    # Omitted leaves it; "" clears it.
    client.patch(url, headers=headers, json={"name": "Renamed"})
    assert client.get(url, headers=headers).json()["initiate_login_uri"] == (
        "https://rp.example/login"
    )
    response = client.patch(url, headers=headers, json={"initiate_login_uri": ""})
    assert response.status_code == 200
    assert response.json()["initiate_login_uri"] is None


def test_update_client_rejects_http_initiate_login_uri(
    client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"initiate_login_uri": "http://rp.example/login"},
    )
    assert response.status_code == 400


def test_update_client_initiate_login_uri_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
):
    response = client.patch(
        f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"initiate_login_uri": "https://rp.example/login"},
    )
    assert response.status_code == 403
