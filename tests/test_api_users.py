"""Tests for User Management API endpoints."""

# =============================================================================
# Roles
# =============================================================================


def test_list_roles_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Admin can list available roles."""
    response = client.get(
        "/api/v1/users/roles",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    assert response.json() == ["member", "admin", "super_admin"]


def test_list_roles_unauthorized(client, test_tenant_host, oauth2_authorization_header):
    """Regular member cannot list roles."""
    response = client.get(
        "/api/v1/users/roles",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# User List
# =============================================================================


def test_list_users_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test listing users as admin."""
    response = client.get(
        "/api/v1/users",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()

    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "limit" in data
    assert data["page"] == 1
    assert data["limit"] == 25
    assert data["total"] >= 1  # At least the admin user exists


def test_list_users_with_pagination(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test listing users with pagination parameters."""
    response = client.get(
        "/api/v1/users?page=1&limit=5",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["page"] == 1
    assert data["limit"] == 5


def test_list_users_unauthorized(client, test_tenant_host, oauth2_authorization_header):
    """Test that non-admin cannot list users."""
    response = client.get(
        "/api/v1/users",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 403


def test_get_user_as_admin(client, test_tenant_host, oauth2_admin_authorization_header, test_user):
    """Test getting a user's details as admin."""
    response = client.get(
        f"/api/v1/users/{test_user['id']}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["id"] == str(test_user["id"])
    assert data["first_name"] == test_user["first_name"]
    assert data["last_name"] == test_user["last_name"]
    assert "emails" in data
    assert "is_service_user" in data


def test_get_user_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test getting a non-existent user."""
    response = client.get(
        "/api/v1/users/00000000-0000-0000-0000-000000000000",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 404


def test_create_user_as_admin(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test creating a new user as admin."""
    response = client.post(
        "/api/v1/users",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@test.example.com",
            "role": "member",
        },
    )

    assert response.status_code == 201
    data = response.json()

    assert data["first_name"] == "New"
    assert data["last_name"] == "User"
    assert data["role"] == "member"
    assert len(data["emails"]) == 1
    assert data["emails"][0]["email"] == "newuser@test.example.com"
    assert data["emails"][0]["is_primary"] is True


def test_create_user_duplicate_email(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test creating a user with duplicate email."""
    response = client.post(
        "/api/v1/users",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        json={
            "first_name": "Duplicate",
            "last_name": "User",
            "email": test_user["email"],  # Already exists
            "role": "member",
        },
    )

    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]


def test_create_user_as_super_admin_with_super_admin_role(
    client, test_tenant_host, test_super_admin_user, test_tenant, normal_oauth2_client
):
    """Test that super_admin can create users with super_admin role."""
    import database

    # Create access token for super_admin
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

    response = client.post(
        "/api/v1/users",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Host": test_tenant_host,
        },
        json={
            "first_name": "New",
            "last_name": "SuperAdmin",
            "email": "newsuperadmin@test.example.com",
            "role": "super_admin",
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["role"] == "super_admin"


def test_create_user_admin_cannot_create_super_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Test that regular admin cannot create users with super_admin role."""
    response = client.post(
        "/api/v1/users",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        json={
            "first_name": "New",
            "last_name": "SuperAdmin",
            "email": "cannotcreate@test.example.com",
            "role": "super_admin",
        },
    )

    assert response.status_code == 403
    assert "Only super_admin" in response.json()["detail"]


def test_update_user_name(client, test_tenant_host, oauth2_admin_authorization_header, test_user):
    """Test updating a user's name."""
    response = client.patch(
        f"/api/v1/users/{test_user['id']}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        json={
            "first_name": "Updated",
            "last_name": "Name",
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["first_name"] == "Updated"
    assert data["last_name"] == "Name"


def test_update_user_role_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test updating a user's role from member to admin."""
    response = client.patch(
        f"/api/v1/users/{test_user['id']}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        json={
            "role": "admin",
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["role"] == "admin"


def test_update_user_role_to_super_admin_requires_super_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test that promoting to super_admin requires super_admin."""
    response = client.patch(
        f"/api/v1/users/{test_user['id']}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        json={
            "role": "super_admin",
        },
    )

    assert response.status_code == 403
    assert "super_admin" in response.json()["detail"]


def test_delete_user(client, test_tenant_host, oauth2_admin_authorization_header, test_tenant):
    """Test deleting a user."""
    import database

    # Create a user to delete
    result = database.users.create_user(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        first_name="Delete",
        last_name="Me",
        email="deleteme@test.example.com",
        role="member",
    )
    user_id = result["user_id"]

    # Add email
    database.user_emails.add_verified_email(
        tenant_id=test_tenant["id"],
        user_id=user_id,
        email="deleteme@test.example.com",
        tenant_id_value=test_tenant["id"],
        is_primary=True,
    )

    # Delete the user
    response = client.delete(
        f"/api/v1/users/{user_id}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 204

    # Verify user is deleted
    get_response = client.get(
        f"/api/v1/users/{user_id}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )
    assert get_response.status_code == 404


def test_delete_user_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test deleting a non-existent user."""
    response = client.delete(
        "/api/v1/users/00000000-0000-0000-0000-000000000000",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 404


def test_delete_service_user_fails(
    client, test_tenant_host, oauth2_admin_authorization_header, b2b_oauth2_client
):
    """Test that deleting a service user fails."""
    response = client.delete(
        f"/api/v1/users/{b2b_oauth2_client['service_user_id']}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 400
    assert "service user" in response.json()["detail"].lower()


def test_delete_self_fails(
    client, test_tenant_host, oauth2_admin_authorization_header, test_admin_user
):
    """Test that deleting yourself fails."""
    response = client.delete(
        f"/api/v1/users/{test_admin_user['id']}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 400
    assert "own account" in response.json()["detail"]
