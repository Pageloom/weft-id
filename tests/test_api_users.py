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
    """Test that promoting to admin requires super_admin (not just admin)."""
    response = client.patch(
        f"/api/v1/users/{test_user['id']}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        json={
            "role": "admin",
        },
    )

    assert response.status_code == 403
    assert "admin" in response.json()["detail"]


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


# =============================================================================
# User Email Management
# =============================================================================


def test_list_current_user_emails(client, test_tenant_host, oauth2_authorization_header):
    """Test listing current user's emails."""
    response = client.get(
        "/api/v1/users/me/emails",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert len(data["items"]) >= 1  # At least primary email


def test_add_email_to_current_user(client, test_tenant_host, oauth2_authorization_header):
    """Test adding an email to current user's account."""
    response = client.post(
        "/api/v1/users/me/emails",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
        json={"email": "newemail@test.example.com"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "newemail@test.example.com"
    assert data["is_primary"] is False
    assert data["verified_at"] is None


def test_add_duplicate_email_fails(
    client, test_tenant_host, oauth2_authorization_header, test_user
):
    """Test adding a duplicate email fails."""
    response = client.post(
        "/api/v1/users/me/emails",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
        json={"email": test_user["email"]},
    )

    assert response.status_code == 409


def test_delete_email_from_current_user(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test deleting a secondary email from current user's account."""
    import database

    # First add a secondary email
    result = database.user_emails.add_email(
        tenant_id=test_tenant["id"],
        user_id=test_user["id"],
        email="secondary@test.example.com",
        tenant_id_value=test_tenant["id"],
    )

    # Delete the email
    response = client.delete(
        f"/api/v1/users/me/emails/{result['id']}",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 204


def test_cannot_delete_primary_email(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test that deleting primary email fails."""
    import database

    # Get primary email (need to use list_user_emails to get the id)
    emails = database.user_emails.list_user_emails(test_tenant["id"], test_user["id"])
    primary = next((e for e in emails if e["is_primary"]), None)
    assert primary is not None, "User should have a primary email"

    response = client.delete(
        f"/api/v1/users/me/emails/{primary['id']}",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 400
    assert "primary" in response.json()["detail"].lower()


def test_set_primary_email(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test setting a verified email as primary."""
    import database

    # Add a verified secondary email
    result = database.user_emails.add_verified_email(
        tenant_id=test_tenant["id"],
        user_id=test_user["id"],
        email="newprimary@test.example.com",
        tenant_id_value=test_tenant["id"],
        is_primary=False,
    )

    # Set as primary
    response = client.post(
        f"/api/v1/users/me/emails/{result['id']}/set-primary",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["is_primary"] is True


def test_cannot_set_unverified_email_as_primary(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test that setting an unverified email as primary fails."""
    import database

    # Add an unverified secondary email
    result = database.user_emails.add_email(
        tenant_id=test_tenant["id"],
        user_id=test_user["id"],
        email="unverified@test.example.com",
        tenant_id_value=test_tenant["id"],
    )

    # Try to set as primary
    response = client.post(
        f"/api/v1/users/me/emails/{result['id']}/set-primary",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 400
    assert "unverified" in response.json()["detail"].lower()


def test_resend_email_verification(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test resending verification email."""
    import database

    # Add an unverified email
    result = database.user_emails.add_email(
        tenant_id=test_tenant["id"],
        user_id=test_user["id"],
        email="resendtest@test.example.com",
        tenant_id_value=test_tenant["id"],
    )

    # Resend verification
    response = client.post(
        f"/api/v1/users/me/emails/{result['id']}/resend-verification",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    assert "sent" in response.json()["message"].lower()


def test_verify_email(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test verifying an email address."""
    import database

    # Add an unverified email
    result = database.user_emails.add_email(
        tenant_id=test_tenant["id"],
        user_id=test_user["id"],
        email="verifytest@test.example.com",
        tenant_id_value=test_tenant["id"],
    )

    # Verify with correct nonce
    response = client.post(
        f"/api/v1/users/me/emails/{result['id']}/verify",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
        json={"nonce": result["verify_nonce"]},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["verified_at"] is not None


def test_verify_email_invalid_nonce(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test verifying with invalid nonce fails."""
    import database

    # Add an unverified email
    result = database.user_emails.add_email(
        tenant_id=test_tenant["id"],
        user_id=test_user["id"],
        email="badnonce@test.example.com",
        tenant_id_value=test_tenant["id"],
    )

    # Verify with wrong nonce
    response = client.post(
        f"/api/v1/users/me/emails/{result['id']}/verify",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
        json={"nonce": result["verify_nonce"] + 1},
    )

    assert response.status_code == 400


# =============================================================================
# Admin Email Management
# =============================================================================


def test_admin_list_user_emails(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test admin listing a user's emails."""
    response = client.get(
        f"/api/v1/users/{test_user['id']}/emails",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert "items" in data


def test_admin_add_email_to_user(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test admin adding an email to a user (pre-verified)."""
    response = client.post(
        f"/api/v1/users/{test_user['id']}/emails",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
        json={"email": "adminadded@test.example.com"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "adminadded@test.example.com"
    assert data["verified_at"] is not None  # Admin-added emails are pre-verified


def test_admin_delete_user_email(
    client, test_tenant_host, oauth2_admin_authorization_header, test_tenant, test_user
):
    """Test admin deleting a user's secondary email."""
    import database

    # Add a secondary email
    result = database.user_emails.add_verified_email(
        tenant_id=test_tenant["id"],
        user_id=test_user["id"],
        email="admindelete@test.example.com",
        tenant_id_value=test_tenant["id"],
        is_primary=False,
    )

    # Delete it
    response = client.delete(
        f"/api/v1/users/{test_user['id']}/emails/{result['id']}",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 204


def test_admin_set_user_primary_email(
    client, test_tenant_host, oauth2_admin_authorization_header, test_tenant, test_user
):
    """Test admin setting a user's primary email."""
    import database

    # Add a verified secondary email
    result = database.user_emails.add_verified_email(
        tenant_id=test_tenant["id"],
        user_id=test_user["id"],
        email="adminprimary@test.example.com",
        tenant_id_value=test_tenant["id"],
        is_primary=False,
    )

    # Set as primary
    response = client.post(
        f"/api/v1/users/{test_user['id']}/emails/{result['id']}/set-primary",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["is_primary"] is True


# =============================================================================
# User MFA Management
# =============================================================================


def test_get_mfa_status(client, test_tenant_host, oauth2_authorization_header):
    """Test getting current user's MFA status."""
    response = client.get(
        "/api/v1/users/me/mfa",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert "enabled" in data
    assert "method" in data
    assert "has_backup_codes" in data


def test_setup_totp(client, test_tenant_host, oauth2_authorization_header):
    """Test initiating TOTP setup."""
    response = client.post(
        "/api/v1/users/me/mfa/totp/setup",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert "secret" in data
    assert "uri" in data
    assert "otpauth://" in data["uri"]


def test_verify_totp_invalid_code(client, test_tenant_host, oauth2_authorization_header):
    """Test verifying TOTP with invalid code fails."""
    # First setup
    client.post(
        "/api/v1/users/me/mfa/totp/setup",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    # Verify with invalid code
    response = client.post(
        "/api/v1/users/me/mfa/totp/verify",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
        json={"code": "000000"},
    )

    assert response.status_code == 400


def test_enable_email_mfa(client, test_tenant_host, oauth2_authorization_header):
    """Test enabling email MFA."""
    response = client.post(
        "/api/v1/users/me/mfa/email/enable",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    # Either direct enable or pending verification
    assert "status" in data or "pending_verification" in data


def test_disable_mfa(client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user):
    """Test disabling MFA."""
    import database

    # First enable email MFA
    database.mfa.enable_mfa(test_tenant["id"], test_user["id"], "email")

    # Disable
    response = client.post(
        "/api/v1/users/me/mfa/disable",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["enabled"] is False


def test_get_backup_codes_status(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test getting backup codes status."""
    import database
    from utils.mfa import generate_backup_codes, hash_code

    # Enable MFA and create some backup codes
    database.mfa.enable_mfa(test_tenant["id"], test_user["id"], "email")
    codes = generate_backup_codes(5)
    for code in codes:
        database.mfa.create_backup_code(
            test_tenant["id"], test_user["id"], hash_code(code.replace("-", "")), test_tenant["id"]
        )

    response = client.get(
        "/api/v1/users/me/mfa/backup-codes",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert data["used"] == 0
    assert data["remaining"] == 5


def test_regenerate_backup_codes(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test regenerating backup codes."""
    import database

    # Enable MFA first
    database.mfa.enable_mfa(test_tenant["id"], test_user["id"], "email")

    response = client.post(
        "/api/v1/users/me/mfa/backup-codes/regenerate",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert "codes" in data
    assert len(data["codes"]) == 10  # Default count


def test_regenerate_backup_codes_requires_mfa(
    client, test_tenant_host, oauth2_authorization_header, test_tenant, test_user
):
    """Test that regenerating backup codes requires MFA enabled."""
    import database

    # Ensure MFA is disabled
    database.users.update_mfa_status(test_tenant["id"], test_user["id"], enabled=False)

    response = client.post(
        "/api/v1/users/me/mfa/backup-codes/regenerate",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 400


# =============================================================================
# Admin MFA Management
# =============================================================================


def test_admin_reset_user_mfa(
    client, test_tenant_host, oauth2_admin_authorization_header, test_tenant, test_user
):
    """Test admin resetting a user's MFA."""
    import database

    # Enable MFA for the user
    database.mfa.enable_mfa(test_tenant["id"], test_user["id"], "email")

    # Admin resets it
    response = client.post(
        f"/api/v1/users/{test_user['id']}/mfa/reset",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["enabled"] is False


# =============================================================================
# User State Management (Inactivate/Reactivate/Anonymize)
# =============================================================================


def test_inactivate_user_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test admin inactivating a user."""
    response = client.post(
        f"/api/v1/users/{test_user['id']}/inactivate",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["is_inactivated"] is True
    assert data["inactivated_at"] is not None


def test_inactivate_user_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, test_admin_user
):
    """Test that regular member cannot inactivate users."""
    response = client.post(
        f"/api/v1/users/{test_admin_user['id']}/inactivate",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 403


def test_inactivate_user_not_found(client, test_tenant_host, oauth2_admin_authorization_header):
    """Test inactivating non-existent user returns 404."""
    import uuid

    fake_id = str(uuid.uuid4())
    response = client.post(
        f"/api/v1/users/{fake_id}/inactivate",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 404


def test_reactivate_user_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test admin reactivating a user."""
    # First inactivate
    client.post(
        f"/api/v1/users/{test_user['id']}/inactivate",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    # Then reactivate
    response = client.post(
        f"/api/v1/users/{test_user['id']}/reactivate",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["is_inactivated"] is False


def test_reactivate_user_not_inactivated(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test reactivating a user that isn't inactivated returns 400."""
    response = client.post(
        f"/api/v1/users/{test_user['id']}/reactivate",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 400
    assert "not inactivated" in response.json()["detail"]


def test_reactivate_user_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, test_admin_user
):
    """Test that regular member cannot reactivate users."""
    response = client.post(
        f"/api/v1/users/{test_admin_user['id']}/reactivate",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 403


def test_anonymize_user_as_super_admin(
    client, test_tenant_host, test_super_admin_user, test_tenant, normal_oauth2_client, test_user
):
    """Test super_admin anonymizing a user."""
    import database

    # Create access token for super_admin
    _, refresh_token_id = database.oauth2.create_refresh_token(
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
        f"/api/v1/users/{test_user['id']}/anonymize",
        headers={"Authorization": f"Bearer {access_token}", "Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["is_anonymized"] is True
    assert data["anonymized_at"] is not None
    assert data["first_name"] == "[Anonymized]"


def test_anonymize_user_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, test_user
):
    """Test that regular admin cannot anonymize users (requires super_admin)."""
    response = client.post(
        f"/api/v1/users/{test_user['id']}/anonymize",
        headers={**oauth2_admin_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 403


def test_anonymize_user_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, test_admin_user
):
    """Test that regular member cannot anonymize users."""
    response = client.post(
        f"/api/v1/users/{test_admin_user['id']}/anonymize",
        headers={**oauth2_authorization_header, "Host": test_tenant_host},
    )

    assert response.status_code == 403
