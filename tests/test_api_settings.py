"""Tests for Settings API endpoints."""

import pytest

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def oauth2_super_admin_access_token(test_tenant, normal_oauth2_client, test_super_admin_user):
    """Create an OAuth2 access token for a super_admin user."""
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
    """Create Authorization header for super_admin user."""
    return {"Authorization": f"Bearer {oauth2_super_admin_access_token}"}


# =============================================================================
# Privileged Domains - List
# =============================================================================


def test_list_privileged_domains_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can list privileged domains."""
    response = client.get(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_list_privileged_domains_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot list privileged domains."""
    response = client.get(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_list_privileged_domains_unauthenticated(client, test_tenant_host):
    """Unauthenticated request returns 401."""
    response = client.get(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


# =============================================================================
# Privileged Domains - Add
# =============================================================================


def test_add_privileged_domain_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can add a privileged domain."""
    response = client.post(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"domain": "example.com"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["domain"] == "example.com"
    assert "id" in data
    assert "created_at" in data


def test_add_privileged_domain_with_at_prefix(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Domain with @ prefix is normalized."""
    response = client.post(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"domain": "@test-domain.com"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["domain"] == "test-domain.com"


def test_add_privileged_domain_uppercase_normalized(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Domain is normalized to lowercase."""
    response = client.post(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"domain": "UPPERCASE.COM"},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["domain"] == "uppercase.com"


def test_add_privileged_domain_invalid_format(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Invalid domain format returns 400."""
    response = client.post(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"domain": "nodot"},
    )

    assert response.status_code == 400
    assert "Invalid domain format" in response.json()["detail"]


def test_add_privileged_domain_duplicate(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Duplicate domain returns 409."""
    # Add first time
    response1 = client.post(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"domain": "duplicate-test.com"},
    )
    assert response1.status_code == 201

    # Add again
    response2 = client.post(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"domain": "duplicate-test.com"},
    )
    assert response2.status_code == 409
    assert "already exists" in response2.json()["detail"]


def test_add_privileged_domain_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot add privileged domains."""
    response = client.post(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"domain": "forbidden.com"},
    )

    assert response.status_code == 403


# =============================================================================
# Privileged Domains - Delete
# =============================================================================


def test_delete_privileged_domain_as_admin(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin can delete a privileged domain."""
    # Create a domain first
    create_response = client.post(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"domain": "to-delete.com"},
    )
    assert create_response.status_code == 201
    domain_id = create_response.json()["id"]

    # Delete it
    delete_response = client.delete(
        f"/api/v1/settings/privileged-domains/{domain_id}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert delete_response.status_code == 204


def test_delete_privileged_domain_not_found(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Deleting non-existent domain returns 404."""
    import uuid

    fake_id = str(uuid.uuid4())
    response = client.delete(
        f"/api/v1/settings/privileged-domains/{fake_id}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 404


def test_delete_privileged_domain_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, oauth2_admin_authorization_header
):
    """Regular member cannot delete privileged domains."""
    # Create as admin
    create_response = client.post(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"domain": "member-cant-delete.com"},
    )
    domain_id = create_response.json()["id"]

    # Try to delete as member
    response = client.delete(
        f"/api/v1/settings/privileged-domains/{domain_id}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Tenant Security - Get
# =============================================================================


def test_get_tenant_security_as_super_admin(client, test_tenant_host, oauth2_super_admin_header):
    """Super admin can get tenant security settings."""
    response = client.get(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    # Check all expected fields are present
    assert "session_timeout_seconds" in data
    assert "persistent_sessions" in data
    assert "allow_users_edit_profile" in data
    assert "allow_users_add_emails" in data


def test_get_tenant_security_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin (not super_admin) cannot get tenant security settings."""
    response = client.get(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


def test_get_tenant_security_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header
):
    """Regular member cannot get tenant security settings."""
    response = client.get(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Tenant Security - Update
# =============================================================================


def test_update_tenant_security_as_super_admin(client, test_tenant_host, oauth2_super_admin_header):
    """Super admin can update tenant security settings."""
    response = client.patch(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            "session_timeout_seconds": 3600,
            "persistent_sessions": False,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["session_timeout_seconds"] == 3600
    assert data["persistent_sessions"] is False


def test_update_tenant_security_partial(client, test_tenant_host, oauth2_super_admin_header):
    """Partial update only changes specified fields."""
    # First set known state
    client.patch(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            "persistent_sessions": True,
            "allow_users_edit_profile": True,
        },
    )

    # Partial update - only change one field
    response = client.patch(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"allow_users_edit_profile": False},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["allow_users_edit_profile"] is False
    assert data["persistent_sessions"] is True  # Unchanged


def test_update_tenant_security_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Admin (not super_admin) cannot update tenant security settings."""
    response = client.patch(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"persistent_sessions": False},
    )

    assert response.status_code == 403


def test_update_tenant_security_invalid_timeout(
    client, test_tenant_host, oauth2_super_admin_header
):
    """Invalid session timeout returns 422."""
    response = client.patch(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"session_timeout_seconds": 0},  # Must be >= 1
    )

    assert response.status_code == 422
