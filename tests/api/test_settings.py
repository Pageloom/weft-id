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
    # Service layer returns specific validation message
    assert "dot" in response.json()["detail"].lower()


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


# =============================================================================
# Tenant Security - Certificate Lifetime
# =============================================================================


def test_get_tenant_security_includes_certificate_lifetime(
    client, test_tenant_host, oauth2_super_admin_header
):
    """GET includes max_certificate_lifetime_years field."""
    response = client.get(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert "max_certificate_lifetime_years" in data
    assert data["max_certificate_lifetime_years"] == 10  # Default


def test_update_certificate_lifetime_valid_values(
    client, test_tenant_host, oauth2_super_admin_header
):
    """PATCH accepts valid certificate lifetime values."""
    for years in [1, 2, 3, 5, 10]:
        response = client.patch(
            "/api/v1/settings/tenant-security",
            headers={"Host": test_tenant_host, **oauth2_super_admin_header},
            json={"max_certificate_lifetime_years": years},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["max_certificate_lifetime_years"] == years


def test_update_certificate_lifetime_invalid_value(
    client, test_tenant_host, oauth2_super_admin_header
):
    """PATCH rejects invalid certificate lifetime value with 422."""
    response = client.patch(
        "/api/v1/settings/tenant-security",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"max_certificate_lifetime_years": 4},  # Not in [1, 2, 3, 5, 10]
    )

    assert response.status_code == 422


# =============================================================================
# Domain-Group Links
# =============================================================================


@pytest.fixture
def domain_and_group(test_tenant, test_admin_user):
    """Create a privileged domain and group for link testing."""
    from uuid import uuid4

    import database

    unique = str(uuid4())[:8]
    domain_name = f"api-dgl-{unique}.example.com"

    domain_row = database.fetchone(
        test_tenant["id"],
        """
        insert into tenant_privileged_domains (tenant_id, domain, created_by)
        values (:tenant_id, :domain, :created_by) returning id
        """,
        {
            "tenant_id": str(test_tenant["id"]),
            "domain": domain_name,
            "created_by": str(test_admin_user["id"]),
        },
    )

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=f"API DGL Group {unique}",
        group_type="weftid",
        created_by=str(test_admin_user["id"]),
    )

    return {
        "domain_id": str(domain_row["id"]),
        "group_id": str(group["id"]),
        "domain_name": domain_name,
    }


def test_list_domain_group_links(
    client, test_tenant_host, oauth2_admin_authorization_header, domain_and_group
):
    """Admin can list group links for a domain."""
    domain_id = domain_and_group["domain_id"]

    response = client.get(
        f"/api/v1/settings/privileged-domains/{domain_id}/group-links",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_add_domain_group_link(
    client, test_tenant_host, oauth2_admin_authorization_header, domain_and_group
):
    """Admin can link a group to a domain."""
    domain_id = domain_and_group["domain_id"]
    group_id = domain_and_group["group_id"]

    response = client.post(
        f"/api/v1/settings/privileged-domains/{domain_id}/group-links",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"group_id": group_id},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["group_id"] == group_id
    assert data["domain_id"] == domain_id
    assert "id" in data


def test_delete_domain_group_link(
    client, test_tenant_host, oauth2_admin_authorization_header, domain_and_group
):
    """Admin can delete a domain-group link."""
    domain_id = domain_and_group["domain_id"]
    group_id = domain_and_group["group_id"]

    # Create a link first
    create_response = client.post(
        f"/api/v1/settings/privileged-domains/{domain_id}/group-links",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"group_id": group_id},
    )
    link_id = create_response.json()["id"]

    # Delete it
    response = client.delete(
        f"/api/v1/settings/privileged-domains/{domain_id}/group-links/{link_id}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 204


def test_domain_group_link_as_member_forbidden(
    client, test_tenant_host, oauth2_authorization_header, domain_and_group
):
    """Regular member cannot manage domain-group links."""
    domain_id = domain_and_group["domain_id"]

    # List
    response = client.get(
        f"/api/v1/settings/privileged-domains/{domain_id}/group-links",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 403

    # Create
    response = client.post(
        f"/api/v1/settings/privileged-domains/{domain_id}/group-links",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"group_id": domain_and_group["group_id"]},
    )
    assert response.status_code == 403


def test_domain_group_link_domain_not_found(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Operations on non-existent domain return 404."""
    fake_id = "00000000-0000-0000-0000-000000000000"

    response = client.get(
        f"/api/v1/settings/privileged-domains/{fake_id}/group-links",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 404


def test_privileged_domains_list_includes_linked_groups(
    client, test_tenant_host, oauth2_admin_authorization_header, domain_and_group
):
    """GET /privileged-domains returns linked_groups in each domain."""
    domain_id = domain_and_group["domain_id"]
    group_id = domain_and_group["group_id"]

    # Link a group
    client.post(
        f"/api/v1/settings/privileged-domains/{domain_id}/group-links",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"group_id": group_id},
    )

    # List domains
    response = client.get(
        "/api/v1/settings/privileged-domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    domain = next(d for d in data if d["id"] == domain_id)
    assert len(domain["linked_groups"]) == 1
    assert domain["linked_groups"][0]["group_id"] == group_id
