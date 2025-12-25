"""Comprehensive tests for OAuth2 database layer operations.

This test file covers all OAuth2 client, authorization code, and token
operations for the database/oauth2.py module.
"""

import pytest
import database
import oauth2


# =============================================================================
# Client Operations Tests
# =============================================================================


def test_create_normal_client_success(test_tenant, test_admin_user):
    """Test creating a normal OAuth2 client for authorization code flow."""
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Test App",
        redirect_uris=["https://example.com/callback"],
        created_by=test_admin_user["id"],
    )

    assert client is not None
    assert client["name"] == "Test App"
    assert client["client_type"] == "normal"
    assert client["redirect_uris"] == ["https://example.com/callback"]
    assert client["service_user_id"] is None
    assert "client_id" in client
    assert "client_secret" in client  # Plain text secret returned once
    assert len(client["client_secret"]) > 20  # Should be a long random string


def test_create_normal_client_with_multiple_redirect_uris(test_tenant, test_admin_user):
    """Test creating a client with multiple redirect URIs."""
    redirect_uris = [
        "https://example.com/callback",
        "https://example.com/callback2",
        "http://localhost:3000/callback",
    ]

    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Multi-Redirect App",
        redirect_uris=redirect_uris,
        created_by=test_admin_user["id"],
    )

    assert client["redirect_uris"] == redirect_uris


def test_create_normal_client_generates_unique_credentials(test_tenant, test_admin_user):
    """Test that each client gets unique client_id and client_secret."""
    client1 = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="App 1",
        redirect_uris=["https://app1.com/callback"],
        created_by=test_admin_user["id"],
    )

    client2 = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="App 2",
        redirect_uris=["https://app2.com/callback"],
        created_by=test_admin_user["id"],
    )

    assert client1["client_id"] != client2["client_id"]
    assert client1["client_secret"] != client2["client_secret"]


def test_create_b2b_client_success(test_tenant, test_admin_user):
    """Test creating a B2B client for client credentials flow."""
    client = database.oauth2.create_b2b_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="B2B Service",
        role="member",
        created_by=test_admin_user["id"],
    )

    assert client is not None
    assert client["name"] == "B2B Service"
    assert client["client_type"] == "b2b"
    assert client["service_user_id"] is not None
    assert client["redirect_uris"] is None  # B2B clients don't use redirect URIs
    assert "client_secret" in client

    # Verify service user was created
    service_user = database.users.get_user_by_id(
        test_tenant["id"], client["service_user_id"]
    )
    assert service_user is not None
    assert service_user["first_name"] == "B2B Service"
    assert service_user["last_name"] == "Service Account"
    assert service_user["role"] == "member"


def test_create_b2b_client_with_admin_role(test_tenant, test_admin_user):
    """Test creating a B2B client with admin role."""
    client = database.oauth2.create_b2b_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Admin Service",
        role="admin",
        created_by=test_admin_user["id"],
    )

    service_user = database.users.get_user_by_id(
        test_tenant["id"], client["service_user_id"]
    )
    assert service_user["role"] == "admin"


def test_get_client_by_client_id_success(test_tenant, normal_oauth2_client):
    """Test retrieving a client by client_id."""
    client = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )

    assert client is not None
    assert str(client["id"]) == str(normal_oauth2_client["id"])
    assert client["client_id"] == normal_oauth2_client["client_id"]
    assert "client_secret_hash" in client  # Hash stored, not plain text
    assert "client_secret" not in client  # Plain text not in DB


def test_get_client_by_client_id_not_found(test_tenant):
    """Test getting a non-existent client."""
    client = database.oauth2.get_client_by_client_id(
        test_tenant["id"], "nonexistent_client_id"
    )

    assert client is None


def test_get_all_clients(test_tenant, normal_oauth2_client, b2b_oauth2_client):
    """Test listing all clients for a tenant."""
    clients = database.oauth2.get_all_clients(test_tenant["id"])

    assert len(clients) >= 2
    client_ids = [c["client_id"] for c in clients]
    assert normal_oauth2_client["client_id"] in client_ids
    assert b2b_oauth2_client["client_id"] in client_ids


def test_delete_client_success(test_tenant, test_admin_user):
    """Test deleting an OAuth2 client."""
    # Create a client to delete
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Delete Me",
        redirect_uris=["https://deleteme.com/callback"],
        created_by=test_admin_user["id"],
    )

    # Delete it
    deleted_count = database.oauth2.delete_client(
        test_tenant["id"], client["client_id"]
    )

    assert deleted_count == 1

    # Verify deletion
    found_client = database.oauth2.get_client_by_client_id(
        test_tenant["id"], client["client_id"]
    )
    assert found_client is None


def test_regenerate_client_secret(test_tenant, normal_oauth2_client):
    """Test regenerating a client secret."""
    old_secret = normal_oauth2_client["client_secret"]

    # Regenerate secret
    new_secret = database.oauth2.regenerate_client_secret(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )

    # New secret should be different
    assert new_secret != old_secret
    assert len(new_secret) > 20

    # Verify old secret no longer works
    client = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert not oauth2.verify_token_hash(old_secret, client["client_secret_hash"])

    # Verify new secret works
    assert oauth2.verify_token_hash(new_secret, client["client_secret_hash"])


def test_get_b2b_client_by_service_user(test_tenant, b2b_oauth2_client):
    """Test retrieving a B2B client by service user ID."""
    client = database.oauth2.get_b2b_client_by_service_user(
        test_tenant["id"], b2b_oauth2_client["service_user_id"]
    )

    assert client is not None
    assert str(client["id"]) == str(b2b_oauth2_client["id"])
    assert client["client_type"] == "b2b"


# =============================================================================
# Authorization Code Flow Tests
# =============================================================================


def test_create_authorization_code_success(test_tenant, normal_oauth2_client, test_user):
    """Test creating an authorization code."""
    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    assert code is not None
    assert len(code) > 20  # Should be a long random string


def test_create_authorization_code_with_pkce_s256(
    test_tenant, normal_oauth2_client, test_user
):
    """Test creating an authorization code with PKCE S256 challenge."""
    import hashlib
    import base64

    code_verifier = "test_verifier_" + "a" * 43  # Min 43 chars
    # S256: BASE64URL(SHA256(ASCII(code_verifier)))
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )

    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    assert code is not None


def test_create_authorization_code_with_pkce_plain(
    test_tenant, normal_oauth2_client, test_user
):
    """Test creating an authorization code with PKCE plain challenge."""
    code_verifier = "test_verifier_plain_method"
    code_challenge = code_verifier  # Plain method: challenge = verifier

    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_challenge=code_challenge,
        code_challenge_method="plain",
    )

    assert code is not None


def test_validate_and_consume_code_success(
    test_tenant, normal_oauth2_client, test_user
):
    """Test validating and consuming an authorization code."""
    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    # Validate and consume
    result = database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    assert result is not None
    assert str(result["user_id"]) == str(test_user["id"])
    assert str(result["tenant_id"]) == str(test_tenant["id"])

    # Code should be consumed (can't use twice)
    result2 = database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    assert result2 is None  # Already consumed


def test_validate_and_consume_code_with_pkce_success(
    test_tenant, normal_oauth2_client, test_user
):
    """Test PKCE code validation with correct verifier."""
    import hashlib
    import base64

    code_verifier = "test_verifier_" + "a" * 43
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )

    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    # Validate with correct verifier
    result = database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_verifier=code_verifier,
    )

    assert result is not None
    assert str(result["user_id"]) == str(test_user["id"])


def test_validate_and_consume_code_with_pkce_invalid_verifier(
    test_tenant, normal_oauth2_client, test_user
):
    """Test PKCE code validation fails with wrong verifier."""
    import hashlib
    import base64

    code_verifier = "test_verifier_" + "a" * 43
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )

    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    # Validate with wrong verifier
    result = database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_verifier="wrong_verifier",
    )

    assert result is None


def test_validate_and_consume_code_invalid_code(test_tenant, normal_oauth2_client):
    """Test validating an invalid authorization code."""
    result = database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code="invalid_code_12345",
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    assert result is None


def test_validate_and_consume_code_wrong_client(
    test_tenant, normal_oauth2_client, test_admin_user, test_user
):
    """Test code validation fails with wrong client."""
    # Create code for client 1
    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    # Create a different client
    other_client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Other Client",
        redirect_uris=["https://other.com/callback"],
        created_by=test_admin_user["id"],
    )

    # Try to use code with wrong client
    result = database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=other_client["id"],  # Wrong client
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    assert result is None


def test_validate_and_consume_code_wrong_redirect_uri(
    test_tenant, normal_oauth2_client, test_user
):
    """Test code validation fails with wrong redirect URI."""
    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    # Try to validate with wrong redirect_uri
    result = database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri="https://wrong-redirect.com/callback",  # Wrong URI
    )

    assert result is None


def test_cleanup_expired_codes(test_tenant, normal_oauth2_client, test_user):
    """Test cleanup of expired authorization codes."""
    # Note: We can't easily test expiration without waiting or mocking time
    # This test just verifies the function runs without error
    deleted_count = database.oauth2.cleanup_expired_codes(test_tenant["id"])
    assert deleted_count >= 0


# =============================================================================
# Token Operations Tests
# =============================================================================


def test_create_refresh_token_success(test_tenant, normal_oauth2_client, test_user):
    """Test creating a refresh token."""
    token, token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    assert token is not None
    assert len(token) > 20
    assert token_id is not None


def test_create_refresh_token_returns_tuple(test_tenant, normal_oauth2_client, test_user):
    """Test that create_refresh_token returns tuple of (token, token_id)."""
    result = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    assert isinstance(result, tuple)
    assert len(result) == 2
    token, token_id = result
    assert isinstance(token, str)
    assert token_id is not None


def test_create_access_token_success(test_tenant, normal_oauth2_client, test_user):
    """Test creating an access token."""
    token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    assert token is not None
    assert len(token) > 20


def test_create_access_token_linked_to_refresh(
    test_tenant, normal_oauth2_client, test_user
):
    """Test creating an access token linked to a refresh token."""
    refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        parent_token_id=refresh_token_id,
    )

    assert access_token is not None


def test_create_access_token_client_credentials(
    test_tenant, b2b_oauth2_client
):
    """Test creating a client credentials access token (24h expiry)."""
    token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=b2b_oauth2_client["id"],
        user_id=b2b_oauth2_client["service_user_id"],
        is_client_credentials=True,
    )

    assert token is not None
    # Can't easily verify 24h vs 1h expiry without checking DB


def test_validate_access_token_success(test_tenant, normal_oauth2_client, test_user):
    """Test validating a valid access token."""
    token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    result = database.oauth2.validate_token(token, test_tenant["id"])

    assert result is not None
    assert str(result["user_id"]) == str(test_user["id"])
    assert str(result["tenant_id"]) == str(test_tenant["id"])
    assert str(result["client_id"]) == str(normal_oauth2_client["id"])
    assert "expires_at" in result


def test_validate_access_token_invalid(test_tenant):
    """Test validating an invalid access token."""
    result = database.oauth2.validate_token("invalid_token_12345", test_tenant["id"])

    assert result is None


def test_validate_access_token_requires_tenant_id():
    """Test that validate_token requires tenant_id for RLS."""
    result = database.oauth2.validate_token("any_token", tenant_id=None)

    assert result is None


def test_validate_refresh_token_success(test_tenant, normal_oauth2_client, test_user):
    """Test validating a valid refresh token."""
    token, token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    result = database.oauth2.validate_refresh_token(
        test_tenant["id"], token, normal_oauth2_client["id"]
    )

    assert result is not None
    assert str(result["id"]) == str(token_id)
    assert str(result["user_id"]) == str(test_user["id"])
    assert str(result["tenant_id"]) == str(test_tenant["id"])


def test_validate_refresh_token_wrong_client(
    test_tenant, normal_oauth2_client, test_admin_user, test_user
):
    """Test refresh token validation fails with wrong client."""
    token, token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    # Create different client
    other_client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Other Client",
        redirect_uris=["https://other.com/callback"],
        created_by=test_admin_user["id"],
    )

    # Try to validate with wrong client
    result = database.oauth2.validate_refresh_token(
        test_tenant["id"], token, other_client["id"]
    )

    assert result is None


def test_revoke_all_client_tokens(test_tenant, normal_oauth2_client, test_user):
    """Test revoking all tokens for a client."""
    # Create some tokens
    refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        parent_token_id=refresh_token_id,
    )

    # Revoke all
    revoked_count = database.oauth2.revoke_all_client_tokens(
        test_tenant["id"], normal_oauth2_client["id"]
    )

    assert revoked_count >= 2  # At least refresh and access

    # Verify tokens no longer valid
    assert (
        database.oauth2.validate_token(access_token, test_tenant["id"]) is None
    )
    assert (
        database.oauth2.validate_refresh_token(
            test_tenant["id"], refresh_token, normal_oauth2_client["id"]
        )
        is None
    )


def test_cleanup_expired_tokens(test_tenant):
    """Test cleanup of expired tokens."""
    # Note: Can't easily test expiration without waiting or mocking time
    deleted_count = database.oauth2.cleanup_expired_tokens(test_tenant["id"])
    assert deleted_count >= 0


# =============================================================================
# Tenant Scoping (RLS) Tests
# =============================================================================


def test_clients_isolated_by_tenant(test_tenant, test_admin_user):
    """Test that OAuth2 clients are isolated by tenant (RLS)."""
    # Create a second tenant
    from uuid import uuid4

    tenant2_subdomain = f"tenant2-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
        {"subdomain": tenant2_subdomain, "name": "Tenant 2"},
    )
    tenant2 = database.fetchone(
        database.UNSCOPED,
        "SELECT id, subdomain, name FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": tenant2_subdomain},
    )

    # Create admin for tenant2
    admin2 = database.users.create_user(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        first_name="Admin",
        last_name="Two",
        email=f"admin2-{uuid4().hex[:8]}@example.com",
        role="super_admin",
    )

    # Create client in tenant1
    client1 = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Tenant 1 Client",
        redirect_uris=["https://tenant1.com/callback"],
        created_by=test_admin_user["id"],
    )

    # Create client in tenant2
    client2 = database.oauth2.create_normal_client(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        name="Tenant 2 Client",
        redirect_uris=["https://tenant2.com/callback"],
        created_by=admin2["user_id"],
    )

    # Tenant1 should not see tenant2's client
    found = database.oauth2.get_client_by_client_id(
        test_tenant["id"], client2["client_id"]
    )
    assert found is None

    # Tenant2 should not see tenant1's client
    found = database.oauth2.get_client_by_client_id(tenant2["id"], client1["client_id"])
    assert found is None

    # Each tenant should see only their own client
    tenant1_clients = database.oauth2.get_all_clients(test_tenant["id"])
    tenant1_client_ids = [c["client_id"] for c in tenant1_clients]
    assert client1["client_id"] in tenant1_client_ids
    assert client2["client_id"] not in tenant1_client_ids


def test_tokens_isolated_by_tenant(test_tenant, normal_oauth2_client, test_user):
    """Test that tokens are isolated by tenant (RLS)."""
    from uuid import uuid4

    # Create second tenant
    tenant2_subdomain = f"tenant2-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
        {"subdomain": tenant2_subdomain, "name": "Tenant 2"},
    )
    tenant2 = database.fetchone(
        database.UNSCOPED,
        "SELECT id, subdomain, name FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": tenant2_subdomain},
    )

    # Create user in tenant2
    user2 = database.users.create_user(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        first_name="User",
        last_name="Two",
        email=f"user2-{uuid4().hex[:8]}@example.com",
        role="member",
    )

    # Create client in tenant2
    admin2 = database.users.create_user(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        first_name="Admin",
        last_name="Two",
        email=f"admin2-{uuid4().hex[:8]}@example.com",
        role="super_admin",
    )

    client2 = database.oauth2.create_normal_client(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        name="Tenant 2 Client",
        redirect_uris=["https://tenant2.com/callback"],
        created_by=admin2["user_id"],
    )

    # Create token in tenant1
    token1 = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    # Create token in tenant2
    token2 = database.oauth2.create_access_token(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        client_id=client2["id"],
        user_id=user2["user_id"],
    )

    # Tenant1 should not validate tenant2's token
    result = database.oauth2.validate_token(token2, test_tenant["id"])
    assert result is None

    # Tenant2 should not validate tenant1's token
    result = database.oauth2.validate_token(token1, tenant2["id"])
    assert result is None


def test_authorization_codes_isolated_by_tenant(
    test_tenant, normal_oauth2_client, test_user
):
    """Test that authorization codes are isolated by tenant (RLS)."""
    from uuid import uuid4

    # Create second tenant
    tenant2_subdomain = f"tenant2-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
        {"subdomain": tenant2_subdomain, "name": "Tenant 2"},
    )
    tenant2 = database.fetchone(
        database.UNSCOPED,
        "SELECT id, subdomain, name FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": tenant2_subdomain},
    )

    # Create user and client in tenant2
    user2 = database.users.create_user(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        first_name="User",
        last_name="Two",
        email=f"user2-{uuid4().hex[:8]}@example.com",
        role="member",
    )

    admin2 = database.users.create_user(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        first_name="Admin",
        last_name="Two",
        email=f"admin2-{uuid4().hex[:8]}@example.com",
        role="super_admin",
    )

    client2 = database.oauth2.create_normal_client(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        name="Tenant 2 Client",
        redirect_uris=["https://tenant2.com/callback"],
        created_by=admin2["user_id"],
    )

    # Create code in tenant1
    code1 = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    # Create code in tenant2
    code2 = database.oauth2.create_authorization_code(
        tenant_id=tenant2["id"],
        tenant_id_value=tenant2["id"],
        client_id=client2["id"],
        user_id=user2["user_id"],
        redirect_uri=client2["redirect_uris"][0],
    )

    # Tenant1 should not validate tenant2's code
    result = database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code2,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )
    assert result is None

    # Tenant2 should not validate tenant1's code
    result = database.oauth2.validate_and_consume_code(
        tenant_id=tenant2["id"],
        code=code1,
        client_id=client2["id"],
        redirect_uri=client2["redirect_uris"][0],
    )
    assert result is None


def test_cross_tenant_token_validation_blocked(
    test_tenant, normal_oauth2_client, test_user
):
    """Test that cross-tenant token validation is blocked."""
    from uuid import uuid4

    # Create token in tenant1
    token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    # Create different tenant
    tenant2_subdomain = f"tenant2-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
        {"subdomain": tenant2_subdomain, "name": "Tenant 2"},
    )
    tenant2 = database.fetchone(
        database.UNSCOPED,
        "SELECT id, subdomain, name FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": tenant2_subdomain},
    )

    # Try to validate tenant1's token using tenant2's context
    result = database.oauth2.validate_token(token, tenant2["id"])

    assert result is None  # Should fail due to RLS
