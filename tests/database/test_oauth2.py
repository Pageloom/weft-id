"""Comprehensive tests for OAuth2 database layer operations.

This test file covers all OAuth2 client, authorization code, and token
operations for the database/oauth2.py module.
"""

import database
import oauth2
import psycopg
import pytest

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
    service_user = database.users.get_user_by_id(test_tenant["id"], client["service_user_id"])
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

    service_user = database.users.get_user_by_id(test_tenant["id"], client["service_user_id"])
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
    client = database.oauth2.get_client_by_client_id(test_tenant["id"], "nonexistent_client_id")

    assert client is None


def test_get_all_clients(test_tenant, normal_oauth2_client, b2b_oauth2_client):
    """Test listing all clients for a tenant."""
    clients = database.oauth2.get_all_clients(test_tenant["id"])

    assert len(clients) >= 2
    client_ids = [c["client_id"] for c in clients]
    assert normal_oauth2_client["client_id"] in client_ids
    assert b2b_oauth2_client["client_id"] in client_ids


def test_get_all_clients_filter_normal(test_tenant, normal_oauth2_client, b2b_oauth2_client):
    """Test filtering clients by type 'normal'."""
    clients = database.oauth2.get_all_clients(test_tenant["id"], client_type="normal")

    client_ids = [c["client_id"] for c in clients]
    assert normal_oauth2_client["client_id"] in client_ids
    assert b2b_oauth2_client["client_id"] not in client_ids
    # All returned clients should be normal type
    for c in clients:
        assert c["client_type"] == "normal"


def test_get_all_clients_filter_b2b(test_tenant, normal_oauth2_client, b2b_oauth2_client):
    """Test filtering clients by type 'b2b'."""
    clients = database.oauth2.get_all_clients(test_tenant["id"], client_type="b2b")

    client_ids = [c["client_id"] for c in clients]
    assert b2b_oauth2_client["client_id"] in client_ids
    assert normal_oauth2_client["client_id"] not in client_ids
    for c in clients:
        assert c["client_type"] == "b2b"


def test_get_all_clients_returns_description_and_is_active(test_tenant, normal_oauth2_client):
    """Test that get_all_clients returns description and is_active columns."""
    clients = database.oauth2.get_all_clients(test_tenant["id"])

    assert len(clients) >= 1
    client = next(c for c in clients if c["client_id"] == normal_oauth2_client["client_id"])
    assert "description" in client
    assert "is_active" in client
    assert client["is_active"] is True  # Default value


def test_get_all_clients_b2b_returns_service_role(test_tenant, b2b_oauth2_client):
    """Test that get_all_clients returns service_role for B2B clients via JOIN."""
    clients = database.oauth2.get_all_clients(test_tenant["id"], client_type="b2b")

    assert len(clients) >= 1
    client = next(c for c in clients if c["client_id"] == b2b_oauth2_client["client_id"])
    assert "service_role" in client
    assert client["service_role"] in ("member", "admin", "super_admin")


def test_create_normal_client_with_description(test_tenant, test_admin_user):
    """Test creating a normal client with a description."""
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Described App",
        redirect_uris=["https://example.com/callback"],
        created_by=test_admin_user["id"],
        description="A test application for integration testing",
    )

    assert client is not None
    assert client["description"] == "A test application for integration testing"
    assert client["is_active"] is True


def test_create_normal_client_without_description(test_tenant, test_admin_user):
    """Test creating a normal client without description defaults to None."""
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="No Description App",
        redirect_uris=["https://example.com/callback"],
        created_by=test_admin_user["id"],
    )

    assert client is not None
    assert client["description"] is None
    assert client["is_active"] is True


def test_create_b2b_client_with_description(test_tenant, test_admin_user):
    """Test creating a B2B client with a description."""
    client = database.oauth2.create_b2b_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Described B2B",
        role="member",
        created_by=test_admin_user["id"],
        description="B2B service for syncing data",
    )

    assert client is not None
    assert client["description"] == "B2B service for syncing data"
    assert client["is_active"] is True


def test_get_client_by_client_id_returns_new_columns(test_tenant, test_admin_user):
    """Test that get_client_by_client_id returns description and is_active."""
    created = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Columns Test App",
        redirect_uris=["https://example.com/callback"],
        created_by=test_admin_user["id"],
        description="Testing column retrieval",
    )

    client = database.oauth2.get_client_by_client_id(test_tenant["id"], created["client_id"])

    assert client is not None
    assert client["description"] == "Testing column retrieval"
    assert client["is_active"] is True


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
    deleted_count = database.oauth2.delete_client(test_tenant["id"], client["client_id"])

    assert deleted_count == 1

    # Verify deletion
    found_client = database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"])
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


def test_create_authorization_code_with_pkce_s256(test_tenant, normal_oauth2_client, test_user):
    """Test creating an authorization code with PKCE S256 challenge."""
    import base64
    import hashlib

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


def test_create_authorization_code_with_pkce_plain(test_tenant, normal_oauth2_client, test_user):
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


def test_validate_and_consume_code_success(test_tenant, normal_oauth2_client, test_user):
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
    assert result["reused"] is False

    # Code is marked consumed: a second redemption reports the reuse (the
    # service layer turns that into a rejection plus grant revocation).
    result2 = database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    assert result2 is not None
    assert result2["reused"] is True
    assert result2["id"] == result["id"]


def test_validate_and_consume_code_with_pkce_success(test_tenant, normal_oauth2_client, test_user):
    """Test PKCE code validation with correct verifier."""
    import base64
    import hashlib

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
    import base64
    import hashlib

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


def test_validate_and_consume_code_garbage_runs_no_argon2(
    test_tenant, normal_oauth2_client, test_user
):
    """DoS regression: a garbage code matches no lookup row, so Argon2 never runs
    (previously it ran once per live code for the client/redirect_uri)."""
    from unittest.mock import patch

    for _ in range(5):
        database.oauth2.create_authorization_code(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
            redirect_uri=normal_oauth2_client["redirect_uris"][0],
        )

    with patch("oauth2.verify_token_hash", wraps=oauth2.verify_token_hash) as spy:
        result = database.oauth2.validate_and_consume_code(
            tenant_id=test_tenant["id"],
            code="weft-id_auth_" + "0" * 64,
            client_id=normal_oauth2_client["id"],
            redirect_uri=normal_oauth2_client["redirect_uris"][0],
        )
    assert result is None
    assert spy.call_count == 0


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


def test_validate_and_consume_code_wrong_redirect_uri(test_tenant, normal_oauth2_client, test_user):
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


def test_create_access_token_linked_to_refresh(test_tenant, normal_oauth2_client, test_user):
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


def test_create_access_token_client_credentials(test_tenant, b2b_oauth2_client):
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
    # No scope was granted at issuance.
    assert result["scope"] is None


def test_validate_access_token_returns_granted_scope(test_tenant, normal_oauth2_client, test_user):
    """validate_token surfaces the persisted granted scope for userinfo gating."""
    token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        scope="openid profile email",
    )

    result = database.oauth2.validate_token(token, test_tenant["id"])

    assert result is not None
    assert result["scope"] == "openid profile email"


def test_validate_access_token_invalid(test_tenant):
    """Test validating an invalid access token."""
    result = database.oauth2.validate_token("invalid_token_12345", test_tenant["id"])

    assert result is None


def test_validate_access_token_requires_tenant_id():
    """Test that validate_token requires tenant_id for RLS."""
    result = database.oauth2.validate_token("any_token", tenant_id=None)

    assert result is None


def test_validate_access_token_runs_argon2_once(test_tenant, normal_oauth2_client, test_user):
    """DoS regression: validation must resolve one row via the indexed lookup
    digest and run Argon2 exactly once, not once per live token in the tenant."""
    from unittest.mock import patch

    tokens = [
        database.oauth2.create_access_token(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
        )
        for _ in range(5)
    ]

    with patch("oauth2.verify_token_hash", wraps=oauth2.verify_token_hash) as spy:
        result = database.oauth2.validate_token(tokens[2], test_tenant["id"])
    assert result is not None
    assert str(result["user_id"]) == str(test_user["id"])
    # One candidate row -> one Argon2 verification, regardless of live-token count.
    assert spy.call_count == 1


def test_validate_access_token_garbage_runs_no_argon2(test_tenant, normal_oauth2_client, test_user):
    """DoS regression: a garbage bearer matches no lookup row, so Argon2 never
    runs (previously it ran once per live token in the tenant)."""
    from unittest.mock import patch

    for _ in range(5):
        database.oauth2.create_access_token(
            tenant_id=test_tenant["id"],
            tenant_id_value=test_tenant["id"],
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
        )

    with patch("oauth2.verify_token_hash", wraps=oauth2.verify_token_hash) as spy:
        result = database.oauth2.validate_token("weft-id_access_" + "0" * 64, test_tenant["id"])
    assert result is None
    assert spy.call_count == 0


def test_access_token_lookup_column_is_sha256(test_tenant, normal_oauth2_client, test_user):
    """The stored token_lookup is the SHA-256 of the plaintext token."""
    token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )
    row = database.fetchone(
        test_tenant["id"],
        "select token_lookup from oauth2_tokens where token_lookup = :lookup",
        {"lookup": oauth2.token_lookup(token)},
    )
    assert row is not None
    assert row["token_lookup"] == oauth2.token_lookup(token)


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
    result = database.oauth2.validate_refresh_token(test_tenant["id"], token, other_client["id"])

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
    assert database.oauth2.validate_token(access_token, test_tenant["id"]) is None
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

    try:
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
        found = database.oauth2.get_client_by_client_id(test_tenant["id"], client2["client_id"])
        assert found is None

        # Tenant2 should not see tenant1's client
        found = database.oauth2.get_client_by_client_id(tenant2["id"], client1["client_id"])
        assert found is None

        # Each tenant should see only their own client
        tenant1_clients = database.oauth2.get_all_clients(test_tenant["id"])
        tenant1_client_ids = [c["client_id"] for c in tenant1_clients]
        assert client1["client_id"] in tenant1_client_ids
        assert client2["client_id"] not in tenant1_client_ids
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": tenant2["id"]},
        )


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

    try:
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
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": tenant2["id"]},
        )


def test_authorization_codes_isolated_by_tenant(test_tenant, normal_oauth2_client, test_user):
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

    try:
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
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": tenant2["id"]},
        )


def test_cross_tenant_token_validation_blocked(test_tenant, normal_oauth2_client, test_user):
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

    try:
        # Try to validate tenant1's token using tenant2's context
        result = database.oauth2.validate_token(token, tenant2["id"])

        assert result is None  # Should fail due to RLS
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": tenant2["id"]},
        )


# =============================================================================
# Code reuse detection, grant ids, and refresh token rotation (migration 0062)
# =============================================================================


def _grant_code(test_tenant, client_row, user):
    return database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=client_row["id"],
        user_id=user["id"],
        redirect_uri=client_row["redirect_uris"][0],
        scope="openid email",
    )


def _consume(test_tenant, client_row, code, **kw):
    return database.oauth2.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=client_row["id"],
        redirect_uri=client_row["redirect_uris"][0],
        **kw,
    )


def _issue_grant(test_tenant, client_row, user, grant_id):
    refresh, refresh_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=client_row["id"],
        user_id=user["id"],
        scope="openid email",
        grant_id=grant_id,
    )
    access = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=client_row["id"],
        user_id=user["id"],
        parent_token_id=refresh_id,
        scope="openid email",
        grant_id=grant_id,
    )
    return refresh, refresh_id, access


def test_consumed_code_is_kept_and_marked(test_tenant, normal_oauth2_client, test_user):
    code = _grant_code(test_tenant, normal_oauth2_client, test_user)
    result = _consume(test_tenant, normal_oauth2_client, code)
    row = database.fetchone(
        test_tenant["id"],
        "select consumed_at from oauth2_authorization_codes where id = :id",
        {"id": result["id"]},
    )
    assert row is not None
    assert row["consumed_at"] is not None


def test_reused_code_with_bad_pkce_is_invalid_not_reuse(
    test_tenant, normal_oauth2_client, test_user
):
    """Reuse is only reported for a redemption that would otherwise be valid,
    so a party without the PKCE verifier cannot trigger grant revocation."""
    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_challenge="verifier-of-sufficient-length-0123456789-abcdefghij",
        code_challenge_method="plain",
    )
    first = _consume(
        test_tenant,
        normal_oauth2_client,
        code,
        code_verifier="verifier-of-sufficient-length-0123456789-abcdefghij",
    )
    assert first is not None and first["reused"] is False
    assert _consume(test_tenant, normal_oauth2_client, code, code_verifier="wrong") is None


def test_expired_consumed_code_is_cleaned_up(test_tenant, normal_oauth2_client, test_user):
    code = _grant_code(test_tenant, normal_oauth2_client, test_user)
    result = _consume(test_tenant, normal_oauth2_client, code)
    database.execute(
        test_tenant["id"],
        "update oauth2_authorization_codes set expires_at = now() - interval '1 second' "
        "where id = :id",
        {"id": result["id"]},
    )
    assert database.oauth2.cleanup_expired_codes(test_tenant["id"]) >= 1
    assert _consume(test_tenant, normal_oauth2_client, code) is None


def test_tokens_carry_grant_id(test_tenant, normal_oauth2_client, test_user):
    code = _grant_code(test_tenant, normal_oauth2_client, test_user)
    grant_id = _consume(test_tenant, normal_oauth2_client, code)["id"]
    refresh, _, _ = _issue_grant(test_tenant, normal_oauth2_client, test_user, grant_id)

    data = database.oauth2.validate_refresh_token(
        test_tenant["id"], refresh, normal_oauth2_client["id"]
    )
    assert str(data["grant_id"]) == grant_id
    assert data["expires_at"] is not None
    rows = database.fetchall(
        test_tenant["id"],
        "select grant_id from oauth2_tokens where grant_id = :g",
        {"g": grant_id},
    )
    assert len(rows) == 2


def test_revoke_grant_tokens_only_touches_that_grant(test_tenant, normal_oauth2_client, test_user):
    grant_a = _consume(
        test_tenant, normal_oauth2_client, _grant_code(test_tenant, normal_oauth2_client, test_user)
    )["id"]
    grant_b = _consume(
        test_tenant, normal_oauth2_client, _grant_code(test_tenant, normal_oauth2_client, test_user)
    )["id"]
    _, _, access_a = _issue_grant(test_tenant, normal_oauth2_client, test_user, grant_a)
    _, _, access_b = _issue_grant(test_tenant, normal_oauth2_client, test_user, grant_b)

    assert database.oauth2.revoke_grant_tokens(test_tenant["id"], grant_a) == 2
    assert database.oauth2.validate_token(access_a, test_tenant["id"]) is None
    assert database.oauth2.validate_token(access_b, test_tenant["id"]) is not None


def test_revoke_grant_tokens_is_tenant_scoped(test_tenant, normal_oauth2_client, test_user):
    """RLS: revoking a grant id from another tenant's scope deletes nothing."""
    import uuid

    grant_id = _consume(
        test_tenant, normal_oauth2_client, _grant_code(test_tenant, normal_oauth2_client, test_user)
    )["id"]
    _, _, access = _issue_grant(test_tenant, normal_oauth2_client, test_user, grant_id)
    assert database.oauth2.revoke_grant_tokens(str(uuid.uuid4()), grant_id) == 0
    assert database.oauth2.validate_token(access, test_tenant["id"]) is not None


def _rotate(test_tenant, client_row, data):
    return database.oauth2.rotate_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        old_token_id=str(data["id"]),
        client_id=client_row["id"],
        user_id=str(data["user_id"]),
        scope=data["scope"],
        grant_id=str(data["grant_id"]) if data["grant_id"] else None,
        expires_at=data["expires_at"],
    )


def test_rotate_refresh_token(test_tenant, normal_oauth2_client, test_user):
    grant_id = _consume(
        test_tenant, normal_oauth2_client, _grant_code(test_tenant, normal_oauth2_client, test_user)
    )["id"]
    old_refresh, _, old_access = _issue_grant(
        test_tenant, normal_oauth2_client, test_user, grant_id
    )
    old = database.oauth2.validate_refresh_token(
        test_tenant["id"], old_refresh, normal_oauth2_client["id"]
    )

    new_refresh, new_id = _rotate(test_tenant, normal_oauth2_client, old)

    # Old token gone, new one valid with the same scope, grant, and expiry.
    assert (
        database.oauth2.validate_refresh_token(
            test_tenant["id"], old_refresh, normal_oauth2_client["id"]
        )
        is None
    )
    new = database.oauth2.validate_refresh_token(
        test_tenant["id"], new_refresh, normal_oauth2_client["id"]
    )
    assert str(new["id"]) == new_id
    assert new["scope"] == old["scope"]
    assert str(new["grant_id"]) == grant_id
    assert new["expires_at"] == old["expires_at"]
    assert str(new["user_id"]) == str(test_user["id"])

    # The old access token was re-parented, not cascade-deleted.
    assert database.oauth2.validate_token(old_access, test_tenant["id"]) is not None
    row = database.fetchone(
        test_tenant["id"],
        "select parent_token_id from oauth2_tokens where token_type = 'access' and grant_id = :g",
        {"g": grant_id},
    )
    assert str(row["parent_token_id"]) == new_id


def test_rotate_already_rotated_token_returns_none(test_tenant, normal_oauth2_client, test_user):
    refresh, _, _ = _issue_grant(test_tenant, normal_oauth2_client, test_user, None)
    data = database.oauth2.validate_refresh_token(
        test_tenant["id"], refresh, normal_oauth2_client["id"]
    )
    assert _rotate(test_tenant, normal_oauth2_client, data) is not None
    # A second rotation of the same (now deleted) token loses.
    assert _rotate(test_tenant, normal_oauth2_client, data) is None
    count = database.fetchone(
        test_tenant["id"],
        "select count(*) as n from oauth2_tokens where token_type = 'refresh' and client_id = :c",
        {"c": normal_oauth2_client["id"]},
    )
    assert count["n"] == 1


def test_rotate_legacy_token_without_grant(test_tenant, normal_oauth2_client, test_user):
    refresh, _, _ = _issue_grant(test_tenant, normal_oauth2_client, test_user, None)
    data = database.oauth2.validate_refresh_token(
        test_tenant["id"], refresh, normal_oauth2_client["id"]
    )
    assert data["grant_id"] is None
    new_refresh, _ = _rotate(test_tenant, normal_oauth2_client, data)
    new = database.oauth2.validate_refresh_token(
        test_tenant["id"], new_refresh, normal_oauth2_client["id"]
    )
    assert new["grant_id"] is None


# =============================================================================
# RP-initiated logout: sid on codes, post-logout redirect URIs on clients
# =============================================================================


def test_code_carries_sid(test_tenant, normal_oauth2_client, test_user):
    code = database.oauth2.create_authorization_code(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        scope="openid",
        sid="session-abc",
    )
    assert _consume(test_tenant, normal_oauth2_client, code)["sid"] == "session-abc"


def test_code_without_sid_returns_none(test_tenant, normal_oauth2_client, test_user):
    code = _grant_code(test_tenant, normal_oauth2_client, test_user)
    assert _consume(test_tenant, normal_oauth2_client, code)["sid"] is None


def test_new_client_has_no_post_logout_redirect_uris(test_tenant, normal_oauth2_client):
    assert normal_oauth2_client["post_logout_redirect_uris"] == []
    fetched = database.oauth2.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert fetched["post_logout_redirect_uris"] == []


def test_create_client_with_post_logout_redirect_uris(test_tenant, test_admin_user):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="Logout App",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        post_logout_redirect_uris=["https://rp.example/bye"],
    )
    assert client["post_logout_redirect_uris"] == ["https://rp.example/bye"]
    by_id = database.oauth2.get_client_by_id(test_tenant["id"], str(client["id"]))
    assert by_id["post_logout_redirect_uris"] == ["https://rp.example/bye"]


def test_update_sets_and_clears_post_logout_redirect_uris(test_tenant, normal_oauth2_client):
    client_id = normal_oauth2_client["client_id"]
    updated = database.oauth2.update_client(
        test_tenant["id"], client_id, post_logout_redirect_uris=["https://rp.example/bye"]
    )
    assert updated["post_logout_redirect_uris"] == ["https://rp.example/bye"]
    # Other fields untouched.
    assert updated["redirect_uris"] == normal_oauth2_client["redirect_uris"]

    cleared = database.oauth2.update_client(
        test_tenant["id"], client_id, post_logout_redirect_uris=[]
    )
    assert cleared["post_logout_redirect_uris"] == []


def test_update_without_post_logout_field_keeps_it(test_tenant, normal_oauth2_client):
    client_id = normal_oauth2_client["client_id"]
    database.oauth2.update_client(
        test_tenant["id"], client_id, post_logout_redirect_uris=["https://rp.example/bye"]
    )
    renamed = database.oauth2.update_client(test_tenant["id"], client_id, name="Renamed")
    assert renamed["post_logout_redirect_uris"] == ["https://rp.example/bye"]


def test_post_logout_redirect_uris_are_bounded(test_tenant, normal_oauth2_client):
    with pytest.raises(psycopg.errors.CheckViolation):
        database.oauth2.update_client(
            test_tenant["id"],
            normal_oauth2_client["client_id"],
            post_logout_redirect_uris=[f"https://rp.example/{i}" for i in range(51)],
        )


def test_client_listing_includes_post_logout_redirect_uris(test_tenant, normal_oauth2_client):
    rows = database.oauth2.get_all_clients(test_tenant["id"], client_type="normal")
    assert all("post_logout_redirect_uris" in row for row in rows)


# ============================================================================
# Front-channel logout: client columns and session-to-client records
# ============================================================================


def test_new_client_frontchannel_logout_defaults(test_tenant, normal_oauth2_client):
    assert normal_oauth2_client["frontchannel_logout_uri"] is None
    # iss/sid on by default (the spec's default is false; see migration 0064).
    assert normal_oauth2_client["frontchannel_logout_session_required"] is True


def test_create_client_with_frontchannel_logout(test_tenant, test_admin_user):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="FC",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        frontchannel_logout_uri="https://rp.example/fc",
        frontchannel_logout_session_required=True,
    )
    for row in (
        client,
        database.oauth2.get_client_by_client_id(test_tenant["id"], client["client_id"]),
        database.oauth2.get_client_by_id(test_tenant["id"], client["id"]),
    ):
        assert row["frontchannel_logout_uri"] == "https://rp.example/fc"
        assert row["frontchannel_logout_session_required"] is True


def test_update_sets_keeps_and_clears_frontchannel_logout(test_tenant, normal_oauth2_client):
    tid, cid = test_tenant["id"], normal_oauth2_client["client_id"]
    updated = database.oauth2.update_client(
        tid,
        cid,
        frontchannel_logout_uri="http://localhost:3000/fc",
        frontchannel_logout_session_required=True,
    )
    assert updated["frontchannel_logout_uri"] == "http://localhost:3000/fc"
    assert updated["frontchannel_logout_session_required"] is True

    kept = database.oauth2.update_client(tid, cid, name="Renamed")
    assert kept["frontchannel_logout_uri"] == "http://localhost:3000/fc"
    assert kept["frontchannel_logout_session_required"] is True

    cleared = database.oauth2.update_client(
        tid, cid, frontchannel_logout_uri="", frontchannel_logout_session_required=False
    )
    assert cleared["frontchannel_logout_uri"] is None
    assert cleared["frontchannel_logout_session_required"] is False


def test_client_listing_includes_frontchannel_logout(test_tenant, normal_oauth2_client):
    for client_type in (None, "normal"):
        rows = database.oauth2.get_all_clients(test_tenant["id"], client_type=client_type)
        assert all("frontchannel_logout_uri" in row for row in rows)


def test_session_client_upsert_and_delete(test_tenant, normal_oauth2_client, test_user):
    tid = test_tenant["id"]
    for _ in range(2):
        database.oauth2.upsert_session_client(
            tid, tid, sid="s-1", client_id=normal_oauth2_client["id"], user_id=test_user["id"]
        )
    database.oauth2.upsert_session_client(
        tid, tid, sid="s-2", client_id=normal_oauth2_client["id"], user_id=test_user["id"]
    )

    (row,) = database.oauth2.delete_session_clients(tid, "s-1")
    assert str(row["id"]) == str(normal_oauth2_client["id"])
    assert row["client_id"] == normal_oauth2_client["client_id"]
    assert str(row["user_id"]) == str(test_user["id"])
    assert {"frontchannel_logout_uri", "frontchannel_logout_session_required"} <= set(row)

    assert database.oauth2.delete_session_clients(tid, "s-1") == []
    assert len(database.oauth2.delete_session_clients(tid, "s-2")) == 1


def test_session_clients_cascade_with_the_client(test_tenant, normal_oauth2_client, test_user):
    tid = test_tenant["id"]
    database.oauth2.upsert_session_client(
        tid, tid, sid="s-1", client_id=normal_oauth2_client["id"], user_id=test_user["id"]
    )
    database.oauth2.delete_client(tid, normal_oauth2_client["client_id"])
    assert database.oauth2.delete_session_clients(tid, "s-1") == []


def test_session_clients_are_tenant_isolated(test_tenant, normal_oauth2_client, test_user):
    """Strict RLS: an UNSCOPED read sees nothing and an UNSCOPED write fails."""
    tid = test_tenant["id"]
    database.oauth2.upsert_session_client(
        tid, tid, sid="s-1", client_id=normal_oauth2_client["id"], user_id=test_user["id"]
    )
    assert database.fetchall(database.UNSCOPED, "select * from oidc_session_clients") == []
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        database.oauth2.upsert_session_client(
            database.UNSCOPED,
            tid,
            sid="s-2",
            client_id=normal_oauth2_client["id"],
            user_id=test_user["id"],
        )
    assert len(database.oauth2.delete_session_clients(tid, "s-1")) == 1
