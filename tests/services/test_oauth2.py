"""Comprehensive tests for OAuth2 service layer functions.

This test file covers all OAuth2 service operations for the services/oauth2.py module.
Most functions are thin wrappers over database operations, so tests focus on:
- Correct passthrough behavior
- Event logging for client creation operations
- Return value formatting
"""

import database
from services import oauth2 as oauth2_service

# =============================================================================
# Client Operations Tests
# =============================================================================


def test_get_client_by_client_id_success(test_tenant, normal_oauth2_client):
    """Test retrieving a client by client_id."""
    result = oauth2_service.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )

    assert result is not None
    assert result["client_id"] == normal_oauth2_client["client_id"]
    assert result["name"] == normal_oauth2_client["name"]


def test_get_client_by_client_id_not_found(test_tenant):
    """Test getting a non-existent client returns None."""
    result = oauth2_service.get_client_by_client_id(test_tenant["id"], "nonexistent_client_id")

    assert result is None


def test_get_all_clients(test_tenant, normal_oauth2_client, b2b_oauth2_client):
    """Test listing all clients for a tenant."""
    result = oauth2_service.get_all_clients(test_tenant["id"])

    assert len(result) >= 2
    client_ids = [c["client_id"] for c in result]
    assert normal_oauth2_client["client_id"] in client_ids
    assert b2b_oauth2_client["client_id"] in client_ids


def test_get_all_clients_filter_normal(test_tenant, normal_oauth2_client, b2b_oauth2_client):
    """Test listing only normal clients."""
    result = oauth2_service.get_all_clients(test_tenant["id"], client_type="normal")

    client_types = {c["client_type"] for c in result}
    assert "normal" in client_types
    assert "b2b" not in client_types


def test_get_all_clients_filter_b2b(test_tenant, normal_oauth2_client, b2b_oauth2_client):
    """Test listing only B2B clients."""
    result = oauth2_service.get_all_clients(test_tenant["id"], client_type="b2b")

    client_types = {c["client_type"] for c in result}
    assert "b2b" in client_types
    assert "normal" not in client_types


def test_get_all_clients_includes_description_and_is_active(test_tenant, normal_oauth2_client):
    """Test that get_all_clients returns description and is_active fields."""
    result = oauth2_service.get_all_clients(test_tenant["id"])

    assert len(result) >= 1
    client = next(c for c in result if c["client_id"] == normal_oauth2_client["client_id"])
    assert "description" in client
    assert "is_active" in client
    assert client["is_active"] is True


def test_get_all_clients_includes_service_role(
    test_tenant, normal_oauth2_client, b2b_oauth2_client
):
    """Test that get_all_clients returns service_role from joined users table."""
    result = oauth2_service.get_all_clients(test_tenant["id"], client_type="b2b")

    assert len(result) >= 1
    b2b = next(c for c in result if c["client_id"] == b2b_oauth2_client["client_id"])
    assert "service_role" in b2b
    assert b2b["service_role"] == "admin"  # b2b_oauth2_client fixture uses admin role


def test_create_normal_client_success(test_tenant, test_admin_user):
    """Test creating a normal OAuth2 client."""
    result = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="Test Normal Client",
        redirect_uris=["https://example.com/callback"],
        created_by=test_admin_user["id"],
    )

    assert result is not None
    assert result["name"] == "Test Normal Client"
    assert result["client_type"] == "normal"
    assert result["redirect_uris"] == ["https://example.com/callback"]
    assert "client_secret" in result


def test_create_normal_client_with_description(test_tenant, test_admin_user):
    """Test creating a normal client with a description."""
    result = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="Described Client",
        redirect_uris=["https://example.com/callback"],
        created_by=test_admin_user["id"],
        description="My test app description",
    )

    assert result is not None
    assert result["description"] == "My test app description"


def test_create_normal_client_without_description(test_tenant, test_admin_user):
    """Test creating a normal client without description defaults to None."""
    result = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="No Desc Client",
        redirect_uris=["https://example.com/callback"],
        created_by=test_admin_user["id"],
    )

    assert result is not None
    assert result["description"] is None


def test_create_normal_client_returns_is_active(test_tenant, test_admin_user):
    """Test creating a normal client returns is_active field."""
    result = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="Active Client",
        redirect_uris=["https://example.com/callback"],
        created_by=test_admin_user["id"],
    )

    assert result is not None
    assert result["is_active"] is True


def test_create_normal_client_logs_event(test_tenant, test_admin_user):
    """Test that creating a normal client logs an event."""
    result = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="Event Test Client",
        redirect_uris=["https://example.com/callback"],
        created_by=test_admin_user["id"],
    )

    # Verify event logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert len(events) > 0
    assert events[0]["event_type"] == "oauth2_client_created"
    assert str(events[0]["artifact_id"]) == str(result["id"])
    assert events[0]["artifact_type"] == "oauth2_client"
    assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])
    assert events[0]["metadata"]["name"] == "Event Test Client"
    assert events[0]["metadata"]["type"] == "normal"
    assert events[0]["metadata"]["client_id"] == result["client_id"]


def test_create_b2b_client_success(test_tenant, test_admin_user):
    """Test creating a B2B OAuth2 client."""
    result = oauth2_service.create_b2b_client(
        tenant_id=test_tenant["id"],
        name="Test B2B Client",
        role="member",
        created_by=test_admin_user["id"],
    )

    assert result is not None
    assert result["name"] == "Test B2B Client"
    assert result["client_type"] == "b2b"
    assert result["service_user_id"] is not None
    assert "client_secret" in result


def test_create_b2b_client_with_description(test_tenant, test_admin_user):
    """Test creating a B2B client with a description."""
    result = oauth2_service.create_b2b_client(
        tenant_id=test_tenant["id"],
        name="Described B2B",
        role="member",
        created_by=test_admin_user["id"],
        description="Sync service for data pipeline",
    )

    assert result is not None
    assert result["description"] == "Sync service for data pipeline"


def test_create_b2b_client_returns_is_active(test_tenant, test_admin_user):
    """Test creating a B2B client returns is_active field."""
    result = oauth2_service.create_b2b_client(
        tenant_id=test_tenant["id"],
        name="Active B2B",
        role="member",
        created_by=test_admin_user["id"],
    )

    assert result is not None
    assert result["is_active"] is True


def test_create_b2b_client_logs_event(test_tenant, test_admin_user):
    """Test that creating a B2B client logs an event."""
    result = oauth2_service.create_b2b_client(
        tenant_id=test_tenant["id"],
        name="B2B Event Test",
        role="admin",
        created_by=test_admin_user["id"],
    )

    # Verify event logged
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert len(events) > 0
    assert events[0]["event_type"] == "oauth2_client_created"
    assert str(events[0]["artifact_id"]) == str(result["id"])
    assert events[0]["artifact_type"] == "oauth2_client"
    assert str(events[0]["actor_user_id"]) == str(test_admin_user["id"])
    assert events[0]["metadata"]["name"] == "B2B Event Test"
    assert events[0]["metadata"]["type"] == "b2b"
    assert events[0]["metadata"]["role"] == "admin"
    assert events[0]["metadata"]["client_id"] == result["client_id"]
    assert str(events[0]["metadata"]["service_user_id"]) == str(result["service_user_id"])


def test_delete_client_success(test_tenant, test_admin_user):
    """Test deleting an OAuth2 client."""
    # Create client to delete
    client = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="Delete Me",
        redirect_uris=["https://deleteme.com/callback"],
        created_by=test_admin_user["id"],
    )

    # Delete it
    deleted_count = oauth2_service.delete_client(
        test_tenant["id"], client["client_id"], test_admin_user["id"]
    )

    assert deleted_count == 1

    # Verify deletion
    found = oauth2_service.get_client_by_client_id(test_tenant["id"], client["client_id"])
    assert found is None


def test_delete_client_not_found(test_tenant, test_admin_user):
    """Test deleting a non-existent client returns 0."""
    deleted_count = oauth2_service.delete_client(
        test_tenant["id"], "nonexistent_client_id", test_admin_user["id"]
    )

    assert deleted_count == 0


def test_regenerate_client_secret(test_tenant, normal_oauth2_client, test_admin_user):
    """Test regenerating a client secret."""
    import oauth2

    old_secret = normal_oauth2_client["client_secret"]

    # Regenerate
    new_secret = oauth2_service.regenerate_client_secret(
        test_tenant["id"], normal_oauth2_client["client_id"], test_admin_user["id"]
    )

    assert new_secret != old_secret
    assert len(new_secret) > 20

    # Verify old secret no longer works
    client = oauth2_service.get_client_by_client_id(
        test_tenant["id"], normal_oauth2_client["client_id"]
    )
    assert not oauth2.verify_token_hash(old_secret, client["client_secret_hash"])
    assert oauth2.verify_token_hash(new_secret, client["client_secret_hash"])


# =============================================================================
# Authorization Code Operations Tests
# =============================================================================


def test_create_authorization_code_success(test_tenant, normal_oauth2_client, test_user):
    """Test creating an authorization code."""
    code = oauth2_service.create_authorization_code(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    assert code is not None
    assert isinstance(code, str)
    assert len(code) > 20


def test_create_authorization_code_with_pkce(test_tenant, normal_oauth2_client, test_user):
    """Test creating an authorization code with PKCE."""
    import base64
    import hashlib

    code_verifier = "test_verifier_" + "a" * 43
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )

    code = oauth2_service.create_authorization_code(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    assert code is not None
    assert isinstance(code, str)


def test_validate_and_consume_code_success(test_tenant, normal_oauth2_client, test_user):
    """Test validating and consuming an authorization code."""
    # Create code
    code = oauth2_service.create_authorization_code(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    # Validate and consume
    result = oauth2_service.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    assert result is not None
    assert str(result["user_id"]) == str(test_user["id"])
    assert str(result["tenant_id"]) == str(test_tenant["id"])


def test_validate_and_consume_code_with_pkce(test_tenant, normal_oauth2_client, test_user):
    """Test PKCE code validation."""
    import base64
    import hashlib

    code_verifier = "test_verifier_" + "a" * 43
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )

    # Create code with PKCE
    code = oauth2_service.create_authorization_code(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    # Validate with correct verifier
    result = oauth2_service.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
        code_verifier=code_verifier,
    )

    assert result is not None
    assert str(result["user_id"]) == str(test_user["id"])


def test_validate_and_consume_code_invalid(test_tenant, normal_oauth2_client):
    """Test validating an invalid code returns None."""
    result = oauth2_service.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code="invalid_code",
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    assert result is None


def test_validate_and_consume_code_single_use(test_tenant, normal_oauth2_client, test_user):
    """Test that authorization codes are single-use."""
    # Create code
    code = oauth2_service.create_authorization_code(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    # Use it once
    result1 = oauth2_service.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )
    assert result1 is not None

    # Try to use again
    result2 = oauth2_service.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=code,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )
    assert result2 is None


# =============================================================================
# Token Operations Tests
# =============================================================================


def test_create_refresh_token_success(test_tenant, normal_oauth2_client, test_user):
    """Test creating a refresh token."""
    token, token_id = oauth2_service.create_refresh_token(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    assert token is not None
    assert isinstance(token, str)
    assert len(token) > 20
    assert token_id is not None


def test_create_refresh_token_returns_tuple(test_tenant, normal_oauth2_client, test_user):
    """Test that create_refresh_token returns a tuple."""
    result = oauth2_service.create_refresh_token(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    assert isinstance(result, tuple)
    assert len(result) == 2


def test_create_access_token_success(test_tenant, normal_oauth2_client, test_user):
    """Test creating an access token."""
    token = oauth2_service.create_access_token(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    assert token is not None
    assert isinstance(token, str)
    assert len(token) > 20


def test_create_access_token_with_parent(test_tenant, normal_oauth2_client, test_user):
    """Test creating an access token linked to a refresh token."""
    # Create refresh token
    refresh_token, refresh_token_id = oauth2_service.create_refresh_token(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    # Create access token linked to it
    access_token = oauth2_service.create_access_token(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        parent_token_id=refresh_token_id,
    )

    assert access_token is not None
    assert isinstance(access_token, str)


def test_create_access_token_client_credentials(test_tenant, b2b_oauth2_client):
    """Test creating a client credentials access token."""
    token = oauth2_service.create_access_token(
        tenant_id=test_tenant["id"],
        client_id=b2b_oauth2_client["id"],
        user_id=b2b_oauth2_client["service_user_id"],
        is_client_credentials=True,
    )

    assert token is not None
    assert isinstance(token, str)


def test_validate_refresh_token_success(test_tenant, normal_oauth2_client, test_user):
    """Test validating a valid refresh token."""
    # Create token
    token, token_id = oauth2_service.create_refresh_token(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    # Validate it
    result = oauth2_service.validate_refresh_token(
        tenant_id=test_tenant["id"],
        token=token,
        client_id=normal_oauth2_client["id"],
    )

    assert result is not None
    assert str(result["id"]) == str(token_id)
    assert str(result["user_id"]) == str(test_user["id"])
    assert str(result["tenant_id"]) == str(test_tenant["id"])


def test_validate_refresh_token_invalid(test_tenant, normal_oauth2_client):
    """Test validating an invalid refresh token returns None."""
    result = oauth2_service.validate_refresh_token(
        tenant_id=test_tenant["id"],
        token="invalid_token",
        client_id=normal_oauth2_client["id"],
    )

    assert result is None


def test_validate_refresh_token_wrong_client(
    test_tenant, normal_oauth2_client, test_admin_user, test_user
):
    """Test refresh token validation fails with wrong client."""
    # Create token for client1
    token, token_id = oauth2_service.create_refresh_token(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
    )

    # Create different client
    other_client = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="Other Client",
        redirect_uris=["https://other.com/callback"],
        created_by=test_admin_user["id"],
    )

    # Try to validate with wrong client
    result = oauth2_service.validate_refresh_token(
        tenant_id=test_tenant["id"],
        token=token,
        client_id=other_client["id"],
    )

    assert result is None
