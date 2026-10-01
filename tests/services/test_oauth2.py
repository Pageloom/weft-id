"""Comprehensive tests for OAuth2 service layer functions.

This test file covers all OAuth2 service operations for the services/oauth2.py module.
Most functions are thin wrappers over database operations, so tests focus on:
- Correct passthrough behavior
- Event logging for client creation operations
- Return value formatting
"""

import database
import pytest
from services import oauth2 as oauth2_service
from services.exceptions import ValidationError

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


def test_reused_code_revokes_grant_and_logs(test_tenant, normal_oauth2_client, test_user, mocker):
    """A second redemption returns None, deletes the grant's tokens, and logs."""
    code = oauth2_service.create_authorization_code(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )
    kwargs = {
        "tenant_id": test_tenant["id"],
        "code": code,
        "client_id": normal_oauth2_client["id"],
        "redirect_uri": normal_oauth2_client["redirect_uris"][0],
    }
    first = oauth2_service.validate_and_consume_code(**kwargs)
    assert first is not None
    assert "reused" not in first
    access = oauth2_service.create_access_token(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        grant_id=first["id"],
    )

    log = mocker.patch("services.oauth2.log_event")
    assert oauth2_service.validate_and_consume_code(**kwargs) is None

    assert database.oauth2.validate_token(access, test_tenant["id"]) is None
    log.assert_called_once()
    assert log.call_args.kwargs["event_type"] == "oauth2_authorization_code_reused"
    assert log.call_args.kwargs["metadata"] == {"grant_id": first["id"], "tokens_revoked": 1}


def test_first_redemption_logs_nothing(test_tenant, normal_oauth2_client, test_user, mocker):
    code = oauth2_service.create_authorization_code(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )
    log = mocker.patch("services.oauth2.log_event")
    assert (
        oauth2_service.validate_and_consume_code(
            tenant_id=test_tenant["id"],
            code=code,
            client_id=normal_oauth2_client["id"],
            redirect_uri=normal_oauth2_client["redirect_uris"][0],
        )
        is not None
    )
    log.assert_not_called()


def test_rotate_refresh_token_service(test_tenant, normal_oauth2_client, test_user):
    token, _ = oauth2_service.create_refresh_token(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        scope="openid",
        grant_id=None,
    )
    data = oauth2_service.validate_refresh_token(
        tenant_id=test_tenant["id"], token=token, client_id=normal_oauth2_client["id"]
    )
    rotated = oauth2_service.rotate_refresh_token(
        test_tenant["id"], normal_oauth2_client["id"], data
    )
    assert rotated is not None
    new_token, _ = rotated
    assert new_token != token
    new = oauth2_service.validate_refresh_token(
        tenant_id=test_tenant["id"], token=new_token, client_id=normal_oauth2_client["id"]
    )
    assert new["scope"] == "openid"
    assert (
        oauth2_service.rotate_refresh_token(test_tenant["id"], normal_oauth2_client["id"], data)
        is None
    )


def test_create_authorization_code_sweeps_expired_codes(
    test_tenant, normal_oauth2_client, test_user
):
    """Consumed codes are kept until expiry; issuing a new code removes the
    tenant's expired ones so the table stays bounded."""
    old = oauth2_service.create_authorization_code(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )
    consumed = oauth2_service.validate_and_consume_code(
        tenant_id=test_tenant["id"],
        code=old,
        client_id=normal_oauth2_client["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )
    database.execute(
        test_tenant["id"],
        "update oauth2_authorization_codes set expires_at = now() - interval '1 second' "
        "where id = :id",
        {"id": consumed["id"]},
    )

    oauth2_service.create_authorization_code(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_user["id"],
        redirect_uri=normal_oauth2_client["redirect_uris"][0],
    )

    rows = database.fetchall(
        test_tenant["id"],
        "select id from oauth2_authorization_codes where client_id = :c",
        {"c": normal_oauth2_client["id"]},
    )
    assert [str(r["id"]) for r in rows] != [consumed["id"]]
    assert consumed["id"] not in {str(r["id"]) for r in rows}
    assert len(rows) == 1


# =============================================================================
# Post-logout redirect URIs (RP-initiated logout)
# =============================================================================


class TestValidatePostLogoutRedirectUris:
    def test_accepts_absolute_http_and_https(self):
        uris = ["https://rp.example/bye", "http://localhost:3000/logged-out?x=1"]
        assert oauth2_service.validate_post_logout_redirect_uris(uris) == uris

    def test_drops_blanks_and_duplicates_keeping_order(self):
        result = oauth2_service.validate_post_logout_redirect_uris(
            ["  https://b.example/ ", "", "https://a.example/", "https://b.example/", "   "]
        )
        assert result == ["https://b.example/", "https://a.example/"]

    def test_empty_list_is_fine(self):
        assert oauth2_service.validate_post_logout_redirect_uris([]) == []

    @pytest.mark.parametrize(
        "bad",
        [
            "/relative/path",
            "rp.example/bye",
            "javascript:alert(1)",
            "ftp://rp.example/bye",
            "https:///no-host",
            "https://rp.example/bye#frag",
            "https://rp.example/bye#",
            "http://[::1",
        ],
    )
    def test_rejects_malformed(self, bad):
        with pytest.raises(ValidationError) as exc:
            oauth2_service.validate_post_logout_redirect_uris([bad])
        assert exc.value.code == "invalid_post_logout_redirect_uri"

    def test_rejects_too_many(self):
        with pytest.raises(ValidationError) as exc:
            oauth2_service.validate_post_logout_redirect_uris(
                [f"https://rp.example/{i}" for i in range(51)]
            )
        assert exc.value.code == "invalid_post_logout_redirect_uri"


def test_create_normal_client_with_post_logout_redirect_uris(test_tenant, test_admin_user):
    client = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="Logout Client",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        post_logout_redirect_uris=[" https://rp.example/bye ", ""],
    )
    assert client["post_logout_redirect_uris"] == ["https://rp.example/bye"]


def test_create_normal_client_rejects_bad_post_logout_uri_before_writing(
    test_tenant, test_admin_user
):
    with pytest.raises(ValidationError):
        oauth2_service.create_normal_client(
            tenant_id=test_tenant["id"],
            name="Never Created",
            redirect_uris=["https://rp.example/cb"],
            created_by=test_admin_user["id"],
            post_logout_redirect_uris=["not a uri"],
        )
    names = [c["name"] for c in oauth2_service.get_all_clients(test_tenant["id"])]
    assert "Never Created" not in names


def test_update_client_sets_post_logout_uris_and_logs(
    test_tenant, normal_oauth2_client, test_admin_user
):
    result = oauth2_service.update_client(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["client_id"],
        actor_user_id=str(test_admin_user["id"]),
        post_logout_redirect_uris=["https://rp.example/bye"],
    )
    assert result["post_logout_redirect_uris"] == ["https://rp.example/bye"]

    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "oauth2_client_updated"
    assert events[0]["metadata"]["changed_fields"] == ["post_logout_redirect_uris"]


def test_update_client_unchanged_post_logout_uris_log_nothing(
    test_tenant, normal_oauth2_client, test_admin_user
):
    before = database.event_log.list_events(test_tenant["id"], limit=1)
    oauth2_service.update_client(
        tenant_id=test_tenant["id"],
        client_id=normal_oauth2_client["client_id"],
        actor_user_id=str(test_admin_user["id"]),
        post_logout_redirect_uris=[],
    )
    after = database.event_log.list_events(test_tenant["id"], limit=1)
    assert [e["id"] for e in after] == [e["id"] for e in before]


def test_update_client_rejects_bad_post_logout_uri(
    test_tenant, normal_oauth2_client, test_admin_user
):
    with pytest.raises(ValidationError) as exc:
        oauth2_service.update_client(
            tenant_id=test_tenant["id"],
            client_id=normal_oauth2_client["client_id"],
            actor_user_id=str(test_admin_user["id"]),
            post_logout_redirect_uris=["https://rp.example/bye#x"],
        )
    assert exc.value.code == "invalid_post_logout_redirect_uri"


def test_update_b2b_client_rejects_post_logout_uris(
    test_tenant, b2b_oauth2_client, test_admin_user
):
    with pytest.raises(ValidationError) as exc:
        oauth2_service.update_client(
            tenant_id=test_tenant["id"],
            client_id=b2b_oauth2_client["client_id"],
            actor_user_id=str(test_admin_user["id"]),
            post_logout_redirect_uris=["https://rp.example/bye"],
        )
    assert exc.value.code == "redirect_uris_not_allowed"


# =============================================================================
# Front-channel logout URI
# =============================================================================

RP_REDIRECTS = ["https://rp.example/cb", "http://localhost:3000/callback"]


class TestValidateFrontchannelLogoutUri:
    @pytest.mark.parametrize(
        "uri",
        [
            "https://rp.example/logout",
            "https://rp.example:443/logout?app=1",
            "HTTPS://RP.EXAMPLE/logout",
            "http://localhost:3000/fc",
        ],
    )
    def test_same_origin_as_a_redirect_uri(self, uri):
        assert oauth2_service.validate_frontchannel_logout_uri(uri, RP_REDIRECTS) == uri

    def test_surrounding_whitespace_is_trimmed(self):
        assert (
            oauth2_service.validate_frontchannel_logout_uri(" https://rp.example/l ", RP_REDIRECTS)
            == "https://rp.example/l"
        )

    @pytest.mark.parametrize("blank", [None, "", "   "])
    def test_blank_means_none(self, blank):
        assert oauth2_service.validate_frontchannel_logout_uri(blank, RP_REDIRECTS) is None

    @pytest.mark.parametrize(
        "bad",
        [
            "not a uri",
            "/relative/logout",
            "ftp://rp.example/logout",
            "https://rp.example/logout#frag",
            "https://rp.example:notaport/logout",
            "https:///logout",
            "https://other.example/logout",  # other host
            "http://rp.example/logout",  # other scheme
            "https://rp.example:8443/logout",  # other port
            "http://localhost/fc",  # port 80 vs 3000
        ],
    )
    def test_rejected(self, bad):
        with pytest.raises(ValidationError) as exc:
            oauth2_service.validate_frontchannel_logout_uri(bad, RP_REDIRECTS)
        assert exc.value.code == "invalid_frontchannel_logout_uri"

    def test_malformed_redirect_uris_are_ignored(self):
        with pytest.raises(ValidationError):
            oauth2_service.validate_frontchannel_logout_uri(
                "https://rp.example/l", ["https://rp.example:bad/cb", "nonsense"]
            )


def test_create_normal_client_with_frontchannel_logout(test_tenant, test_admin_user):
    client = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="FC App",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        frontchannel_logout_uri="https://rp.example/fc",
        frontchannel_logout_session_required=True,
    )
    assert client["frontchannel_logout_uri"] == "https://rp.example/fc"
    assert client["frontchannel_logout_session_required"] is True


def test_create_normal_client_frontchannel_logout_defaults(test_tenant, test_admin_user):
    client = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="Plain App",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
    )
    assert client["frontchannel_logout_uri"] is None
    assert client["frontchannel_logout_session_required"] is True


def test_create_normal_client_rejects_cross_origin_frontchannel_uri_before_writing(
    test_tenant, test_admin_user
):
    with pytest.raises(ValidationError) as exc:
        oauth2_service.create_normal_client(
            tenant_id=test_tenant["id"],
            name="Never Created",
            redirect_uris=["https://rp.example/cb"],
            created_by=test_admin_user["id"],
            frontchannel_logout_uri="https://evil.example/fc",
        )
    assert exc.value.code == "invalid_frontchannel_logout_uri"
    names = [c["name"] for c in oauth2_service.get_all_clients(test_tenant["id"])]
    assert "Never Created" not in names


def _update(test_tenant, client, actor, **kw):
    return oauth2_service.update_client(
        tenant_id=test_tenant["id"],
        client_id=client["client_id"],
        actor_user_id=str(actor["id"]),
        **kw,
    )


def test_update_client_sets_frontchannel_logout_and_logs(
    test_tenant, normal_oauth2_client, test_admin_user
):
    result = _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        frontchannel_logout_uri="http://localhost:3000/fc",
        frontchannel_logout_session_required=False,
    )
    assert result["frontchannel_logout_uri"] == "http://localhost:3000/fc"
    assert result["frontchannel_logout_session_required"] is False

    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "oauth2_client_updated"
    assert events[0]["metadata"]["changed_fields"] == [
        "frontchannel_logout_uri",
        "frontchannel_logout_session_required",
    ]


def test_update_client_empty_string_clears_frontchannel_uri(
    test_tenant, normal_oauth2_client, test_admin_user
):
    _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        frontchannel_logout_uri="http://localhost:3000/fc",
    )
    result = _update(test_tenant, normal_oauth2_client, test_admin_user, frontchannel_logout_uri="")
    assert result["frontchannel_logout_uri"] is None
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["metadata"]["changed_fields"] == ["frontchannel_logout_uri"]


def test_update_client_unchanged_frontchannel_settings_log_nothing(
    test_tenant, normal_oauth2_client, test_admin_user
):
    before = database.event_log.list_events(test_tenant["id"], limit=1)
    _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        frontchannel_logout_uri="",
        frontchannel_logout_session_required=True,
    )
    after = database.event_log.list_events(test_tenant["id"], limit=1)
    assert [e["id"] for e in after] == [e["id"] for e in before]


def test_update_client_omitted_frontchannel_settings_are_kept(
    test_tenant, normal_oauth2_client, test_admin_user
):
    _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        frontchannel_logout_uri="http://localhost:3000/fc",
        frontchannel_logout_session_required=True,
    )
    result = _update(test_tenant, normal_oauth2_client, test_admin_user, name="Renamed")
    assert result["frontchannel_logout_uri"] == "http://localhost:3000/fc"
    assert result["frontchannel_logout_session_required"] is True


def test_update_client_rejects_cross_origin_frontchannel_uri(
    test_tenant, normal_oauth2_client, test_admin_user
):
    with pytest.raises(ValidationError) as exc:
        _update(
            test_tenant,
            normal_oauth2_client,
            test_admin_user,
            frontchannel_logout_uri="https://evil.example/fc",
        )
    assert exc.value.code == "invalid_frontchannel_logout_uri"


def test_update_client_validates_frontchannel_uri_against_new_redirect_uris(
    test_tenant, normal_oauth2_client, test_admin_user
):
    """Both change at once: the URI is checked against the new redirect URIs."""
    result = _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        redirect_uris=["https://new.example/cb"],
        frontchannel_logout_uri="https://new.example/fc",
    )
    assert result["frontchannel_logout_uri"] == "https://new.example/fc"


def test_update_client_redirect_change_cannot_orphan_the_frontchannel_uri(
    test_tenant, normal_oauth2_client, test_admin_user
):
    _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        frontchannel_logout_uri="http://localhost:3000/fc",
    )
    with pytest.raises(ValidationError) as exc:
        _update(
            test_tenant,
            normal_oauth2_client,
            test_admin_user,
            redirect_uris=["https://elsewhere.example/cb"],
        )
    assert exc.value.code == "invalid_frontchannel_logout_uri"


@pytest.mark.parametrize(
    "kw",
    [
        {"frontchannel_logout_uri": "https://rp.example/fc"},
        {"frontchannel_logout_session_required": True},
    ],
)
def test_update_b2b_client_rejects_frontchannel_settings(
    test_tenant, b2b_oauth2_client, test_admin_user, kw
):
    with pytest.raises(ValidationError) as exc:
        _update(test_tenant, b2b_oauth2_client, test_admin_user, **kw)
    assert exc.value.code == "redirect_uris_not_allowed"


# =============================================================================
# Back-channel logout URI (OpenID Connect Back-Channel Logout 1.0)
# =============================================================================


class TestValidateBackchannelLogoutUri:
    @pytest.mark.parametrize(
        "uri",
        [
            "https://rp.example/bc",
            "http://localhost:3000/bc",
            "https://other.example:8443/bc?tenant=1",
            "HTTPS://RP.EXAMPLE/bc",
        ],
    )
    def test_valid(self, uri):
        assert oauth2_service.validate_backchannel_logout_uri(uri) == uri

    def test_any_origin_is_allowed(self):
        """Unlike front-channel, no redirect-URI origin rule (BCL 2.2)."""
        uri = "https://api.elsewhere.example/logout"
        assert oauth2_service.validate_backchannel_logout_uri(uri) == uri

    def test_trimmed(self):
        assert (
            oauth2_service.validate_backchannel_logout_uri(" https://rp.example/bc ")
            == "https://rp.example/bc"
        )

    @pytest.mark.parametrize("blank", [None, "", "   "])
    def test_blank_is_none(self, blank):
        assert oauth2_service.validate_backchannel_logout_uri(blank) is None

    @pytest.mark.parametrize(
        "bad",
        [
            "rp.example/bc",
            "/bc",
            "ftp://rp.example/bc",
            "javascript:alert(1)",
            "https://",
            "https://rp.example/bc#frag",
            "https://rp.example/bc#",
            "https://rp.example:99999/bc",
            "https://rp.example:abc/bc",
            "https://[::1/bc",
        ],
    )
    def test_rejected(self, bad):
        with pytest.raises(ValidationError) as exc:
            oauth2_service.validate_backchannel_logout_uri(bad)
        assert exc.value.code == "invalid_backchannel_logout_uri"


def test_create_normal_client_with_backchannel_logout(test_tenant, test_admin_user):
    client = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="BC",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        backchannel_logout_uri="https://api.rp.example/bc",
        backchannel_logout_session_required=False,
    )
    assert client["backchannel_logout_uri"] == "https://api.rp.example/bc"
    assert client["backchannel_logout_session_required"] is False


def test_create_normal_client_backchannel_logout_defaults(test_tenant, test_admin_user):
    client = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="BC defaults",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
    )
    assert client["backchannel_logout_uri"] is None
    assert client["backchannel_logout_session_required"] is True


def test_create_normal_client_rejects_bad_backchannel_uri_before_writing(
    test_tenant, test_admin_user
):
    with pytest.raises(ValidationError) as exc:
        oauth2_service.create_normal_client(
            tenant_id=test_tenant["id"],
            name="Never Created BC",
            redirect_uris=["https://rp.example/cb"],
            created_by=test_admin_user["id"],
            backchannel_logout_uri="https://rp.example/bc#frag",
        )
    assert exc.value.code == "invalid_backchannel_logout_uri"
    names = [c["name"] for c in oauth2_service.get_all_clients(test_tenant["id"])]
    assert "Never Created BC" not in names


def test_update_client_sets_backchannel_logout_and_logs(
    test_tenant, normal_oauth2_client, test_admin_user
):
    result = _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        backchannel_logout_uri="https://api.rp.example/bc",
        backchannel_logout_session_required=False,
    )
    assert result["backchannel_logout_uri"] == "https://api.rp.example/bc"
    assert result["backchannel_logout_session_required"] is False
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "oauth2_client_updated"
    assert events[0]["metadata"]["changed_fields"] == [
        "backchannel_logout_uri",
        "backchannel_logout_session_required",
    ]


def test_update_client_empty_string_clears_backchannel_uri(
    test_tenant, normal_oauth2_client, test_admin_user
):
    _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        backchannel_logout_uri="https://rp.example/bc",
    )
    result = _update(test_tenant, normal_oauth2_client, test_admin_user, backchannel_logout_uri="")
    assert result["backchannel_logout_uri"] is None
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["metadata"]["changed_fields"] == ["backchannel_logout_uri"]


def test_update_client_unchanged_backchannel_settings_log_nothing(
    test_tenant, normal_oauth2_client, test_admin_user
):
    before = database.event_log.list_events(test_tenant["id"], limit=1)
    _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        backchannel_logout_uri="",
        backchannel_logout_session_required=True,
    )
    after = database.event_log.list_events(test_tenant["id"], limit=1)
    assert [e["id"] for e in after] == [e["id"] for e in before]


def test_update_client_omitted_backchannel_settings_are_kept(
    test_tenant, normal_oauth2_client, test_admin_user
):
    _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        backchannel_logout_uri="https://rp.example/bc",
        backchannel_logout_session_required=False,
    )
    result = _update(test_tenant, normal_oauth2_client, test_admin_user, name="Renamed")
    assert result["backchannel_logout_uri"] == "https://rp.example/bc"
    assert result["backchannel_logout_session_required"] is False


def test_update_client_rejects_bad_backchannel_uri(
    test_tenant, normal_oauth2_client, test_admin_user
):
    with pytest.raises(ValidationError) as exc:
        _update(
            test_tenant,
            normal_oauth2_client,
            test_admin_user,
            backchannel_logout_uri="ftp://rp.example/bc",
        )
    assert exc.value.code == "invalid_backchannel_logout_uri"


@pytest.mark.parametrize(
    "kw",
    [
        {"backchannel_logout_uri": "https://rp.example/bc"},
        {"backchannel_logout_session_required": True},
    ],
)
def test_update_b2b_client_rejects_backchannel_settings(
    test_tenant, b2b_oauth2_client, test_admin_user, kw
):
    with pytest.raises(ValidationError) as exc:
        _update(test_tenant, b2b_oauth2_client, test_admin_user, **kw)
    assert exc.value.code == "redirect_uris_not_allowed"


# =============================================================================
# Third-party-initiated login (initiate_login_uri)
# =============================================================================


class TestValidateInitiateLoginUri:
    @pytest.mark.parametrize(
        "uri",
        [
            "https://rp.example/login",
            "https://rp.example:8443/sso/start?tenant=acme",
            "https://RP.example/Login",
        ],
    )
    def test_valid(self, uri):
        assert oauth2_service.validate_initiate_login_uri(uri) == uri

    def test_trimmed(self):
        assert (
            oauth2_service.validate_initiate_login_uri(" https://rp.example/login ")
            == "https://rp.example/login"
        )

    @pytest.mark.parametrize("blank", [None, "", "   "])
    def test_blank_is_none(self, blank):
        assert oauth2_service.validate_initiate_login_uri(blank) is None

    @pytest.mark.parametrize(
        "bad",
        [
            "http://rp.example/login",
            "rp.example/login",
            "/login",
            "javascript:alert(1)",
            "https://",
            "https://rp.example/login#frag",
            "https://rp.example/login#",
            "https://rp.example:99999/login",
            "https://[::1/login",
        ],
    )
    def test_rejected(self, bad):
        with pytest.raises(ValidationError) as exc:
            oauth2_service.validate_initiate_login_uri(bad)
        assert exc.value.code == "invalid_initiate_login_uri"


class TestInitiateLoginUrl:
    def test_adds_iss(self):
        assert oauth2_service.initiate_login_url(
            "https://rp.example/login", "https://acme.weftid.example"
        ) == ("https://rp.example/login?iss=https%3A%2F%2Facme.weftid.example")

    def test_keeps_query_and_replaces_any_iss(self):
        url = oauth2_service.initiate_login_url(
            "https://rp.example/login?a=1&iss=https://other.example&b=",
            "https://acme.weftid.example",
        )
        assert url == "https://rp.example/login?a=1&b=&iss=https%3A%2F%2Facme.weftid.example"

    def test_sends_no_hint_or_target(self):
        url = oauth2_service.initiate_login_url("https://rp.example/login", "https://i.example")
        assert "login_hint" not in url
        assert "target_link_uri" not in url


def test_create_normal_client_with_initiate_login_uri(test_tenant, test_admin_user):
    client = oauth2_service.create_normal_client(
        tenant_id=test_tenant["id"],
        name="Launchable",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        initiate_login_uri=" https://rp.example/login ",
    )
    assert client["initiate_login_uri"] == "https://rp.example/login"


def test_create_normal_client_rejects_http_initiate_login_uri_before_writing(
    test_tenant, test_admin_user
):
    with pytest.raises(ValidationError) as exc:
        oauth2_service.create_normal_client(
            tenant_id=test_tenant["id"],
            name="Never Created Launchable",
            redirect_uris=["https://rp.example/cb"],
            created_by=test_admin_user["id"],
            initiate_login_uri="http://rp.example/login",
        )
    assert exc.value.code == "invalid_initiate_login_uri"
    names = [c["name"] for c in oauth2_service.get_all_clients(test_tenant["id"])]
    assert "Never Created Launchable" not in names


def test_update_client_sets_initiate_login_uri_and_logs(
    test_tenant, normal_oauth2_client, test_admin_user
):
    result = _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        initiate_login_uri="https://rp.example/login",
    )
    assert result["initiate_login_uri"] == "https://rp.example/login"
    events = database.event_log.list_events(test_tenant["id"], limit=1)
    assert events[0]["event_type"] == "oauth2_client_updated"
    assert events[0]["metadata"]["changed_fields"] == ["initiate_login_uri"]


def test_update_client_clears_and_keeps_initiate_login_uri(
    test_tenant, normal_oauth2_client, test_admin_user
):
    _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        initiate_login_uri="https://rp.example/login",
    )
    kept = _update(test_tenant, normal_oauth2_client, test_admin_user, name="Renamed")
    assert kept["initiate_login_uri"] == "https://rp.example/login"

    before = database.event_log.list_events(test_tenant["id"], limit=1)
    _update(
        test_tenant,
        normal_oauth2_client,
        test_admin_user,
        initiate_login_uri="https://rp.example/login",
    )
    after = database.event_log.list_events(test_tenant["id"], limit=1)
    assert [e["id"] for e in after] == [e["id"] for e in before]

    cleared = _update(test_tenant, normal_oauth2_client, test_admin_user, initiate_login_uri="")
    assert cleared["initiate_login_uri"] is None


def test_update_client_rejects_http_initiate_login_uri(
    test_tenant, normal_oauth2_client, test_admin_user
):
    with pytest.raises(ValidationError) as exc:
        _update(
            test_tenant,
            normal_oauth2_client,
            test_admin_user,
            initiate_login_uri="http://rp.example/login",
        )
    assert exc.value.code == "invalid_initiate_login_uri"


def test_update_b2b_client_rejects_initiate_login_uri(
    test_tenant, b2b_oauth2_client, test_admin_user
):
    with pytest.raises(ValidationError) as exc:
        _update(
            test_tenant, b2b_oauth2_client, test_admin_user, initiate_login_uri="https://x.example"
        )
    assert exc.value.code == "redirect_uris_not_allowed"
