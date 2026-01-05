"""OAuth2 service layer.

This module provides business logic for OAuth2 operations:
- Client lookup and validation
- Authorization code creation
- Token creation and validation

All functions:
- Are utility functions without authorization (OAuth2 has its own auth)
- Return data from database layer
- Have no knowledge of HTTP concepts
"""

import database
from services.event_log import log_event

# =============================================================================
# Client Operations
# =============================================================================


def get_client_by_client_id(tenant_id: str, client_id: str) -> dict | None:
    """
    Get an OAuth2 client by its client_id.

    Args:
        tenant_id: Tenant ID
        client_id: OAuth2 client identifier

    Returns:
        Client dict or None if not found
    """
    return database.oauth2.get_client_by_client_id(tenant_id, client_id)


# =============================================================================
# Authorization Code Operations
# =============================================================================


def create_authorization_code(
    tenant_id: str,
    client_id: str,
    user_id: str,
    redirect_uri: str,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
) -> str:
    """
    Create an authorization code for OAuth2 authorization code flow.

    Args:
        tenant_id: Tenant ID
        client_id: Internal client UUID (not the client_id string)
        user_id: User UUID authorizing the request
        redirect_uri: Registered redirect URI
        code_challenge: Optional PKCE code challenge
        code_challenge_method: Optional PKCE method (S256 or plain)

    Returns:
        Authorization code string
    """
    return database.oauth2.create_authorization_code(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        client_id=client_id,
        user_id=user_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )


def validate_and_consume_code(
    tenant_id: str,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str | None = None,
) -> dict | None:
    """
    Validate and consume an authorization code.

    The code is consumed (deleted) upon successful validation.

    Args:
        tenant_id: Tenant ID
        code: Authorization code to validate
        client_id: Internal client UUID
        redirect_uri: Redirect URI (must match original)
        code_verifier: Optional PKCE code verifier

    Returns:
        Code data dict with user_id, or None if invalid
    """
    return database.oauth2.validate_and_consume_code(
        tenant_id=tenant_id,
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
    )


# =============================================================================
# Token Operations
# =============================================================================


def create_refresh_token(
    tenant_id: str,
    client_id: str,
    user_id: str,
) -> tuple[str, str]:
    """
    Create a refresh token.

    Args:
        tenant_id: Tenant ID
        client_id: Internal client UUID
        user_id: User UUID

    Returns:
        Tuple of (refresh_token_string, refresh_token_id)
    """
    return database.oauth2.create_refresh_token(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        client_id=client_id,
        user_id=user_id,
    )


def create_access_token(
    tenant_id: str,
    client_id: str,
    user_id: str,
    parent_token_id: str | None = None,
    is_client_credentials: bool = False,
) -> str:
    """
    Create an access token.

    Args:
        tenant_id: Tenant ID
        client_id: Internal client UUID
        user_id: User UUID
        parent_token_id: Optional refresh token ID (for linked tokens)
        is_client_credentials: True if this is a client_credentials grant

    Returns:
        Access token string
    """
    return database.oauth2.create_access_token(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        client_id=client_id,
        user_id=user_id,
        parent_token_id=parent_token_id,
        is_client_credentials=is_client_credentials,
    )


def validate_refresh_token(
    tenant_id: str,
    token: str,
    client_id: str,
) -> dict | None:
    """
    Validate a refresh token.

    Args:
        tenant_id: Tenant ID
        token: Refresh token string
        client_id: Internal client UUID

    Returns:
        Token data dict with user_id and id, or None if invalid
    """
    return database.oauth2.validate_refresh_token(
        tenant_id=tenant_id,
        token=token,
        client_id=client_id,
    )


# =============================================================================
# Client Management Operations
# =============================================================================


def get_all_clients(tenant_id: str) -> list[dict]:
    """
    Get all OAuth2 clients for a tenant.

    Args:
        tenant_id: Tenant ID

    Returns:
        List of client dicts
    """
    return database.oauth2.get_all_clients(tenant_id)


def create_normal_client(
    tenant_id: str,
    name: str,
    redirect_uris: list[str],
    created_by: str,
) -> dict:
    """
    Create a normal OAuth2 client (authorization code flow).

    Args:
        tenant_id: Tenant ID
        name: Client name
        redirect_uris: List of allowed redirect URIs
        created_by: User ID who created the client

    Returns:
        Client dict including plaintext client_secret
    """
    result = database.oauth2.create_normal_client(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=name,
        redirect_uris=redirect_uris,
        created_by=created_by,
    )

    if result is None:
        raise ValueError("Failed to create OAuth2 client")

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=created_by,
        artifact_type="oauth2_client",
        artifact_id=str(result["id"]),
        event_type="oauth2_client_created",
        metadata={
            "name": name,
            "type": "normal",
            "client_id": result["client_id"],
        },
        request_metadata=None,
    )

    return result


def create_b2b_client(
    tenant_id: str,
    name: str,
    role: str,
    created_by: str,
) -> dict:
    """
    Create a B2B OAuth2 client (client credentials flow).

    Creates a service user with the specified role and links it.

    Args:
        tenant_id: Tenant ID
        name: Client name (used as service user first_name)
        role: Role for service user (member, admin, super_admin)
        created_by: User ID who created the client

    Returns:
        Client dict including plaintext client_secret
    """
    result = database.oauth2.create_b2b_client(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        name=name,
        role=role,
        created_by=created_by,
    )

    if result is None:
        raise ValueError("Failed to create B2B OAuth2 client")

    # Log the event
    log_event(
        tenant_id=tenant_id,
        actor_user_id=created_by,
        artifact_type="oauth2_client",
        artifact_id=str(result["id"]),
        event_type="oauth2_client_created",
        metadata={
            "name": name,
            "type": "b2b",
            "role": role,
            "client_id": result["client_id"],
            "service_user_id": str(result.get("service_user_id")),
        },
        request_metadata=None,
    )

    return result


def delete_client(tenant_id: str, client_id: str, actor_user_id: str) -> int:
    """
    Delete an OAuth2 client.

    Cascades to delete tokens and authorization codes.

    Args:
        tenant_id: Tenant ID
        client_id: The client_id string (e.g., "loom_client_abc123")
        actor_user_id: User ID performing the deletion

    Returns:
        Number of rows deleted (0 if not found)
    """
    # Get client info before deletion for logging
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if not client:
        return 0

    rows = database.oauth2.delete_client(tenant_id, client_id)

    if rows > 0:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="oauth2_client",
            artifact_id=str(client["id"]),
            event_type="oauth2_client_deleted",
            metadata={"name": client["name"], "client_id": client_id},
            request_metadata=None,
        )

    return rows


def regenerate_client_secret(
    tenant_id: str, client_id: str, actor_user_id: str
) -> str:
    """
    Regenerate the client secret.

    Args:
        tenant_id: Tenant ID
        client_id: The client_id string
        actor_user_id: User ID performing the regeneration

    Returns:
        New plaintext client secret
    """
    # Get client info for logging
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)

    new_secret = database.oauth2.regenerate_client_secret(tenant_id, client_id)

    if client:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            artifact_type="oauth2_client",
            artifact_id=str(client["id"]),
            event_type="oauth2_client_secret_regenerated",
            metadata={"name": client["name"], "client_id": client_id},
            request_metadata=None,
        )

    return new_secret
