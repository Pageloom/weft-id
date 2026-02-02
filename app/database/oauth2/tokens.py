"""OAuth2 token database operations."""

import oauth2
from database._core import TenantArg, execute, fetchall, fetchone


def create_access_token(
    tenant_id: TenantArg,
    tenant_id_value: str,
    client_id: str,
    user_id: str,
    parent_token_id: str | None = None,
    is_client_credentials: bool = False,
) -> str:
    """
    Create an OAuth2 access token.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        client_id: OAuth2 client UUID (not client_id string!)
        user_id: User ID this token acts as
        parent_token_id: Refresh token ID (for access tokens from refresh flow)
        is_client_credentials: Whether this is a client credentials token (24h expiry)

    Returns:
        Plain text access token (shown once)
    """
    # Generate token
    token = oauth2.generate_opaque_token("access")
    token_hash = oauth2.hash_token(token)

    # Calculate expiry (24h for client credentials, 1h for others)
    if is_client_credentials:
        expires_at = oauth2.calculate_expires_at(oauth2.CLIENT_CREDENTIALS_TOKEN_EXPIRY)
    else:
        expires_at = oauth2.calculate_expires_at(oauth2.ACCESS_TOKEN_EXPIRY)

    # Insert token
    fetchone(
        tenant_id,
        """
        insert into oauth2_tokens (
            tenant_id, token_hash, token_type, client_id, user_id,
            expires_at, parent_token_id
        )
        values (
            :tenant_id, :token_hash, 'access', :client_id, :user_id,
            :expires_at, :parent_token_id
        )
        returning id
        """,
        {
            "tenant_id": tenant_id_value,
            "token_hash": token_hash,
            "client_id": client_id,
            "user_id": user_id,
            "expires_at": expires_at,
            "parent_token_id": parent_token_id,
        },
    )

    return token


def create_refresh_token(
    tenant_id: TenantArg,
    tenant_id_value: str,
    client_id: str,
    user_id: str,
) -> tuple[str, str]:
    """
    Create an OAuth2 refresh token.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        client_id: OAuth2 client UUID (not client_id string!)
        user_id: User ID this token acts as

    Returns:
        Tuple of (plain text refresh token, refresh token ID)
    """
    # Generate token
    token = oauth2.generate_opaque_token("refresh")
    token_hash = oauth2.hash_token(token)

    # Calculate expiry (30 days)
    expires_at = oauth2.calculate_expires_at(oauth2.REFRESH_TOKEN_EXPIRY)

    # Insert token
    result = fetchone(
        tenant_id,
        """
        insert into oauth2_tokens (
            tenant_id, token_hash, token_type, client_id, user_id, expires_at
        )
        values (
            :tenant_id, :token_hash, 'refresh', :client_id, :user_id, :expires_at
        )
        returning id
        """,
        {
            "tenant_id": tenant_id_value,
            "token_hash": token_hash,
            "client_id": client_id,
            "user_id": user_id,
            "expires_at": expires_at,
        },
    )

    if result is None:
        raise ValueError("Failed to create refresh token")

    return token, result["id"]


def validate_token(token: str, tenant_id: TenantArg | None = None) -> dict | None:
    """
    Validate an OAuth2 access token.

    Args:
        token: Plain text access token
        tenant_id: Tenant ID to scope the search (required for RLS compliance)

    Returns:
        Dict with user_id, tenant_id, client_id, expires_at if valid, None otherwise
    """
    if tenant_id is None:
        # Tenant ID is required due to RLS policies
        return None

    # Find all access tokens for this tenant
    tokens = fetchall(
        tenant_id,
        """
        select id, token_hash, user_id, tenant_id, client_id, expires_at
        from oauth2_tokens
        where token_type = 'access'
          and expires_at > now()
        """,
        {},
    )

    # Find the matching token by verifying hash
    for token_record in tokens:
        if oauth2.verify_token_hash(token, token_record["token_hash"]):
            return {
                "user_id": token_record["user_id"],
                "tenant_id": token_record["tenant_id"],
                "client_id": token_record["client_id"],
                "expires_at": token_record["expires_at"],
            }

    return None


def validate_refresh_token(tenant_id: TenantArg, token: str, client_id: str) -> dict | None:
    """
    Validate an OAuth2 refresh token.

    Args:
        tenant_id: Tenant ID for scoping
        token: Plain text refresh token
        client_id: OAuth2 client UUID (must match token's client_id)

    Returns:
        Dict with id, user_id, tenant_id if valid, None otherwise
    """
    # Find all refresh tokens for this client
    tokens = fetchall(
        tenant_id,
        """
        select id, token_hash, user_id, tenant_id
        from oauth2_tokens
        where token_type = 'refresh'
          and client_id = :client_id
          and expires_at > now()
        """,
        {"client_id": client_id},
    )

    # Find the matching token by verifying hash
    for token_record in tokens:
        if oauth2.verify_token_hash(token, token_record["token_hash"]):
            return {
                "id": token_record["id"],
                "user_id": token_record["user_id"],
                "tenant_id": token_record["tenant_id"],
            }

    return None


def revoke_token(tenant_id: TenantArg, token_hash: str) -> int:
    """
    Revoke a token by deleting it.

    Args:
        tenant_id: Tenant ID for scoping
        token_hash: Hashed token to revoke

    Returns:
        Number of rows deleted
    """
    return execute(
        tenant_id,
        "delete from oauth2_tokens where token_hash = :token_hash",
        {"token_hash": token_hash},
    )


def revoke_all_client_tokens(tenant_id: TenantArg, client_id: str) -> int:
    """
    Revoke all tokens for a client.

    Args:
        tenant_id: Tenant ID for scoping
        client_id: OAuth2 client UUID

    Returns:
        Number of tokens deleted
    """
    return execute(
        tenant_id,
        "delete from oauth2_tokens where client_id = :client_id",
        {"client_id": client_id},
    )


def cleanup_expired_tokens(tenant_id: TenantArg) -> int:
    """
    Delete expired tokens.

    Returns:
        Number of tokens deleted
    """
    return execute(
        tenant_id,
        "delete from oauth2_tokens where expires_at <= now()",
        {},
    )


def revoke_all_user_tokens(tenant_id: TenantArg, user_id: str) -> int:
    """
    Revoke all tokens for a user.

    Used when a user is inactivated to ensure their API access is immediately revoked.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to revoke all tokens for

    Returns:
        Number of tokens deleted
    """
    return execute(
        tenant_id,
        "delete from oauth2_tokens where user_id = :user_id",
        {"user_id": user_id},
    )
