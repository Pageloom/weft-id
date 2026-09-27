"""OAuth2 token database operations."""

from datetime import datetime

import oauth2
from database._core import TenantArg, execute, fetchone, session


def create_access_token(
    tenant_id: TenantArg,
    tenant_id_value: str,
    client_id: str,
    user_id: str,
    parent_token_id: str | None = None,
    is_client_credentials: bool = False,
    scope: str | None = None,
    grant_id: str | None = None,
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
        scope: Granted space-delimited scope string (optional; persisted so
            downstream userinfo can gate released claims by the token's scopes)
        grant_id: The authorization code that started this grant (optional;
            lets a reused code revoke every token issued from it)

    Returns:
        Plain text access token (shown once)
    """
    # Generate token
    token = oauth2.generate_opaque_token("access")
    token_hash = oauth2.hash_token(token)
    token_lookup = oauth2.token_lookup(token)

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
            tenant_id, token_hash, token_lookup, token_type, client_id, user_id,
            expires_at, parent_token_id, scope, grant_id
        )
        values (
            :tenant_id, :token_hash, :token_lookup, 'access', :client_id, :user_id,
            :expires_at, :parent_token_id, :scope, :grant_id
        )
        returning id
        """,
        {
            "tenant_id": tenant_id_value,
            "token_hash": token_hash,
            "token_lookup": token_lookup,
            "client_id": client_id,
            "user_id": user_id,
            "expires_at": expires_at,
            "parent_token_id": parent_token_id,
            "scope": scope,
            "grant_id": grant_id,
        },
    )

    return token


def create_refresh_token(
    tenant_id: TenantArg,
    tenant_id_value: str,
    client_id: str,
    user_id: str,
    scope: str | None = None,
    grant_id: str | None = None,
) -> tuple[str, str]:
    """
    Create an OAuth2 refresh token.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        client_id: OAuth2 client UUID (not client_id string!)
        user_id: User ID this token acts as
        scope: Granted space-delimited scope string (optional; persisted so
            the scope can be carried forward onto access tokens minted by the
            refresh_token grant, keeping userinfo claims consistent)
        grant_id: The authorization code that started this grant (optional;
            carried onto rotated refresh tokens and their access tokens)

    Returns:
        Tuple of (plain text refresh token, refresh token ID)
    """
    # Generate token
    token = oauth2.generate_opaque_token("refresh")
    token_hash = oauth2.hash_token(token)
    token_lookup = oauth2.token_lookup(token)

    # Calculate expiry (30 days)
    expires_at = oauth2.calculate_expires_at(oauth2.REFRESH_TOKEN_EXPIRY)

    # Insert token
    result = fetchone(
        tenant_id,
        """
        insert into oauth2_tokens (
            tenant_id, token_hash, token_lookup, token_type,
            client_id, user_id, expires_at, scope, grant_id
        )
        values (
            :tenant_id, :token_hash, :token_lookup, 'refresh',
            :client_id, :user_id, :expires_at, :scope, :grant_id
        )
        returning id
        """,
        {
            "tenant_id": tenant_id_value,
            "token_hash": token_hash,
            "token_lookup": token_lookup,
            "client_id": client_id,
            "user_id": user_id,
            "expires_at": expires_at,
            "scope": scope,
            "grant_id": grant_id,
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
        Dict with user_id, tenant_id, client_id, expires_at, scope if valid,
        None otherwise. `scope` is the space-delimited granted-scope string
        persisted at issuance (may be None for pre-OIDC / non-scoped tokens);
        the userinfo endpoint uses it to gate which claims are released.
    """
    if tenant_id is None:
        # Tenant ID is required due to RLS policies
        return None

    # Resolve exactly one candidate row by the indexed lookup digest, then run
    # Argon2 once on it. Selecting every live token and Argon2-verifying in a
    # loop was a pre-auth resource-exhaustion amplifier (see oauth2.token_lookup).
    token_record = fetchone(
        tenant_id,
        """
        select id, token_hash, user_id, tenant_id, client_id, expires_at, scope
        from oauth2_tokens
        where token_type = 'access'
          and token_lookup = :lookup
          and expires_at > now()
        """,
        {"lookup": oauth2.token_lookup(token)},
    )

    if token_record and oauth2.verify_token_hash(token, token_record["token_hash"]):
        return {
            "user_id": token_record["user_id"],
            "tenant_id": token_record["tenant_id"],
            "client_id": token_record["client_id"],
            "expires_at": token_record["expires_at"],
            "scope": token_record["scope"],
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
        Dict with id, user_id, tenant_id, scope, grant_id, expires_at if
        valid, None otherwise.
        `scope` is the space-delimited granted-scope string persisted at
        issuance (may be None for pre-OIDC / non-scoped tokens); the
        refresh_token grant carries it onto the refreshed access token.
    """
    # Resolve exactly one candidate row by the indexed lookup digest, then run
    # Argon2 once on it (see oauth2.token_lookup). The client_id filter keeps a
    # refresh token bound to the client it was issued to.
    token_record = fetchone(
        tenant_id,
        """
        select id, token_hash, user_id, tenant_id, scope, grant_id, expires_at
        from oauth2_tokens
        where token_type = 'refresh'
          and client_id = :client_id
          and token_lookup = :lookup
          and expires_at > now()
        """,
        {"client_id": client_id, "lookup": oauth2.token_lookup(token)},
    )

    if token_record and oauth2.verify_token_hash(token, token_record["token_hash"]):
        return {
            "id": token_record["id"],
            "user_id": token_record["user_id"],
            "tenant_id": token_record["tenant_id"],
            "scope": token_record["scope"],
            "grant_id": token_record["grant_id"],
            "expires_at": token_record["expires_at"],
        }

    return None


def rotate_refresh_token(
    tenant_id: TenantArg,
    tenant_id_value: str,
    old_token_id: str,
    client_id: str,
    user_id: str,
    scope: str | None,
    grant_id: str | None,
    expires_at: datetime,
) -> tuple[str, str] | None:
    """
    Replace a refresh token with a new one (refresh token rotation).

    In one transaction: the old token's row is locked (a concurrent rotation
    of the same token waits, then finds it gone, so exactly one succeeds), a
    new refresh token is inserted with the same client, user, scope, grant and
    absolute expiry, the old token's access tokens are re-parented onto the new
    one so they are not cascade-deleted mid-use, and the old token is deleted.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        old_token_id: The refresh token being redeemed
        client_id: OAuth2 client UUID
        user_id: User ID the token acts as
        scope: Granted scope, carried forward
        grant_id: Grant the token belongs to, carried forward
        expires_at: The old token's expiry, carried forward (rotation never
            extends the grant's lifetime)

    Returns:
        Tuple of (plain text refresh token, refresh token ID), or None when the
        old token no longer exists (already redeemed or revoked).
    """
    token = oauth2.generate_opaque_token("refresh")
    with session(tenant_id=tenant_id) as cur:
        cur.execute(
            """
            select id from oauth2_tokens
            where id = %(old_id)s and token_type = 'refresh'
            for update
            """,
            {"old_id": old_token_id},
        )
        if cur.fetchone() is None:
            return None

        cur.execute(
            """
            insert into oauth2_tokens (
                tenant_id, token_hash, token_lookup, token_type,
                client_id, user_id, expires_at, scope, grant_id
            )
            values (
                %(tenant_id)s, %(token_hash)s, %(token_lookup)s, 'refresh',
                %(client_id)s, %(user_id)s, %(expires_at)s, %(scope)s, %(grant_id)s
            )
            returning id
            """,
            {
                "tenant_id": tenant_id_value,
                "token_hash": oauth2.hash_token(token),
                "token_lookup": oauth2.token_lookup(token),
                "client_id": client_id,
                "user_id": user_id,
                "expires_at": expires_at,
                "scope": scope,
                "grant_id": grant_id,
            },
        )
        new_row = cur.fetchone()
        if new_row is None:
            raise ValueError("Failed to create refresh token")

        cur.execute(
            "update oauth2_tokens set parent_token_id = %(new_id)s "
            "where parent_token_id = %(old_id)s",
            {"new_id": new_row["id"], "old_id": old_token_id},
        )
        cur.execute("delete from oauth2_tokens where id = %(old_id)s", {"old_id": old_token_id})

    return token, str(new_row["id"])


def revoke_grant_tokens(tenant_id: TenantArg, grant_id: str) -> int:
    """
    Revoke every token issued under one grant (one authorization code).

    Used when an authorization code is redeemed a second time.

    Args:
        tenant_id: Tenant ID for scoping
        grant_id: The authorization code's id

    Returns:
        Number of tokens deleted
    """
    return execute(
        tenant_id,
        "delete from oauth2_tokens where grant_id = :grant_id",
        {"grant_id": grant_id},
    )


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
