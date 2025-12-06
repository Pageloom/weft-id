"""OAuth2 database operations for clients, authorization codes, and tokens."""

import oauth2
from database._core import TenantArg, execute, fetchall, fetchone
from database.users import create_user

# ============================================================================
# OAuth2 Client Operations
# ============================================================================


def create_normal_client(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    redirect_uris: list[str],
    created_by: str,
) -> dict:
    """
    Create a normal OAuth2 client for authorization code flow.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        name: Client name
        redirect_uris: List of exact redirect URIs
        created_by: User ID who created the client

    Returns:
        Dict with client details including id, client_id, and plain text client_secret
        (client_secret is only returned once!)
    """
    # Generate client credentials
    client_id = oauth2.generate_client_id()
    client_secret = oauth2.generate_client_secret()
    client_secret_hash = oauth2.hash_token(client_secret)

    # Insert client
    client = fetchone(
        tenant_id,
        """
        insert into oauth2_clients (
            tenant_id, client_id, client_secret_hash, client_type,
            name, redirect_uris, created_by
        )
        values (
            :tenant_id, :client_id, :client_secret_hash, 'normal',
            :name, :redirect_uris, :created_by
        )
        returning id, tenant_id, client_id, client_type, name, redirect_uris,
                  service_user_id, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "client_id": client_id,
            "client_secret_hash": client_secret_hash,
            "name": name,
            "redirect_uris": redirect_uris,
            "created_by": created_by,
        },
    )

    if client:
        client["client_secret"] = client_secret  # Add plain text secret (shown once)

    return client


def create_b2b_client(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    role: str,
    created_by: str,
) -> dict:
    """
    Create a B2B OAuth2 client for client credentials flow.

    This automatically creates a service user with the specified role.
    The service user's first_name is set to the client name, and last_name to "Service Account".

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        name: Client name (also used as service user first_name)
        role: Role for service user ('member', 'admin', 'super_admin')
        created_by: User ID who created the client

    Returns:
        Dict with client details including id, client_id, service_user_id, and plain
        text client_secret (client_secret is only returned once!)
    """
    # First, create the service user
    # Service users have no password and use client name as first_name
    service_user = create_user(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id_value,
        first_name=name,
        last_name="Service Account",
        email=f"service_{oauth2.generate_opaque_token('user')}@system.local",
        role=role,
    )

    if not service_user:
        raise ValueError("Failed to create service user")

    # Generate client credentials
    client_id = oauth2.generate_client_id("loom_b2b")
    client_secret = oauth2.generate_client_secret()
    client_secret_hash = oauth2.hash_token(client_secret)

    # Insert B2B client
    client = fetchone(
        tenant_id,
        """
        insert into oauth2_clients (
            tenant_id, client_id, client_secret_hash, client_type,
            name, service_user_id, created_by
        )
        values (
            :tenant_id, :client_id, :client_secret_hash, 'b2b',
            :name, :service_user_id, :created_by
        )
        returning id, tenant_id, client_id, client_type, name, redirect_uris,
                  service_user_id, created_at
        """,
        {
            "tenant_id": tenant_id_value,
            "client_id": client_id,
            "client_secret_hash": client_secret_hash,
            "name": name,
            "service_user_id": service_user["user_id"],
            "created_by": created_by,
        },
    )

    if client:
        client["client_secret"] = client_secret  # Add plain text secret (shown once)

    return client


def get_client_by_client_id(tenant_id: TenantArg, client_id: str) -> dict | None:
    """
    Get OAuth2 client by client_id.

    Returns:
        Client record with id, tenant_id, client_id, client_secret_hash, client_type,
        name, redirect_uris, service_user_id, created_at
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, client_id, client_secret_hash, client_type,
               name, redirect_uris, service_user_id, created_at
        from oauth2_clients
        where client_id = :client_id
        """,
        {"client_id": client_id},
    )


def get_all_clients(tenant_id: TenantArg) -> list[dict]:
    """
    Get all OAuth2 clients for a tenant.

    Returns:
        List of client records
    """
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, client_id, client_type, name, redirect_uris,
               service_user_id, created_at
        from oauth2_clients
        order by created_at desc
        """,
        {},
    )


def delete_client(tenant_id: TenantArg, client_id: str) -> int:
    """
    Delete an OAuth2 client.

    This cascades to delete all tokens and authorization codes.
    For B2B clients, the service user is NOT deleted (ON DELETE RESTRICT prevents this).

    Returns:
        Number of rows deleted
    """
    return execute(
        tenant_id,
        "delete from oauth2_clients where client_id = :client_id",
        {"client_id": client_id},
    )


def regenerate_client_secret(tenant_id: TenantArg, client_id: str) -> str:
    """
    Regenerate client secret for an OAuth2 client.

    Args:
        tenant_id: Tenant ID for scoping
        client_id: Client ID to regenerate secret for

    Returns:
        New plain text client_secret (shown only once!)
    """
    # Generate new secret
    client_secret = oauth2.generate_client_secret()
    client_secret_hash = oauth2.hash_token(client_secret)

    # Update client
    execute(
        tenant_id,
        """
        update oauth2_clients
        set client_secret_hash = :client_secret_hash
        where client_id = :client_id
        """,
        {"client_secret_hash": client_secret_hash, "client_id": client_id},
    )

    return client_secret


def get_b2b_client_by_service_user(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get B2B OAuth2 client by service user ID.

    Used to check if a user is a service user before deletion.

    Returns:
        Client record or None
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, client_id, client_type, name
        from oauth2_clients
        where service_user_id = :user_id and client_type = 'b2b'
        """,
        {"user_id": user_id},
    )


# ============================================================================
# OAuth2 Authorization Code Operations
# ============================================================================


def create_authorization_code(
    tenant_id: TenantArg,
    tenant_id_value: str,
    client_id: str,
    user_id: str,
    redirect_uri: str,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
) -> str:
    """
    Create an authorization code for the authorization code flow.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store
        client_id: OAuth2 client UUID (not client_id string!)
        user_id: User ID authorizing the request
        redirect_uri: Redirect URI for this authorization
        code_challenge: PKCE code challenge (optional)
        code_challenge_method: PKCE challenge method (optional)

    Returns:
        Plain text authorization code (shown once)
    """
    # Generate authorization code
    code = oauth2.generate_opaque_token("auth")
    code_hash = oauth2.hash_token(code)

    # Calculate expiry
    expires_at = oauth2.calculate_expires_at(oauth2.AUTHORIZATION_CODE_EXPIRY)

    # Insert authorization code
    fetchone(
        tenant_id,
        """
        insert into oauth2_authorization_codes (
            tenant_id, code_hash, client_id, user_id, redirect_uri,
            code_challenge, code_challenge_method, expires_at
        )
        values (
            :tenant_id, :code_hash, :client_id, :user_id, :redirect_uri,
            :code_challenge, :code_challenge_method, :expires_at
        )
        returning id
        """,
        {
            "tenant_id": tenant_id_value,
            "code_hash": code_hash,
            "client_id": client_id,
            "user_id": user_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "expires_at": expires_at,
        },
    )

    return code


def validate_and_consume_code(
    tenant_id: TenantArg,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str | None = None,
) -> dict | None:
    """
    Validate and consume an authorization code (one-time use).

    Args:
        tenant_id: Tenant ID for scoping
        code: Plain text authorization code
        client_id: OAuth2 client UUID (not client_id string!)
        redirect_uri: Redirect URI to match
        code_verifier: PKCE code verifier (if PKCE was used)

    Returns:
        Dict with user_id and tenant_id if valid, None otherwise

    Note:
        Authorization codes are deleted after use (one-time use).
    """
    # Find all matching authorization codes for this client and redirect_uri
    codes = fetchall(
        tenant_id,
        """
        select id, code_hash, user_id, tenant_id, code_challenge, code_challenge_method, expires_at
        from oauth2_authorization_codes
        where client_id = :client_id
          and redirect_uri = :redirect_uri
          and expires_at > now()
        """,
        {"client_id": client_id, "redirect_uri": redirect_uri},
    )

    # Find the matching code by verifying hash
    matching_code = None
    for code_record in codes:
        if oauth2.verify_token_hash(code, code_record["code_hash"]):
            matching_code = code_record
            break

    if not matching_code:
        return None

    # Verify PKCE if code_challenge was provided during authorization
    if matching_code["code_challenge"]:
        if not code_verifier:
            return None  # PKCE required but verifier not provided
        if not oauth2.verify_pkce_challenge(
            code_verifier,
            matching_code["code_challenge"],
            matching_code["code_challenge_method"],
        ):
            return None  # PKCE verification failed

    # Delete the authorization code (one-time use)
    execute(
        tenant_id,
        "delete from oauth2_authorization_codes where id = :id",
        {"id": matching_code["id"]},
    )

    return {
        "user_id": matching_code["user_id"],
        "tenant_id": matching_code["tenant_id"],
    }


def cleanup_expired_codes(tenant_id: TenantArg) -> int:
    """
    Delete expired authorization codes.

    Returns:
        Number of codes deleted
    """
    return execute(
        tenant_id,
        "delete from oauth2_authorization_codes where expires_at <= now()",
        {},
    )


# ============================================================================
# OAuth2 Token Operations
# ============================================================================


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
