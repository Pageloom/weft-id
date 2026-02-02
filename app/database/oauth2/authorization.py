"""OAuth2 authorization code database operations."""

import oauth2
from database._core import TenantArg, execute, fetchall, fetchone


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
