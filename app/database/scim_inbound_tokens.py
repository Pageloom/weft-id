"""Inbound SCIM bearer token database operations.

Bearer tokens accepted by WeftID's `/scim/v2/inbound/<idp_id>/` endpoint
family (Iteration 2+). Each token is tied to one `saml_identity_providers`
row; deleting the IdP cascades the tokens.

Storage is **hash-only**: the table stores a SHA-256 hex digest, not the
plaintext. Inbound auth verifies an incoming bearer by hashing it and
looking up the row; plaintext is never reconstructable. (Outbound is
different -- there we need to *send* the token, so it's encrypted at
rest.)
"""

from ._core import TenantArg, execute, fetchall, fetchone


def create_token(
    tenant_id: TenantArg,
    tenant_id_value: str,
    idp_id: str,
    token_hash: str,
    name: str | None,
    created_by_user_id: str,
) -> dict:
    """Insert a new inbound SCIM bearer token row.

    Args:
        tenant_id: Tenant scope for RLS.
        tenant_id_value: Tenant id as a string for the INSERT.
        idp_id: The `saml_identity_providers.id` this token belongs to.
        token_hash: SHA-256 hex digest of the plaintext (64 hex chars).
        name: Optional admin-facing label (e.g. "Okta production").
        created_by_user_id: Super-admin user id (audit field).

    Returns:
        Dict with id, tenant_id, idp_id, name, created_by_user_id,
        created_at, revoked_at, last_used_at.
    """
    result = fetchone(
        tenant_id,
        """
        insert into scim_inbound_tokens (
            tenant_id, idp_id, token_hash, name, created_by_user_id
        ) values (
            :tenant_id, :idp_id, :token_hash, :name, :created_by_user_id
        )
        returning id, tenant_id, idp_id, name, created_by_user_id,
                  created_at, revoked_at, last_used_at
        """,
        {
            "tenant_id": tenant_id_value,
            "idp_id": idp_id,
            "token_hash": token_hash,
            "name": name,
            "created_by_user_id": created_by_user_id,
        },
    )
    assert result is not None  # INSERT ... RETURNING always returns a row
    return result


def list_tokens(tenant_id: TenantArg, idp_id: str) -> list[dict]:
    """List all inbound SCIM tokens for one IdP, newest first.

    Returns both active and revoked rows so the admin UI can show
    revocation history. Hash is intentionally not in the SELECT list --
    only metadata leaves the database layer.
    """
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, idp_id, name, created_by_user_id,
               created_at, revoked_at, last_used_at
        from scim_inbound_tokens
        where idp_id = :idp_id
        order by created_at desc
        """,
        {"idp_id": idp_id},
    )


def list_active_tokens(tenant_id: TenantArg, idp_id: str) -> list[dict]:
    """List active (not-revoked) inbound SCIM tokens for one IdP, newest first."""
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, idp_id, name, created_by_user_id,
               created_at, revoked_at, last_used_at
        from scim_inbound_tokens
        where idp_id = :idp_id and revoked_at is null
        order by created_at desc
        """,
        {"idp_id": idp_id},
    )


def get_by_hash(tenant_id: TenantArg, token_hash: str) -> dict | None:
    """Look up an inbound SCIM token by its SHA-256 hex digest.

    Used by the inbound SCIM bearer-auth dependency (iteration 2). The
    caller must check `revoked_at` before accepting the token; this
    function returns the row regardless so the auth path can distinguish
    "no such token" from "revoked".

    Args:
        tenant_id: Tenant scope (typically `UNSCOPED` because the auth
            path needs to find the row before tenant context is known --
            the token's `tenant_id` becomes the request scope).
        token_hash: SHA-256 hex digest of the bearer plaintext.

    Returns:
        Dict with id, tenant_id, idp_id, revoked_at, or None.
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, idp_id, name, created_by_user_id,
               created_at, revoked_at, last_used_at
        from scim_inbound_tokens
        where token_hash = :token_hash
        """,
        {"token_hash": token_hash},
    )


def get_token(tenant_id: TenantArg, token_id: str) -> dict | None:
    """Fetch a single token row by id within the tenant scope."""
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, idp_id, name, created_by_user_id,
               created_at, revoked_at, last_used_at
        from scim_inbound_tokens
        where id = :id
        """,
        {"id": token_id},
    )


def revoke(tenant_id: TenantArg, token_id: str) -> int:
    """Mark an inbound SCIM token as revoked. Returns rows updated.

    Idempotent: a second revoke on the same row is a no-op (the WHERE
    clause excludes already-revoked rows so this returns 0). Inbound has
    no overlap window -- revocation is instant.
    """
    return execute(
        tenant_id,
        """
        update scim_inbound_tokens
        set revoked_at = now()
        where id = :id and revoked_at is null
        """,
        {"id": token_id},
    )


def touch_last_used(tenant_id: TenantArg, token_id: str) -> int:
    """Record that the token was used to authenticate a request just now.

    Called by the inbound bearer-auth dependency after a successful match
    (iteration 2). Best-effort -- the caller does not gate request
    handling on the update succeeding.
    """
    return execute(
        tenant_id,
        """
        update scim_inbound_tokens
        set last_used_at = now()
        where id = :id
        """,
        {"id": token_id},
    )
