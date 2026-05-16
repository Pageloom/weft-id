"""Outbound SCIM bearer credential database operations.

Bearer tokens issued to WeftID by downstream Service Providers. Stored as
SHA-256 hashes only; plaintext is never persisted. Multiple active rows per
SP are supported for rotation-overlap windows.
"""

import re

from ._core import TenantArg, execute, fetchall, fetchone

# Accept simple `<int> <unit>` interval expressions for overlap windows.
# Anything more exotic should be passed as an explicit `revoke_at` timestamp.
_INTERVAL_RE = re.compile(
    r"^\s*(\d+)\s+(seconds?|minutes?|hours?|days?|weeks?|months?|years?)\s*$",
    re.IGNORECASE,
)


def create_credential(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sp_id: str,
    token_hash: str,
    created_by_user_id: str,
) -> dict:
    """Create a new SCIM bearer credential for a service provider.

    Args:
        tenant_id: Tenant scope for RLS.
        tenant_id_value: Tenant id as a string for the INSERT.
        sp_id: Service provider id this token belongs to.
        token_hash: SHA-256 hex digest of the plaintext token.
        created_by_user_id: User id of the admin creating the token.

    Returns:
        Dict with id, sp_id, tenant_id, token_hash, created_by_user_id,
        created_at, revoked_at, last_used_at.
    """
    result = fetchone(
        tenant_id,
        """
        insert into sp_scim_credentials (
            tenant_id, sp_id, token_hash, created_by_user_id
        ) values (
            :tenant_id, :sp_id, :token_hash, :created_by_user_id
        )
        returning id, tenant_id, sp_id, token_hash, created_by_user_id,
                  created_at, revoked_at, last_used_at
        """,
        {
            "tenant_id": tenant_id_value,
            "sp_id": sp_id,
            "token_hash": token_hash,
            "created_by_user_id": created_by_user_id,
        },
    )
    # Defensive: should never happen on INSERT with RETURNING
    assert result is not None
    return result


def list_active_credentials(tenant_id: TenantArg, sp_id: str) -> list[dict]:
    """List non-revoked credentials for a service provider, newest first."""
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, sp_id, token_hash, created_by_user_id,
               created_at, revoked_at, last_used_at
        from sp_scim_credentials
        where sp_id = :sp_id and revoked_at is null
        order by created_at desc
        """,
        {"sp_id": sp_id},
    )


def list_all_credentials(tenant_id: TenantArg, sp_id: str) -> list[dict]:
    """List all credentials (including revoked) for a service provider, newest first."""
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, sp_id, token_hash, created_by_user_id,
               created_at, revoked_at, last_used_at
        from sp_scim_credentials
        where sp_id = :sp_id
        order by created_at desc
        """,
        {"sp_id": sp_id},
    )


def get_credential_by_hash(tenant_id: TenantArg, token_hash: str) -> dict | None:
    """Look up a credential by token hash. Used to authenticate inbound use."""
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, sp_id, token_hash, created_by_user_id,
               created_at, revoked_at, last_used_at
        from sp_scim_credentials
        where token_hash = :token_hash
        """,
        {"token_hash": token_hash},
    )


def mark_revoked(tenant_id: TenantArg, credential_id: str) -> int:
    """Revoke a credential immediately. Returns number of rows updated."""
    return execute(
        tenant_id,
        """
        update sp_scim_credentials
        set revoked_at = now()
        where id = :id and revoked_at is null
        """,
        {"id": credential_id},
    )


def schedule_revocation(
    tenant_id: TenantArg,
    credential_id: str,
    revoke_at: str | None = None,
    overlap_interval: str = "24 hours",
) -> int:
    """Schedule a credential for revocation after a grace window.

    Used during rotation so the old token stays valid during the overlap
    window. Pass `revoke_at` for an explicit timestamp, otherwise the
    revocation is scheduled `overlap_interval` from now.

    Returns:
        Number of rows updated.
    """
    if revoke_at is not None:
        return execute(
            tenant_id,
            """
            update sp_scim_credentials
            set revoked_at = :revoke_at
            where id = :id and revoked_at is null
            """,
            {"id": credential_id, "revoke_at": revoke_at},
        )
    # psycopg's named-param parser treats `::interval` as a named parameter,
    # so we use make_interval() with a parsed integer + named unit instead.
    match = _INTERVAL_RE.match(overlap_interval)
    if not match:
        raise ValueError(
            f"overlap_interval must be like '24 hours' or '7 days', got {overlap_interval!r}"
        )
    qty = int(match.group(1))
    unit = match.group(2).lower().rstrip("s")
    column = {
        "second": "secs",
        "minute": "mins",
        "hour": "hours",
        "day": "days",
        "week": "weeks",
        "month": "months",
        "year": "years",
    }[unit]
    return execute(
        tenant_id,
        f"""
        update sp_scim_credentials
        set revoked_at = now() + make_interval({column} => :qty)
        where id = :id and revoked_at is null
        """,
        {"id": credential_id, "qty": qty},
    )


def update_last_used(tenant_id: TenantArg, credential_id: str) -> int:
    """Mark a credential as having been used just now. Returns rows updated."""
    return execute(
        tenant_id,
        """
        update sp_scim_credentials
        set last_used_at = now()
        where id = :id
        """,
        {"id": credential_id},
    )
