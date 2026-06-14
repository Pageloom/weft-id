"""Single-use nonce store for forward-auth authorization tokens.

The forward-auth handshake mints a short-lived, single-use authorization token
(carried from `/forward-auth/authorize` on the canonical tenant host to
`/forward-auth/callback` on the portal host). Each token embeds a random nonce
that is recorded here at mint time and atomically consumed at redemption.

The consume is a single conditional `DELETE ... RETURNING`: the first redemption
deletes the row and returns it (accept); a concurrent or replayed second
redemption finds no row and returns None (reject). This is safe under concurrent
callbacks because the delete is atomic -- there is no check-then-write window.

All queries are RLS-scoped by tenant. The consume path runs pre-auth on the
portal host (no central session, no tenant scope yet), so it uses the UNSCOPED
sentinel; the 0048 RLS policy allows UNSCOPED reads/writes the same way 0047
does for protected_domains. The mint path runs on the canonical tenant host with
a known tenant scope.
"""

from datetime import datetime

from database._core import TenantArg, execute, fetchone


def create_nonce(
    tenant_id: TenantArg,
    tenant_id_value: str,
    nonce: str,
    domain: str,
    expires_at: datetime,
) -> dict | None:
    """Record a freshly minted nonce so its token can later be redeemed once.

    Runs on the canonical tenant host with a known tenant scope.

    Args:
        tenant_id: RLS scope (the minting tenant).
        tenant_id_value: The tenant UUID stored on the row.
        nonce: The random nonce embedded in the authorization token.
        domain: The protected domain the token is bound to.
        expires_at: When the nonce/token expires (basis for cleanup).

    Returns:
        The created nonce row, or None on failure.
    """
    return fetchone(
        tenant_id,
        """
        insert into forward_auth_nonces (nonce, tenant_id, domain, expires_at)
        values (:nonce, :tenant_id, :domain, :expires_at)
        returning nonce, tenant_id, domain, expires_at, created_at
        """,
        {
            "nonce": nonce,
            "tenant_id": tenant_id_value,
            "domain": domain,
            "expires_at": expires_at,
        },
    )


def consume_nonce(
    tenant_id: TenantArg,
    nonce: str,
    domain: str,
) -> dict | None:
    """Atomically consume a nonce, returning its row iff it was unconsumed.

    This is the single-use guard. The conditional `DELETE ... RETURNING` is
    atomic: exactly one concurrent caller can delete a given row and get it
    back; every other caller (replay or race) gets None. There is NO
    check-then-write window, so double-spend is impossible even under
    concurrent `/callback` redemptions.

    The `domain` predicate is defense-in-depth against cross-domain
    substitution: a nonce minted for one domain cannot be consumed against
    another (the token's HMAC already binds the domain, but this prevents the
    nonce being spent at all under the wrong domain).

    Runs pre-auth on the portal host, so callers pass UNSCOPED.

    Args:
        tenant_id: RLS scope (UNSCOPED on the pre-auth portal-host path).
        nonce: The nonce extracted from the redeemed token.
        domain: The protected domain the redemption is for.

    Returns:
        The consumed nonce row if it existed and matched the domain, else None
        (already consumed, never minted, or wrong domain).
    """
    return fetchone(
        tenant_id,
        """
        delete from forward_auth_nonces
        where nonce = :nonce and domain = :domain
        returning nonce, tenant_id, domain, expires_at, created_at
        """,
        {"nonce": nonce, "domain": domain},
    )


def delete_expired_nonces(tenant_id: TenantArg, now: datetime) -> int:
    """Purge expired nonce rows (cleanup path for iteration 5 / jobs).

    Args:
        tenant_id: RLS scope (UNSCOPED for a cross-tenant cleanup sweep).
        now: The cutoff; rows with expires_at <= now are deleted.

    Returns:
        Number of rows deleted.
    """
    return execute(
        tenant_id,
        "delete from forward_auth_nonces where expires_at <= :now",
        {"now": now},
    )
