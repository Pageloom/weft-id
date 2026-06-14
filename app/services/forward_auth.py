"""Forward-auth token redemption: stateless verify + atomic single-use consume.

This service composes the pure crypto primitives in ``utils.forward_auth`` with
the DB-backed nonce store (``database.forward_auth_nonces``) to mint and redeem
the short-lived, single-use authorization token of the handshake. It contains no
HTTP wiring; the iteration-5 runtime calls these functions.

  * ``issue_authorization_token`` -- mint the token AND record its nonce, so the
    token can later be redeemed exactly once. Runs on the canonical tenant host
    with a known tenant scope.

  * ``redeem_authorization_token`` -- verify the token (signature, expiry,
    domain binding) AND atomically consume its nonce. Returns the bound identity
    on success, or None on any failure (bad signature, expiry, cross-domain
    substitution, or replay/double-spend). Runs pre-auth on the portal host, so
    it consumes with ``UNSCOPED``.

The single-use guarantee comes from the atomic ``DELETE ... RETURNING`` in
``consume_nonce``: only the first redemption finds and deletes the nonce row;
every replay or concurrent race gets None. There is no check-then-write window,
so double-spend is impossible even under concurrent callbacks.
"""

from datetime import UTC, datetime
from typing import Any

import database
from utils.forward_auth import (
    FORWARD_AUTH_TOKEN_TTL,
    generate_nonce,
    mint_authorization_token,
    verify_authorization_token,
)


def issue_authorization_token(
    *,
    user_id: str,
    tenant_id: str,
    domain: str,
    app_id: str,
    rd: str,
    ttl_seconds: int = FORWARD_AUTH_TOKEN_TTL,
) -> str:
    """Mint a single-use authorization token and record its nonce.

    The nonce is recorded BEFORE the token is handed out so a redemption can
    always find (and consume) it. Runs on the canonical tenant host where the
    tenant scope is known, so the nonce row is written tenant-scoped.

    Args:
        user_id: The authenticated user the token authorizes.
        tenant_id: The minting (home) tenant.
        domain: The protected domain the token (and later cookie) is bound to.
        app_id: The proxy app being authorized.
        rd: The post-handshake redirect target (validated by the runtime).
        ttl_seconds: Token lifetime in seconds (short).

    Returns:
        The signed token string to place in the callback URL.
    """
    nonce = generate_nonce()
    expires_at = datetime.fromtimestamp(datetime.now(UTC).timestamp() + ttl_seconds, tz=UTC)

    database.forward_auth_nonces.create_nonce(
        tenant_id,
        tenant_id,
        nonce,
        domain,
        expires_at,
    )

    return mint_authorization_token(
        user_id=user_id,
        tenant_id=tenant_id,
        domain=domain,
        app_id=app_id,
        rd=rd,
        nonce=nonce,
        ttl_seconds=ttl_seconds,
    )


def redeem_authorization_token(
    token: str,
    *,
    expected_domain: str,
) -> dict[str, Any] | None:
    """Verify a token and atomically consume its nonce (single-use redemption).

    Order matters: verify the stateless parts first (cheap, no DB), then consume
    the nonce. The consume is the single-use gate -- a replayed token whose
    nonce was already spent returns None even though its signature/expiry/domain
    still check out. The nonce is also re-bound to ``expected_domain`` in the
    delete predicate as defense-in-depth against cross-domain substitution.

    Runs pre-auth on the portal host: the nonce is consumed with ``UNSCOPED``
    because no central session/tenant scope exists at the callback. The 0048 RLS
    policy permits this UNSCOPED consume the same way 0047 does for the
    portal-host lookup; the nonce is a 256-bit secret and the token's HMAC binds
    {tenant, domain, ...}, so an UNSCOPED consume grants nothing on its own.

    Args:
        token: The token from the callback URL.
        expected_domain: The protected domain the callback is redeeming for.

    Returns:
        The validated token payload (``sub``, ``tid``, ``dom``, ``app``, ``rd``,
        ``nonce``, ``exp``) on success, or None on any failure: bad signature,
        expired token, cross-domain substitution, or replay/double-spend.
    """
    payload = verify_authorization_token(token, expected_domain=expected_domain)
    if payload is None:
        return None

    consumed = database.forward_auth_nonces.consume_nonce(
        database.UNSCOPED,
        payload["nonce"],
        expected_domain,
    )
    if consumed is None:
        # Nonce already spent (replay) or never minted -> reject.
        return None

    # Defense-in-depth: the consumed row's tenant must match the token's bound
    # tenant. The token HMAC already guarantees this, but a mismatch indicates
    # tampering somewhere upstream; fail closed.
    if str(consumed["tenant_id"]) != str(payload["tid"]):
        return None

    return payload
