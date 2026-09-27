"""OIDC ID-token minting.

Mints signed RS256 ID tokens for the downstream OIDC provider. The token is
signed with the tenant's active signing key (Iteration 1) and carries the
`kid` header so relying parties can select the matching JWKS key to verify it.

An ID token is only ever minted for a client that has opted into OIDC
(`oidc_enabled`) and a request that included the `openid` scope; the router
enforces that gate before calling here, and this module keeps that contract in
its docstring so plain-OAuth2 issuance is never affected.

Envelope claims added here (OpenID Connect Core 1.0, section 2):
  * ``iss``       - the tenant issuer (the request's tenant host)
  * ``sub``       - the stable WeftID user id (never the email)
  * ``aud``       - the client's public client_id
  * ``exp`` / ``iat`` - token lifetime
  * ``auth_time`` - the user's authentication time
  * ``nonce``     - echoed only when the request supplied one
  * ``sid``       - the WeftID session the user authenticated in (OpenID
    Connect Front-Channel / Back-Channel Logout 1.0), when known

Scope-gated identity claims (profile, email, groups) are NOT put in the ID
token. WeftID issues ID tokens only from the authorization code flow, where
an access token is always issued alongside, and OpenID Connect Core 1.0
section 5.4 defines those scopes as requests for the claims at the userinfo
endpoint. The ID token asserts the authentication event; the identity data
comes from userinfo (:mod:`services.oidc.userinfo`), so it is never exposed
to parties the RP later shows the ID token to.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import database
import jwt
from services.event_log import log_event
from services.oidc.keys import get_active_signing_key, get_verification_public_keys

# ID tokens are short-lived: they assert authentication at a point in time and
# are consumed immediately by the RP. One hour matches the OAuth2 access-token
# lifetime already used in this codebase.
ID_TOKEN_EXPIRY = timedelta(hours=1)


def issue_id_token(
    *,
    tenant_id: str,
    issuer: str,
    client_uuid: str,
    client_id: str,
    user_id: str,
    scopes: set[str],
    nonce: str | None = None,
    auth_time: datetime | None = None,
    sid: str | None = None,
) -> str:
    """Mint and return a signed RS256 ID token for a user.

    Authorization: none of its own -- the caller (token endpoint) must have
    already authenticated the client, validated the code, and confirmed the
    client is `oidc_enabled` with the `openid` scope present.

    Logs: ``oidc_id_token_issued`` (one issuance, one log). With a ``sid``
    the issuance is also recorded against that session, so ending the session
    can notify this client (front-channel logout).

    Args:
        tenant_id: Tenant ID for RLS scoping and signing-key resolution.
        issuer: The `iss` value -- the tenant host base URL the RP used.
        client_uuid: The client's internal UUID, used as the audit artifact id.
        client_id: The public client_id string, used as the `aud`.
        user_id: The subject; becomes `sub` (stable WeftID id, never email).
        scopes: Granted scope names (recorded in the audit event only).
        nonce: Request nonce; echoed into the token only when supplied.
        auth_time: The user's authentication time. Falls back to issuance time
            (`iat`) when not recorded on the code.
        sid: The session identifier recorded on the code. Omitted when absent
            (codes issued before the identifier existed); such a token is not
            tied to a session and no logout reaches its client.

    Returns:
        The compact-serialized signed JWT string.
    """
    now = datetime.now(UTC)
    issued_at = int(now.timestamp())
    expires_at = int((now + ID_TOKEN_EXPIRY).timestamp())

    # auth_time defaults to issuance time when the session login timestamp was
    # not captured on the authorization code.
    effective_auth_time = int(auth_time.timestamp()) if auth_time is not None else issued_at

    payload: dict = {
        "iss": issuer,
        "sub": str(user_id),
        "aud": client_id,
        "iat": issued_at,
        "exp": expires_at,
        "auth_time": effective_auth_time,
    }

    # Echo the nonce only when the RP supplied one (OIDC Core 3.1.2.1).
    if nonce:
        payload["nonce"] = nonce
    if sid:
        payload["sid"] = sid

    signing_key = get_active_signing_key(tenant_id)
    id_token = jwt.encode(
        payload,
        signing_key.private_key_pem,
        algorithm=signing_key.algorithm,
        headers={"kid": signing_key.kid},
    )

    if sid:
        database.oauth2.upsert_session_client(
            tenant_id, tenant_id, sid=sid, client_id=str(client_uuid), user_id=str(user_id)
        )

    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="oauth2_client",
        artifact_id=str(client_uuid),
        event_type="oidc_id_token_issued",
        metadata={
            "client_id": client_id,
            "kid": signing_key.kid,
            "scopes": sorted(scopes),
            "nonce_echoed": bool(nonce),
        },
    )

    return id_token


def verify_id_token_hint(
    *,
    tenant_id: str,
    issuer: str,
    client_id: str,
    id_token: str,
) -> dict | None:
    """Verify an ``id_token_hint`` and return its claims, or ``None``.

    Authorization: none -- the authorization endpoint calls this before any
    user interaction. Read-only; nothing is logged.

    The hint is a WeftID-issued ID token the RP received earlier (OpenID
    Connect Core 1.0, section 3.1.2.1). It is accepted when it was signed by
    one of this tenant's signing keys (active or previous, selected by the
    ``kid`` header), carries this tenant's ``iss`` and the requesting client's
    ``client_id`` in ``aud``. Expiry is deliberately **not** enforced: a hint
    is routinely presented after the token has expired (the spec allows an
    expired hint), and the caller only uses its ``sub`` to compare with the
    current session. Any other verification failure returns ``None``.
    """
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        return None
    kid = header.get("kid")
    if not isinstance(kid, str):
        return None
    public_key_pem = get_verification_public_keys(tenant_id).get(kid)
    if public_key_pem is None:
        return None
    try:
        claims = jwt.decode(
            id_token,
            public_key_pem,
            algorithms=["RS256"],
            audience=client_id,
            issuer=issuer,
            options={"verify_exp": False, "require": ["iss", "sub", "aud"]},
        )
    except jwt.PyJWTError:
        return None
    return claims if isinstance(claims.get("sub"), str) else None
