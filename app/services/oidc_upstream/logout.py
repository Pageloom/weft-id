"""OIDC upstream logout: WeftID as the relying party of an upstream IdP.

RP-Initiated Logout 1.0, RP side. When the connection has "sign out at the
provider" on and the provider publishes an ``end_session_endpoint``, a WeftID
sign-out sends the browser on to it (``build_upstream_logout_url``) with the
session's upstream ID token as ``id_token_hint``; the provider returns the
browser to WeftID's post-logout landing.

Back-Channel Logout 1.0, RP side. When a user signs in through an upstream
OIDC connection, ``record_upstream_session`` links the new WeftID session to
the upstream ``sub`` and, when the IdP sent one, the upstream ``sid``. When the
user's session at the IdP ends, the IdP POSTs a logout token to the
connection's back-channel logout URL; ``handle_backchannel_logout`` validates
it (section 2.6) and ends every WeftID session it names: the session is
revoked server-side (``services.sessions``), downstream back-channel logouts
are queued and the session's refresh tokens revoked (``end_oidc_session``).
Downstream front-channel logout cannot run: there is no browser.

Logout token validation (section 2.6):

* RS256 signature against the connection's JWKS (``kid`` required). An
  unknown ``kid`` refetches the JWKS at most once per
  ``_JWKS_REFETCH_INTERVAL`` per connection, so a stream of forged tokens
  cannot turn the receiver into a JWKS fetch amplifier.
* ``iss`` is the connection issuer, ``aud`` contains its client_id; ``iat``,
  ``exp`` and ``jti`` are required, ``exp``/``iat`` checked with leeway.
* ``typ`` header, when present, is ``logout+jwt`` (or plain ``JWT``).
* ``events`` has the back-channel logout member, an object.
* ``sid`` or ``sub`` present; ``nonce`` absent.
* ``jti`` not seen before for this connection (kept until the token expires).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import database
import jwt
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.oidc import end_oidc_session
from services.oidc_upstream import jwks as jwks_service
from services.oidc_upstream.errors import (
    IDTokenSignatureError,
    JwksError,
    LogoutTokenError,
)
from services.oidc_upstream.id_token import select_signing_key

logger = logging.getLogger(__name__)

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

# Algorithm is fixed, never taken from the token header (RFC 8725 2.1).
_ALLOWED_ALGORITHMS = ["RS256"]
_LEEWAY_SECONDS = 60
_ACCEPTED_TYP = frozenset({"logout+jwt", "application/logout+jwt", "jwt"})

# Upstream identifiers longer than the columns allow are not recorded (the
# link table has the same bound, so such a subject could not sign in anyway).
_MAX_UPSTREAM_ID_LENGTH = 255

# The ID token kept for id_token_hint (the column's bound). A longer one is
# dropped; the logout request then identifies WeftID by client_id alone.
MAX_STORED_ID_TOKEN_LENGTH = 16384

# At most one JWKS refetch per connection in this window (key rotation).
_JWKS_REFETCH_INTERVAL = 60.0
_refetch_lock = threading.Lock()
_last_refetch: dict[tuple[str, str], float] = {}


@dataclass(frozen=True)
class BackchannelLogoutResult:
    """What an accepted logout token ended."""

    sessions_ended: int
    matched_by: str


def record_upstream_session(
    *,
    tenant_id: str,
    sid: str,
    connection_id: str,
    user_id: str,
    upstream_sub: str,
    upstream_sid: str | None,
    id_token: str | None = None,
) -> bool:
    """Link WeftID session ``sid`` to the upstream sign-in that created it.

    Authorization: none -- called by login completion for the session it has
    just created, from values of an ID token that verified.

    No audit of its own: the ``user_signed_in`` event records the sign-in;
    the link is bookkeeping that lets the IdP's logout reach the session.

    ``id_token`` is the verified upstream ID token, kept as the
    ``id_token_hint`` of a later RP-initiated logout (dropped when longer than
    ``MAX_STORED_ID_TOKEN_LENGTH``).

    Returns:
        False when an identifier is too long to record (nothing written).
    """
    if len(upstream_sub) > _MAX_UPSTREAM_ID_LENGTH or (
        upstream_sid is not None and len(upstream_sid) > _MAX_UPSTREAM_ID_LENGTH
    ):
        logger.warning("Upstream session identifiers too long to record for %s", connection_id)
        return False
    database.oidc_upstream.record_idp_session(
        tenant_id,
        tenant_id,
        sid=sid,
        idp_id=connection_id,
        user_id=user_id,
        upstream_sub=upstream_sub,
        upstream_sid=upstream_sid,
        id_token=id_token if id_token and len(id_token) <= MAX_STORED_ID_TOKEN_LENGTH else None,
    )
    return True


def build_upstream_logout_url(
    *, tenant_id: str, sid: str, post_logout_redirect_uri: str
) -> str | None:
    """The provider's end_session URL for WeftID session ``sid``, or None.

    Authorization: none -- called while the session itself is being ended,
    before ``end_oidc_session`` forgets the upstream link.

    None unless the session began at an upstream OIDC connection that has
    "sign out at the provider" on and an ``end_session_endpoint``. The URL
    carries ``client_id`` and ``post_logout_redirect_uri`` always, and
    ``id_token_hint`` when the ID token was kept. Disabled connections still
    qualify: the session they created is being ended either way.

    No audit: the caller's ``user_signed_out`` event records the logout.
    """
    link = database.oidc_upstream.get_idp_session(tenant_id, sid)
    if link is None:
        return None
    connection = database.oidc_upstream.get_connection(tenant_id, str(link["idp_id"]))
    if connection is None or not connection.get("sign_out_at_idp"):
        return None
    endpoint = connection.get("end_session_endpoint")
    client_id = connection.get("client_id")
    if not endpoint or not client_id:
        return None
    params: dict[str, str] = {}
    if link.get("id_token"):
        params["id_token_hint"] = link["id_token"]
    params["client_id"] = client_id
    params["post_logout_redirect_uri"] = post_logout_redirect_uri
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{urlencode(params)}"


def _may_refetch(tenant_id: str, connection_id: str) -> bool:
    key = (tenant_id, connection_id)
    now = time.monotonic()
    with _refetch_lock:
        last = _last_refetch.get(key)
        if last is not None and now - last < _JWKS_REFETCH_INTERVAL:
            return False
        _last_refetch[key] = now
        return True


def _decode(token: str, key_set: jwt.PyJWKSet, *, issuer: str, client_id: str) -> dict:
    try:
        key = select_signing_key(token, key_set)
    except IDTokenSignatureError as exc:
        raise LogoutTokenError("signature", str(exc)) from exc
    try:
        return jwt.decode(
            token,
            key=key,
            algorithms=_ALLOWED_ALGORITHMS,
            audience=client_id,
            issuer=issuer,
            leeway=_LEEWAY_SECONDS,
            options={"require": ["iss", "aud", "iat", "exp", "jti"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise LogoutTokenError("expired", "Logout token is expired") from exc
    except jwt.InvalidIssuerError as exc:
        raise LogoutTokenError("issuer", "Logout token issuer does not match") from exc
    except jwt.InvalidAudienceError as exc:
        raise LogoutTokenError("audience", "Logout token audience does not match") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise LogoutTokenError("missing_claim", f"Logout token missing claim: {exc}") from exc
    except (jwt.ImmatureSignatureError, jwt.InvalidIssuedAtError) as exc:
        raise LogoutTokenError("not_yet_valid", "Logout token is not yet valid") from exc
    except jwt.exceptions.InvalidSubjectError as exc:
        raise LogoutTokenError("sub", "Logout token sub is not a string") from exc
    except jwt.exceptions.InvalidJTIError as exc:
        raise LogoutTokenError("jti", "Logout token jti is not a string") from exc
    except jwt.InvalidAlgorithmError as exc:
        raise LogoutTokenError("algorithm", "Logout token algorithm is not RS256") from exc
    except jwt.InvalidSignatureError as exc:
        raise LogoutTokenError("signature", "Logout token signature did not verify") from exc
    except jwt.InvalidTokenError as exc:
        # Structural problems (bad encoding, non-numeric exp): not a key
        # rotation symptom, so no JWKS refetch.
        raise LogoutTokenError("malformed", f"Logout token is malformed: {exc}") from exc


def validate_logout_token(
    *,
    token: str,
    tenant_id: str,
    connection_id: str,
    issuer: str,
    client_id: str,
    jwks_uri: str,
) -> dict:
    """Validate an upstream logout token (section 2.6) and return its claims.

    Replay (``jti``) is checked by ``handle_backchannel_logout``, which owns
    the write.

    Raises:
        LogoutTokenError: on any failure.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise LogoutTokenError("malformed", f"Logout token is not a JWT: {exc}") from exc
    typ = header.get("typ")
    if typ is not None and (not isinstance(typ, str) or typ.lower() not in _ACCEPTED_TYP):
        raise LogoutTokenError("typ", f"Logout token has typ {typ!r}")

    try:
        key_set = jwks_service.get_jwks(tenant_id, connection_id, jwks_uri)
        try:
            claims = _decode(token, key_set, issuer=issuer, client_id=client_id)
        except LogoutTokenError as exc:
            if exc.reason != "signature" or not _may_refetch(tenant_id, connection_id):
                raise
            key_set = jwks_service.refresh_jwks(tenant_id, connection_id, jwks_uri)
            claims = _decode(token, key_set, issuer=issuer, client_id=client_id)
    except JwksError as exc:
        raise LogoutTokenError("jwks", str(exc)) from exc

    events = claims.get("events")
    if not isinstance(events, dict) or not isinstance(events.get(BACKCHANNEL_LOGOUT_EVENT), dict):
        raise LogoutTokenError("events", "Logout token has no back-channel logout event")
    if "nonce" in claims:
        raise LogoutTokenError("nonce", "Logout token must not contain a nonce")
    sid = claims.get("sid")
    sub = claims.get("sub")
    if sid is not None and not isinstance(sid, str):
        raise LogoutTokenError("sid", "Logout token sid is not a string")
    if sub is not None and not isinstance(sub, str):
        raise LogoutTokenError("sub", "Logout token sub is not a string")
    if not sid and not sub:
        raise LogoutTokenError("missing_claim", "Logout token has neither sid nor sub")
    if not isinstance(claims.get("jti"), str) or not claims["jti"]:
        raise LogoutTokenError("jti", "Logout token jti is empty")
    return claims


def _log_rejection(tenant_id: str, connection: dict, error: LogoutTokenError) -> None:
    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="oidc_idp_connection",
        artifact_id=str(connection["id"]),
        event_type="oidc_idp_logout_rejected",
        metadata={
            "idp_name": connection.get("name"),
            "reason": error.reason,
            "detail": str(error)[:500],
        },
    )


def handle_backchannel_logout(
    *,
    tenant_id: str,
    connection_id: str,
    logout_token: str,
    issuer: str,
) -> BackchannelLogoutResult:
    """Validate an upstream logout token and end the WeftID sessions it names.

    Authorization: the logout token itself -- signed by the connection's IdP
    and bound to its client_id. The endpoint is unauthenticated otherwise.

    Logs ``user_signed_out`` (reason ``upstream_backchannel_logout``) for each
    ended session, and ``oidc_idp_logout_rejected`` when a token for a known
    connection fails validation or is replayed.

    With ``sid`` the sessions created by that upstream session end (narrowed
    to ``sub`` when both are present); with only ``sub``, every session of
    that subject at this connection. No matching session is still a success
    (section 2.8: the logout already holds).

    Args:
        tenant_id: Tenant ID.
        connection_id: The upstream connection the IdP was configured with.
        logout_token: The compact JWT from the ``logout_token`` form field.
        issuer: The tenant issuer, the ``iss`` of downstream logout tokens for
            session records written before the issuer was recorded.

    Raises:
        LogoutTokenError: when the token is rejected (the caller answers 400).
    """
    connection = database.oidc_upstream.get_connection(tenant_id, connection_id)
    if connection is None:
        raise LogoutTokenError("unknown_connection", "No such connection")
    if not connection.get("jwks_uri") or not connection.get("client_id"):
        error = LogoutTokenError("configuration_error", "Connection has no JWKS or client_id")
        _log_rejection(tenant_id, connection, error)
        raise error

    try:
        claims = validate_logout_token(
            token=logout_token,
            tenant_id=tenant_id,
            connection_id=connection_id,
            issuer=connection["issuer"],
            client_id=connection["client_id"],
            jwks_uri=connection["jwks_uri"],
        )
        expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=UTC) + timedelta(
            seconds=_LEEWAY_SECONDS
        )
        if len(claims["jti"]) > _MAX_UPSTREAM_ID_LENGTH or not (
            database.oidc_upstream.consume_logout_token_jti(
                tenant_id,
                tenant_id,
                idp_id=connection_id,
                jti=claims["jti"],
                expires_at=expires_at,
            )
        ):
            raise LogoutTokenError("replay", "Logout token jti was already used")
    except LogoutTokenError as error:
        _log_rejection(tenant_id, connection, error)
        raise

    upstream_sid = claims.get("sid") or None
    upstream_sub = claims.get("sub") or None
    rows = database.oidc_upstream.find_idp_sessions(
        tenant_id, connection_id, upstream_sid=upstream_sid, upstream_sub=upstream_sub
    )
    matched_by = "sid" if upstream_sid else "sub"
    for row in rows:
        ended = end_oidc_session(tenant_id=tenant_id, issuer=issuer, sid=row["sid"])
        user_id = str(row["user_id"])
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            artifact_type="user",
            artifact_id=user_id,
            event_type="user_signed_out",
            metadata={
                "reason": "upstream_backchannel_logout",
                "idp_id": connection_id,
                "idp_name": connection.get("name"),
                "matched_by": matched_by,
                "backchannel_logout_count": ended.backchannel_logout_count,
                "refresh_tokens_revoked": ended.refresh_tokens_revoked,
            },
        )
    return BackchannelLogoutResult(sessions_ended=len(rows), matched_by=matched_by)
