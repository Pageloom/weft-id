"""OpenID Connect logout: end_session requests and the relying-party fan-out.

``resolve_end_session_request`` implements RP-Initiated Logout 1.0;
``end_oidc_session`` implements the OP side of Front-Channel Logout 1.0 and
queues the logout tokens of Back-Channel Logout 1.0 (sent by the worker, see
``services.oidc.backchannel``).

A relying party sends the browser to the end_session endpoint with any of
``id_token_hint``, ``client_id``, ``post_logout_redirect_uri`` and ``state``.
This module decides what WeftID may trust about that request; the router
decides what to show and whether to end the session.

Trust rules:

* ``id_token_hint`` is verified exactly like the authorization endpoint's
  hint (tenant signing key, ``iss``, ``aud``; expiry not enforced). Its
  ``aud`` names the client when ``client_id`` is absent; when both are
  present they must agree (a hint for another client fails verification).
* ``post_logout_redirect_uri`` is honoured only with a verified hint and only
  when it exactly matches one of that client's registered
  ``post_logout_redirect_uris``. Without a hint WeftID never redirects
  (section 2: the OP MUST NOT redirect unless it can confirm the target is
  legitimate), because anyone can put a ``client_id`` in a link.

Resolution writes and logs nothing, like ``verify_id_token_hint``.

Front-channel fan-out: every ID token issued in a session is recorded
against the session's ``sid`` (``issue_id_token``). When the session ends,
``end_oidc_session`` deletes those records and returns the front-channel
logout URLs of the clients that registered one, for the logout page to load
in iframes, queues a back-channel delivery for each client that registered a
back-channel logout URI, and revokes the refresh tokens issued in the session
(Back-Channel Logout 1.0, section 2.7).

A user's deactivation or deletion ends every session they hold:
``end_user_oidc_sessions`` queues the back-channel deliveries for all of them.
There is no browser, so front-channel logout does not apply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlencode

import database
import jwt
import settings
from services.oidc.tokens import verify_id_token_hint
from services.sessions import revoke_session

# Why an end_session request cannot be honoured as sent. The router shows the
# confirmation page (never an RP redirect) whenever one of these is set.
PROBLEM_INVALID_ID_TOKEN_HINT = "invalid_id_token_hint"
PROBLEM_UNKNOWN_CLIENT = "unknown_client"
PROBLEM_ID_TOKEN_HINT_REQUIRED = "id_token_hint_required"
PROBLEM_UNREGISTERED_POST_LOGOUT_REDIRECT_URI = "unregistered_post_logout_redirect_uri"


@dataclass(frozen=True)
class EndSessionRequest:
    """What WeftID may trust about an end_session request.

    Attributes:
        client: The client the request is for, when named by a verified hint
            or by ``client_id`` (active, normal clients only).
        hint_claims: The verified ``id_token_hint`` claims, or None.
        post_logout_redirect_uri: The verified redirect target, or None. Only
            ever set together with ``hint_claims``.
        problem: One of the ``PROBLEM_*`` codes, or None.
    """

    client: dict | None = None
    hint_claims: dict | None = None
    post_logout_redirect_uri: str | None = None
    problem: str | None = None

    @property
    def hint_subject(self) -> str | None:
        """The verified hint's ``sub`` (the WeftID user id), or None."""
        return self.hint_claims["sub"] if self.hint_claims else None


def _active_normal_client(tenant_id: str, client_id: str) -> dict | None:
    client = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if not client or client["client_type"] != "normal" or not client.get("is_active", True):
        return None
    return client


def _hint_audience(id_token_hint: str) -> str | None:
    """The single audience of an (as yet unverified) ID token, or None.

    Used only to pick which client's audience to verify against; the
    signature check that follows is what makes the value trustworthy.
    """
    try:
        claims = jwt.decode(id_token_hint, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) == 1:
        aud = aud[0]
    return aud if isinstance(aud, str) and aud else None


def resolve_end_session_request(
    *,
    tenant_id: str,
    issuer: str,
    id_token_hint: str | None,
    client_id: str | None,
    post_logout_redirect_uri: str | None,
) -> EndSessionRequest:
    """Resolve an end_session request into what may be trusted.

    Authorization: none -- the end_session endpoint is public and this is a
    read-only check performed before any user interaction.

    Args:
        tenant_id: Tenant ID for RLS scoping and signing-key resolution.
        issuer: The tenant issuer (request host base URL) the hint must carry.
        id_token_hint: A WeftID-issued ID token, when the RP sent one.
        client_id: The RP's client_id, when sent.
        post_logout_redirect_uri: Where the RP asks to be sent afterwards.

    Returns:
        The resolved request. ``problem`` is set whenever the request cannot
        be honoured as sent; the client is then only reported when it was
        named by ``client_id`` and the problem is not about the client.
    """
    client: dict | None = None
    hint_claims: dict | None = None

    if id_token_hint:
        audience = client_id or _hint_audience(id_token_hint)
        candidate = _active_normal_client(tenant_id, audience) if audience else None
        if candidate is not None:
            hint_claims = verify_id_token_hint(
                tenant_id=tenant_id,
                issuer=issuer,
                client_id=candidate["client_id"],
                id_token=id_token_hint,
            )
        if hint_claims is None:
            return EndSessionRequest(problem=PROBLEM_INVALID_ID_TOKEN_HINT)
        client = candidate
    elif client_id:
        client = _active_normal_client(tenant_id, client_id)
        if client is None:
            return EndSessionRequest(problem=PROBLEM_UNKNOWN_CLIENT)

    if not post_logout_redirect_uri:
        return EndSessionRequest(client=client, hint_claims=hint_claims)

    # A verified hint always names its client, so ``client`` is only None here
    # when there was no hint.
    if hint_claims is None or client is None:
        return EndSessionRequest(client=client, problem=PROBLEM_ID_TOKEN_HINT_REQUIRED)

    if post_logout_redirect_uri not in (client.get("post_logout_redirect_uris") or []):
        return EndSessionRequest(
            client=client,
            hint_claims=hint_claims,
            problem=PROBLEM_UNREGISTERED_POST_LOGOUT_REDIRECT_URI,
        )

    return EndSessionRequest(
        client=client,
        hint_claims=hint_claims,
        post_logout_redirect_uri=post_logout_redirect_uri,
    )


def _frontchannel_logout_url(client: dict, *, issuer: str, sid: str) -> str:
    """The client's front-channel logout URI with ``iss``/``sid`` when required.

    The parameters are appended to any query the RP registered (Front-Channel
    Logout 1.0, section 2 allows one).
    """
    uri: str = client["frontchannel_logout_uri"]
    if not client.get("frontchannel_logout_session_required"):
        return uri
    separator = "&" if "?" in uri else "?"
    return f"{uri}{separator}{urlencode({'iss': issuer, 'sid': sid})}"


@dataclass(frozen=True)
class OidcSessionEnd:
    """How the relying parties of an ending session are being notified.

    Attributes:
        frontchannel_logout_urls: Front-channel logout URLs for the logout
            page to load in iframes, in first-issued order, deduplicated.
        backchannel_logout_count: Back-channel logout deliveries queued for
            the worker.
        refresh_tokens_revoked: Refresh tokens issued in the session that
            were revoked with it.
    """

    frontchannel_logout_urls: list[str] = field(default_factory=list)
    backchannel_logout_count: int = 0
    refresh_tokens_revoked: int = 0


def end_oidc_session(
    *,
    tenant_id: str,
    issuer: str,
    sid: str | None,
    exclude_client_uuid: str | None = None,
) -> OidcSessionEnd:
    """Notify the clients that received ID tokens in a session that is ending.

    Authorization: none -- called only while the session itself is being
    terminated (logout button, end_session endpoint, forced
    re-authentication), for that session's own ``sid``.

    No audit of its own: the caller's ``user_signed_out`` event records the
    logout, including the front-channel URL, back-channel delivery and
    revoked refresh-token counts.

    The session's records are consumed, and a back-channel logout delivery is
    queued for every active OIDC client that registered a
    ``backchannel_logout_uri``, in the same database statement; the worker
    sends the logout tokens (``services.oidc.backchannel``). The refresh
    tokens issued in the session are revoked, for every client including an
    excluded one (a re-authenticating client receives new tokens for the new
    session), and so are the access tokens minted from them. The session
    itself is revoked server-side first (``services.sessions``), so a copy of
    its cookie is refused from now on.

    Args:
        tenant_id: Tenant ID for RLS scoping.
        issuer: The tenant issuer, sent as ``iss`` to front-channel clients
            that require it and as the logout token's ``iss``.
        sid: The ending session's identifier; None (a session that never
            had one) notifies nobody.
        exclude_client_uuid: A client not to notify (its record is still
            removed). Forced re-authentication passes the client that asked
            for it: that RP is mid-login, and a logout would clear the state it
            keeps for the authorization response.

    Returns:
        The front-channel logout URLs to load (one per active OIDC client that
        registered a ``frontchannel_logout_uri``), how many back-channel
        deliveries were queued, and how many refresh tokens were revoked.
    """
    if not sid:
        return OidcSessionEnd()
    revoke_session(tenant_id=tenant_id, sid=sid)
    urls: list[str] = []
    rows = database.oauth2.consume_session_clients(
        tenant_id,
        tenant_id,
        sid,
        issuer=issuer,
        exclude_client_id=exclude_client_uuid,
    )
    for client in sorted(rows, key=lambda row: row["created_at"]):
        if (
            not client.get("frontchannel_logout_uri")
            or client.get("client_type") != "normal"
            or not client.get("is_active", True)
            or not client.get("oidc_enabled")
            or str(client["id"]) == exclude_client_uuid
        ):
            continue
        url = _frontchannel_logout_url(client, issuer=issuer, sid=sid)
        if url not in urls:
            urls.append(url)
    revoked = database.oauth2.revoke_session_refresh_tokens(tenant_id, sid)
    return OidcSessionEnd(
        frontchannel_logout_urls=urls,
        backchannel_logout_count=sum(1 for row in rows if row.get("backchannel_queued")),
        refresh_tokens_revoked=revoked,
    )


def _canonical_issuer(tenant_id: str) -> str:
    """The tenant's canonical ``https://<subdomain>.<BASE_DOMAIN>`` issuer.

    Only a fallback: session records carry the issuer of the ID token that
    created them, except records written before the issuer was recorded.
    """
    tenant = database.tenants.get_tenant_by_id(tenant_id)
    if not tenant or not tenant.get("subdomain") or not settings.BASE_DOMAIN:
        return ""
    return f"https://{tenant['subdomain']}.{settings.BASE_DOMAIN}"


def end_user_oidc_sessions(*, tenant_id: str, user_id: str) -> int:
    """Queue back-channel logouts for every session a user holds.

    Authorization: none -- called by the user lifecycle paths (deactivation,
    anonymization, deletion) after their own authorization, and by worker
    jobs that deactivate users.

    No audit of its own: the caller's lifecycle event records the action; the
    queued deliveries are their own log. Every session record of the user is
    consumed and one delivery is queued per (session, back-channel client),
    in one database statement. Refresh tokens are not touched here: the
    lifecycle paths revoke all of the user's tokens themselves, and deletion
    cascades.

    Must run **before** a user row is deleted: session records cascade with
    the user, deliveries do not (they carry the user id as ``sub``).

    Returns:
        The number of back-channel deliveries queued.
    """
    tenant_id = str(tenant_id)
    rows = database.oauth2.consume_user_session_clients(
        tenant_id, tenant_id, str(user_id), issuer=_canonical_issuer(tenant_id)
    )
    return sum(1 for row in rows if row.get("backchannel_queued"))
