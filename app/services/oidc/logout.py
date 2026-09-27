"""OpenID Connect RP-Initiated Logout 1.0: end_session request resolution.

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

Nothing here writes or logs: resolution is a pure read, like
``verify_id_token_hint``.
"""

from __future__ import annotations

from dataclasses import dataclass

import database
import jwt
from services.oidc.tokens import verify_id_token_hint

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
