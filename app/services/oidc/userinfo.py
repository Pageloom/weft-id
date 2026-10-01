"""OIDC userinfo claim assembly.

Assembles the userinfo response for an authenticated bearer access token. The
token's persisted scope (Iteration 2) gates which claims are released, and the
claims themselves come from the SINGLE shared assembler
(:mod:`services.oidc.claims`) -- the same one the ID-token minter uses -- so the
userinfo response and the ID token can never carry different claims for the same
granted scopes. The only claim this layer adds is `sub`, which the userinfo
response MUST include (OpenID Connect Core 1.0, section 5.3.2): the client's
subject identifier for the user (the WeftID user id, or a pairwise value).

The caller (the userinfo router / its bearer dependency) is responsible for
authenticating the access token and returning the correct OAuth2 error on an
invalid/expired/revoked/missing token; this service assumes an already-validated
token and only assembles + audits the claim release.

A client that registered ``userinfo_signed_response_alg`` (RS256) gets the
claims as a JWT signed with the tenant's OIDC key, with ``iss`` and ``aud``
added (Core 5.3.2); :func:`sign_userinfo` builds it.
"""

from __future__ import annotations

import jwt
from services.activity import track_activity
from services.event_log import log_event
from services.oidc import claims as claims_service
from services.oidc.keys import get_active_signing_key

USERINFO_SIGNING_ALG_VALUES_SUPPORTED = ("RS256",)


def get_userinfo(
    *,
    tenant_id: str,
    user_id: str,
    client_uuid: str,
    client_id: str,
    scope: str | None,
    subject: str | None = None,
) -> dict:
    """Assemble the scope-gated userinfo claims for a validated bearer token.

    Authorization: none of its own -- the caller must have already validated the
    access token and resolved the token's subject, client, and granted scope.

    Reads: tracked via ``track_activity`` (userinfo is a read of the subject's
    identity).

    Logs: ``oidc_userinfo_accessed`` (audit trail of an identity release to a
    downstream client).

    Args:
        tenant_id: Tenant ID for RLS scoping.
        user_id: The token subject's stable WeftID id.
        subject: The ``sub`` the client knows the user by
            (:func:`services.oidc.subject.subject_for`). Defaults to
            ``user_id``, which is only right for a public-subject client.
        client_uuid: The client's internal UUID (audit artifact id).
        client_id: The client's public client_id (recorded in the audit metadata).
        scope: The token's persisted space-delimited granted scope. Gates which
            profile/email claims are released; `sub` is always present regardless.

    Returns:
        A dict of released claims, always including `sub`.
    """
    track_activity(tenant_id, str(user_id))

    scopes = claims_service.parse_scope(scope)

    # Reuse the single shared assembler so userinfo and the ID token can never
    # drift. It never emits `sub`; we add the client's subject identifier here.
    userinfo: dict = claims_service.build_claims(tenant_id, str(user_id), scopes)
    userinfo["sub"] = subject if subject is not None else str(user_id)

    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user_id),
        artifact_type="oauth2_client",
        artifact_id=str(client_uuid),
        event_type="oidc_userinfo_accessed",
        metadata={
            "client_id": client_id,
            "scopes": sorted(scopes),
        },
    )

    return userinfo


def userinfo_signing_alg(client: dict) -> str | None:
    """The ``userinfo_signed_response_alg`` the client registered, if any."""
    alg = (client.get("registration_metadata") or {}).get("userinfo_signed_response_alg")
    return alg if alg in USERINFO_SIGNING_ALG_VALUES_SUPPORTED else None


def sign_userinfo(*, tenant_id: str, issuer: str, client: dict, userinfo: dict) -> str | None:
    """Sign the userinfo claims for a client that asked for a signed response.

    Authorization: none of its own -- ``userinfo`` was assembled (and audited)
    by :func:`get_userinfo` for a validated token of this client.

    Returns:
        The compact JWT (``iss`` the issuer, ``aud`` the client_id), or None
        when the client takes plain JSON.
    """
    alg = userinfo_signing_alg(client)
    if alg is None:
        return None
    signing_key = get_active_signing_key(tenant_id)
    payload = {**userinfo, "iss": issuer.rstrip("/"), "aud": client["client_id"]}
    return jwt.encode(
        payload,
        signing_key.private_key_pem,
        algorithm=alg,
        headers={"kid": signing_key.kid},
    )
