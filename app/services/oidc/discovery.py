"""OpenID Provider discovery metadata assembly.

Builds the discovery document (`/.well-known/openid-configuration`) that
relying parties fetch to learn the tenant's issuer and endpoint layout. The
document is assembled from the request's tenant base URL so the advertised
`issuer` and every endpoint match the exact host the RP used -- a request that
arrives on tenant A's host can never surface tenant B's issuer.

Advertisement policy: this document reflects ONLY what is actually implemented.
Logout, introspection, revocation, device grant, PAR, and dynamic client
registration are intentionally absent -- they are the separate "OIDC Hardening"
item. `scopes_supported` is sourced from the shared claim assembler's
``SUPPORTED_SCOPES`` so the advertised scopes and the scopes actually gated by
claim release can never drift; the `groups` scope is therefore advertised only
once Iteration 4 adds it to that tuple.
"""

from __future__ import annotations

from schemas.oidc import OIDCProviderMetadata
from services.oidc import claims as claims_service

# Subject identifier type. WeftID uses the stable user id directly (never a
# pairwise identifier); pairwise `sub` is deferred to the Hardening item.
SUBJECT_TYPES_SUPPORTED = ["public"]

# The only signing algorithm the signing-key model issues (Iteration 1).
ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = ["RS256"]

# The single authorization-endpoint response type the OAuth2 flow supports.
RESPONSE_TYPES_SUPPORTED = ["code"]

# Grant types the token endpoint accepts today.
GRANT_TYPES_SUPPORTED = ["authorization_code", "refresh_token", "client_credentials"]

# Claims that may appear in an ID token or a userinfo response. This is the
# union of the token-envelope claims added by the ID-token minter
# (services.oidc.tokens) and the scope-gated identity claims produced by the
# shared assembler (services.oidc.claims). Kept in step with those two modules
# so discovery never advertises a claim the provider cannot emit.
CLAIMS_SUPPORTED = [
    # Envelope claims (from the ID-token minter / userinfo endpoint).
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    # profile-scope claims.
    "name",
    "given_name",
    "family_name",
    "locale",
    "updated_at",
    # email-scope claims.
    "email",
    "email_verified",
    # groups-scope claim (WeftID extension: effective, DAG-aware memberships).
    "groups",
]


def build_discovery_metadata(issuer: str) -> OIDCProviderMetadata:
    """Assemble the OpenID Provider metadata for a tenant.

    Args:
        issuer: The tenant base URL (``https://<tenant-host>``) derived from the
            request host. Becomes the `issuer` and the prefix of every endpoint.

    Returns:
        The populated discovery document. All endpoints are absolute URLs on the
        same host, so `issuer` and the endpoints are consistent by construction.
    """
    base = issuer.rstrip("/")
    return OIDCProviderMetadata(
        issuer=base,
        authorization_endpoint=f"{base}/oauth2/authorize",
        token_endpoint=f"{base}/oauth2/token",
        userinfo_endpoint=f"{base}/userinfo",
        jwks_uri=f"{base}/.well-known/jwks.json",
        scopes_supported=list(claims_service.SUPPORTED_SCOPES),
        response_types_supported=list(RESPONSE_TYPES_SUPPORTED),
        grant_types_supported=list(GRANT_TYPES_SUPPORTED),
        subject_types_supported=list(SUBJECT_TYPES_SUPPORTED),
        id_token_signing_alg_values_supported=list(ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED),
        claims_supported=list(CLAIMS_SUPPORTED),
    )
