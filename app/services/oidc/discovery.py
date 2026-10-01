"""OpenID Provider discovery metadata assembly.

Builds the discovery document (`/.well-known/openid-configuration`) that
relying parties fetch to learn the tenant's issuer and endpoint layout. The
document is assembled from the request's tenant base URL so the advertised
`issuer` and every endpoint match the exact host the RP used -- a request that
arrives on tenant A's host can never surface tenant B's issuer.

Advertisement policy: this document reflects ONLY what is actually implemented.
RP-initiated logout (``end_session_endpoint``), front-channel logout (with
``iss``/``sid``), back-channel logout (with ``sid``), token introspection (RFC
7662) and token revocation (RFC 7009) are advertised; dynamic client
registration (RFC 7591) is advertised only while the tenant has it turned on;
signed request objects and signed userinfo are advertised with their
algorithms; PAR is absent until it exists. `scopes_supported`
is sourced from the shared claim assembler's ``SUPPORTED_SCOPES`` so the
advertised scopes and the scopes actually gated by claim release can never
drift; the `groups` scope is therefore advertised only once Iteration 4 adds it
to that tuple.
"""

from __future__ import annotations

from schemas.oidc import OIDCProviderMetadata
from services import oauth2_client_auth, oauth2_request_objects
from services.oidc import claims as claims_service
from services.oidc import userinfo as userinfo_service

# Subject identifier type. WeftID uses the stable user id directly (never a
# pairwise identifier); pairwise `sub` is deferred to the Hardening item.
SUBJECT_TYPES_SUPPORTED = ["public"]

# The only signing algorithm the signing-key model issues (Iteration 1).
ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED = ["RS256"]

# The single authorization-endpoint response type the OAuth2 flow supports.
RESPONSE_TYPES_SUPPORTED = ["code"]

# How the authorization response reaches the RP: the redirect query (the
# default for `code`) or an auto-submitting HTML form POST (OAuth 2.0 Form
# Post Response Mode).
RESPONSE_MODES_SUPPORTED = ["query", "form_post"]

# Grant types the token endpoint accepts today.
GRANT_TYPES_SUPPORTED = [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
]

# Client authentication methods the introspection endpoint accepts (RFC 6749
# section 2.3.1). Basic is the spec-mandated method and the discovery default
# when the token endpoint's field is omitted; post is the form-field variant
# many SDKs send; private_key_jwt is a signed client assertion (RFC 7523).
# Introspection needs an authenticated client, so no "none".
CONFIDENTIAL_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "private_key_jwt"]

# JWS algorithms accepted for private_key_jwt assertions, at every endpoint
# that authenticates clients.
AUTH_SIGNING_ALG_VALUES_SUPPORTED = list(oauth2_client_auth.SIGNING_ALG_VALUES_SUPPORTED)

# The token (and device authorization) and revocation endpoints also accept
# public clients, which send client_id alone ("none"; RFC 6749 section 2.1,
# RFC 7009 section 2.1). Public clients exist for the device grant only.
TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = [*CONFIDENTIAL_AUTH_METHODS, "none"]

# Request objects (OpenID Connect Core 1.0, section 6) are accepted by value
# and by reference, signed only (no "none"), and a request_uri must be one the
# client registered (services.oauth2_request_objects).
REQUEST_PARAMETER_SUPPORTED = True
REQUEST_URI_PARAMETER_SUPPORTED = True
REQUIRE_REQUEST_URI_REGISTRATION = True
REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED = list(
    oauth2_request_objects.SIGNING_ALG_VALUES_SUPPORTED
)

# The `claims` request parameter (OpenID Connect Core 1.0, section 5.5) is not
# honoured: claims are released by scope only. Advertised explicitly because
# RPs otherwise have to guess.
CLAIMS_PARAMETER_SUPPORTED = False

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
    "sid",
    # profile-scope claims.
    "name",
    "given_name",
    "family_name",
    "locale",
    "zoneinfo",
    "updated_at",
    # email-scope claims.
    "email",
    "email_verified",
    # groups-scope claim (WeftID extension: effective, DAG-aware memberships).
    "groups",
]


def build_discovery_metadata(
    issuer: str, *, registration_enabled: bool = False
) -> OIDCProviderMetadata:
    """Assemble the OpenID Provider metadata for a tenant.

    Args:
        issuer: The tenant base URL (``https://<tenant-host>``) derived from the
            request host. Becomes the `issuer` and the prefix of every endpoint.
        registration_enabled: Whether the tenant's dynamic client registration
            policy is on; adds `registration_endpoint`.

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
        end_session_endpoint=f"{base}/oauth2/logout",
        introspection_endpoint=f"{base}/oauth2/introspect",
        introspection_endpoint_auth_methods_supported=list(CONFIDENTIAL_AUTH_METHODS),
        introspection_endpoint_auth_signing_alg_values_supported=list(
            AUTH_SIGNING_ALG_VALUES_SUPPORTED
        ),
        revocation_endpoint=f"{base}/oauth2/revoke",
        device_authorization_endpoint=f"{base}/oauth2/device_authorization",
        revocation_endpoint_auth_methods_supported=list(TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED),
        revocation_endpoint_auth_signing_alg_values_supported=list(
            AUTH_SIGNING_ALG_VALUES_SUPPORTED
        ),
        registration_endpoint=f"{base}/oauth2/register" if registration_enabled else None,
        scopes_supported=list(claims_service.SUPPORTED_SCOPES),
        response_types_supported=list(RESPONSE_TYPES_SUPPORTED),
        response_modes_supported=list(RESPONSE_MODES_SUPPORTED),
        grant_types_supported=list(GRANT_TYPES_SUPPORTED),
        subject_types_supported=list(SUBJECT_TYPES_SUPPORTED),
        id_token_signing_alg_values_supported=list(ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED),
        token_endpoint_auth_methods_supported=list(TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED),
        token_endpoint_auth_signing_alg_values_supported=list(AUTH_SIGNING_ALG_VALUES_SUPPORTED),
        claims_supported=list(CLAIMS_SUPPORTED),
        request_parameter_supported=REQUEST_PARAMETER_SUPPORTED,
        request_uri_parameter_supported=REQUEST_URI_PARAMETER_SUPPORTED,
        require_request_uri_registration=REQUIRE_REQUEST_URI_REGISTRATION,
        request_object_signing_alg_values_supported=list(
            REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED
        ),
        userinfo_signing_alg_values_supported=list(
            userinfo_service.USERINFO_SIGNING_ALG_VALUES_SUPPORTED
        ),
        claims_parameter_supported=CLAIMS_PARAMETER_SUPPORTED,
        frontchannel_logout_supported=True,
        frontchannel_logout_session_supported=True,
        backchannel_logout_supported=True,
        backchannel_logout_session_supported=True,
    )
