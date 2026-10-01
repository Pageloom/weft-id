"""Pydantic schemas for OAuth2 client management and token responses."""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ============================================================================
# OAuth2 Client Management Schemas
# ============================================================================


class NormalClientCreate(BaseModel):
    """Request schema for creating a normal OAuth2 client (authorization code flow)."""

    name: str = Field(..., min_length=1, max_length=255, description="Client name")
    description: str | None = Field(None, max_length=500, description="Optional client description")
    redirect_uris: list[Annotated[str, Field(max_length=2048)]] = Field(
        default_factory=list,
        description=(
            "List of exact redirect URIs (no wildcards). At least one is required, "
            "except for a public client, which has none."
        ),
    )
    post_logout_redirect_uris: list[Annotated[str, Field(max_length=2048)]] = Field(
        default_factory=list,
        max_length=50,
        description=(
            "Exact URIs the end_session endpoint may redirect to after logout "
            "(absolute http/https, no fragment). Optional."
        ),
    )
    frontchannel_logout_uri: str | None = Field(
        None,
        max_length=2048,
        description=(
            "OpenID Connect Front-Channel Logout: URL WeftID loads in an iframe when "
            "the user's session ends (absolute http/https, no fragment, same scheme, "
            "host and port as a redirect URI). Optional."
        ),
    )
    frontchannel_logout_session_required: bool = Field(
        True,
        description=(
            "Whether the front-channel logout URL receives the iss and sid parameters "
            "(default true)."
        ),
    )
    backchannel_logout_uri: str | None = Field(
        None,
        max_length=2048,
        description=(
            "OpenID Connect Back-Channel Logout: URL WeftID POSTs a signed logout "
            "token to when the user's session ends (absolute http/https, no "
            "fragment). Optional."
        ),
    )
    backchannel_logout_session_required: bool = Field(
        True,
        description="Whether the logout token carries the sid claim (default true).",
    )
    initiate_login_uri: str | None = Field(
        None,
        max_length=2048,
        description=(
            "OpenID Connect third-party-initiated login: the app's URL that starts a "
            "sign-in at WeftID (absolute https, no fragment). An OIDC-enabled client "
            "with one appears in My Apps. Optional."
        ),
    )
    device_grant_enabled: bool = Field(
        False,
        description=(
            "Whether the client may use the OAuth 2.0 device authorization grant "
            "(RFC 8628) for devices without a convenient browser (default false)."
        ),
    )
    is_public: bool = Field(
        False,
        description=(
            "Create a public client (default false): no client secret; it sends its "
            "client_id alone and may use only the device authorization and refresh "
            "token grants. Switches the device grant on, takes no redirect URIs, "
            "post-logout redirect URIs, front-channel logout URI, or login initiation "
            "URI, and cannot be changed after creation."
        ),
    )


class B2BClientCreate(BaseModel):
    """Request schema for creating a B2B OAuth2 client (client credentials flow)."""

    name: str = Field(..., min_length=1, max_length=255, description="Client name")
    description: str | None = Field(None, max_length=500, description="Optional client description")
    role: str = Field(
        ...,
        max_length=50,
        pattern="^(member|admin|super_admin)$",
        description="Role for the service user",
    )


class ClientUpdate(BaseModel):
    """Request schema for updating an OAuth2 client."""

    name: str | None = Field(None, min_length=1, max_length=255, description="Client name")
    description: str | None = Field(None, max_length=500, description="Optional client description")
    redirect_uris: list[Annotated[str, Field(max_length=2048)]] | None = Field(
        None,
        min_length=1,
        description="List of exact redirect URIs (normal clients only)",
    )
    post_logout_redirect_uris: list[Annotated[str, Field(max_length=2048)]] | None = Field(
        None,
        max_length=50,
        description=(
            "Exact URIs the end_session endpoint may redirect to after logout "
            "(normal clients only; absolute http/https, no fragment). An empty "
            "list clears them."
        ),
    )
    frontchannel_logout_uri: str | None = Field(
        None,
        max_length=2048,
        description=(
            "Front-channel logout URL (normal clients only; absolute http/https, no "
            "fragment, same scheme, host and port as a redirect URI). An empty string "
            "clears it."
        ),
    )
    frontchannel_logout_session_required: bool | None = Field(
        None,
        description="Whether the front-channel logout URL receives iss and sid (normal clients).",
    )
    backchannel_logout_uri: str | None = Field(
        None,
        max_length=2048,
        description=(
            "Back-channel logout URL (normal clients only; absolute http/https, no "
            "fragment). An empty string clears it."
        ),
    )
    backchannel_logout_session_required: bool | None = Field(
        None,
        description="Whether the logout token carries the sid claim (normal clients).",
    )
    initiate_login_uri: str | None = Field(
        None,
        max_length=2048,
        description=(
            "Login initiation URL (normal clients only; absolute https, no fragment). "
            "An empty string clears it."
        ),
    )
    device_grant_enabled: bool | None = Field(
        None,
        description="Whether the device authorization grant is allowed (normal clients only).",
    )
    require_pushed_authorization_requests: bool | None = Field(
        None,
        description=(
            "Whether the client may only start an authorization through the PAR "
            "endpoint (normal confidential clients only)."
        ),
    )
    can_introspect_tenant_tokens: bool | None = Field(
        None,
        description=(
            "Whether the client may introspect every token in the tenant (a resource "
            "server), not just its own. Changing it on a B2B client requires super_admin."
        ),
    )


class ClientAuthenticationUpdate(BaseModel):
    """Request schema for setting how a confidential client authenticates."""

    method: Literal["client_secret", "private_key_jwt"] = Field(
        ...,
        description=(
            "client_secret (client_secret_basic or client_secret_post) or "
            "private_key_jwt (a client assertion signed with one of the client's keys)."
        ),
    )
    jwks: dict[str, Any] | None = Field(
        None,
        description=(
            "The client's public keys as a JSON Web Key Set (RSA or EC, at most 20 keys, "
            "no private members). Give this or jwks_uri, not both."
        ),
    )
    jwks_uri: str | None = Field(
        None,
        max_length=2048,
        description="URL of the client's JSON Web Key Set (absolute https, no fragment).",
    )


class ClientSubjectTypeUpdate(BaseModel):
    """Request schema for setting an app's subject identifier type."""

    subject_type: Literal["public", "pairwise"] = Field(
        ...,
        description=(
            "public (sub is the WeftID user id) or pairwise (sub is derived from the "
            "user id and the app's sector, OpenID Connect Core 8.1)."
        ),
    )
    sector_identifier_uri: str | None = Field(
        None,
        max_length=2048,
        description=(
            "pairwise only: https URL of a JSON array listing every redirect URI of the "
            "app. Its host is the sector. Without it, the redirect URIs must share one "
            "host, which is the sector."
        ),
    )


class ClientRoleUpdate(BaseModel):
    """Request schema for updating a B2B client's service role."""

    role: str = Field(
        ...,
        max_length=50,
        pattern="^(member|admin|super_admin)$",
        description="New role for the service user",
    )


class ClientResponse(BaseModel):
    """Response schema for OAuth2 client (without secret)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    client_id: str
    client_type: str
    name: str
    description: str | None = None
    redirect_uris: list[str] | None
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    frontchannel_logout_uri: str | None = None
    frontchannel_logout_session_required: bool = True
    backchannel_logout_uri: str | None = None
    backchannel_logout_session_required: bool = True
    service_user_id: str | None
    is_active: bool = True
    oidc_enabled: bool = False
    available_to_all: bool = False
    can_introspect_tenant_tokens: bool = False
    dynamically_registered: bool = Field(
        False,
        description="Whether the client registered itself through dynamic client registration.",
    )
    logo_uri: str | None = Field(None, description="Logo shown on the consent page.")
    client_uri: str | None = Field(None, description="The client's home page.")
    policy_uri: str | None = Field(None, description="The client's privacy policy.")
    tos_uri: str | None = Field(None, description="The client's terms of service.")
    initiate_login_uri: str | None = Field(
        None,
        description="The client's URL that starts a sign-in at WeftID (My Apps launch).",
    )
    device_grant_enabled: bool = Field(
        False, description="Whether the client may use the device authorization grant."
    )
    is_public: bool = Field(
        False,
        description=(
            "Whether the client is public: no secret, device authorization and "
            "refresh token grants only."
        ),
    )
    client_auth_method: str = Field(
        "client_secret",
        description=(
            "How the client authenticates: client_secret or private_key_jwt "
            "(a public client sends its client_id alone)."
        ),
    )
    jwks: dict[str, Any] | None = Field(None, description="The client's public keys, inline.")
    jwks_uri: str | None = Field(None, description="URL of the client's public keys.")
    token_endpoint_auth_signing_alg: str | None = Field(
        None,
        description="The one algorithm the client's assertions must use, when it registered one.",
    )
    require_pushed_authorization_requests: bool = Field(
        False,
        description=(
            "Whether the client may only start an authorization through the pushed "
            "authorization request (PAR) endpoint."
        ),
    )
    subject_type: str = Field(
        "public",
        description="The sub the client receives: public (the user id) or pairwise.",
    )
    sector_identifier_uri: str | None = Field(
        None, description="The pairwise sector identifier URI, when one is set."
    )
    created_at: datetime


class ClientWithSecret(ClientResponse):
    """Response schema for OAuth2 client with secret (only returned on creation)."""

    client_secret: str | None = Field(
        None,
        description="Client secret - shown only once, store securely (null for a public client)",
    )


# ============================================================================
# Dynamic Client Registration (admin side)
# ============================================================================

REGISTRATION_POLICIES = ("off", "token_required", "open")
REGISTRATION_DEFAULT_ACCESS = ("none", "all")


class RegistrationSettings(BaseModel):
    """The tenant's dynamic client registration settings."""

    policy: str = Field(
        ...,
        description=(
            "off: the registration endpoint is closed (default). token_required: a "
            "registration needs an initial access token. open: anyone who can reach "
            "the tenant can register a client."
        ),
    )
    default_access: str = Field(
        ...,
        description=(
            "none: a newly registered client is available to no one until an admin "
            "assigns groups (default). all: it is available to every user."
        ),
    )
    registration_endpoint: str | None = Field(
        None, description="The registration endpoint URL, when the policy is not off."
    )


class RegistrationSettingsUpdate(BaseModel):
    """Fields to change on the registration settings (omitted fields are kept)."""

    policy: str | None = Field(
        None, max_length=50, pattern="^(off|token_required|open)$", description="See response."
    )
    default_access: str | None = Field(
        None, max_length=50, pattern="^(none|all)$", description="See response."
    )


class InitialAccessTokenCreate(BaseModel):
    """Request schema for issuing an initial access token."""

    name: str = Field(..., min_length=1, max_length=255, description="Who or what the token is for")
    expires_in_days: int | None = Field(
        None,
        ge=1,
        le=365,
        description="Days until the token stops working (1 to 365). Omit for no expiry.",
    )


class InitialAccessTokenResponse(BaseModel):
    """An initial access token (never the token value)."""

    id: str
    name: str
    created_by: str | None = None
    created_by_name: str | None = None
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None
    registered_client_count: int = 0
    status: str = Field(..., description="active, expired, or revoked")


class InitialAccessTokenCreated(InitialAccessTokenResponse):
    """A newly issued initial access token, with its value (shown only once)."""

    token: str = Field(..., description="The token value. Shown only once, store securely")


# ============================================================================
# OAuth2 Token Endpoint Schemas
# ============================================================================


class TokenResponse(BaseModel):
    """Standard OAuth2 token response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int = Field(..., description="Access token lifetime in seconds")
    refresh_token: str | None = Field(
        None, description="Refresh token (not included for client credentials flow)"
    )
    id_token: str | None = Field(
        None,
        description=(
            "Signed RS256 OIDC ID token. Only present when the client is "
            "oidc_enabled and the request included the openid scope; omitted "
            "for plain OAuth2 clients."
        ),
    )


class DeviceAuthorizationResponse(BaseModel):
    """Device authorization response (RFC 8628 section 3.2)."""

    device_code: str = Field(..., description="Code the device polls the token endpoint with")
    user_code: str = Field(..., description="Code the user types on the verification page")
    verification_uri: str = Field(..., description="Page where the user enters the user code")
    verification_uri_complete: str = Field(
        ..., description="The verification page with the user code filled in (for a QR code)"
    )
    expires_in: int = Field(..., description="Lifetime of both codes in seconds")
    interval: int = Field(..., description="Minimum seconds between token endpoint polls")


class PushedAuthorizationResponse(BaseModel):
    """Pushed authorization response (RFC 9126 section 2.2)."""

    request_uri: str = Field(
        ...,
        description=(
            "Reference to the pushed request (urn:ietf:params:oauth:request_uri:...), "
            "sent to the authorization endpoint with the client_id"
        ),
    )
    expires_in: int = Field(..., description="Seconds until the request_uri stops working")


class TokenErrorResponse(BaseModel):
    """Standard OAuth2 error response."""

    error: str = Field(
        ...,
        description="Error code: invalid_request, invalid_client, invalid_grant, "
        "unauthorized_client, unsupported_grant_type; for the device_code grant also "
        "authorization_pending, slow_down, access_denied, expired_token",
    )
    error_description: str | None = Field(None, description="Human-readable error description")


# ============================================================================
# Authorization Endpoint Schemas
# ============================================================================


class AuthorizeParams(BaseModel):
    """Query parameters for OAuth2 authorization endpoint."""

    client_id: str = Field(..., max_length=255)
    redirect_uri: str = Field(..., max_length=2048)
    state: str | None = Field(None, max_length=2048)
    code_challenge: str | None = Field(None, max_length=128, description="PKCE code challenge")
    code_challenge_method: str | None = Field(
        None, max_length=10, pattern="^(S256|plain)$", description="PKCE challenge method"
    )
    scope: str | None = Field(
        None, max_length=500, description="Space-delimited OAuth2/OIDC scopes"
    )
    nonce: str | None = Field(
        None, max_length=512, description="OIDC nonce bound to the resulting ID token"
    )


class AuthorizeForm(BaseModel):
    """Form data for OAuth2 authorization approval."""

    client_id: str = Field(..., max_length=255)
    redirect_uri: str = Field(..., max_length=2048)
    state: str | None = Field(None, max_length=2048)
    code_challenge: str | None = Field(None, max_length=128)
    code_challenge_method: str | None = Field(None, max_length=10)
    scope: str | None = Field(None, max_length=500)
    nonce: str | None = Field(None, max_length=512)
    action: str = Field(..., max_length=10, pattern="^(allow|deny)$")
