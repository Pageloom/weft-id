"""Pydantic schemas for the OIDC provider surface.

Iteration 1 covers the signing-key model and the JWKS document. Later
iterations add discovery, ID-token, userinfo, and client-management schemas.
"""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field


class JWK(BaseModel):
    """A single JSON Web Key (public RSA key), per RFC 7517 / RFC 7518.

    Only public components are ever populated. Private material (d, p, q, ...)
    is never included.
    """

    kty: str = Field(..., description="Key type. Always 'RSA'.")
    use: str = Field(..., description="Public key use. Always 'sig' (signature verification).")
    alg: str = Field(..., description="Signing algorithm. Always 'RS256'.")
    kid: str = Field(..., description="Stable key id; matches the JWT header 'kid'.")
    n: str = Field(..., description="RSA modulus, base64url-encoded.")
    e: str = Field(..., description="RSA public exponent, base64url-encoded.")


class JWKS(BaseModel):
    """A JSON Web Key Set: the tenant's active plus within-grace retired keys."""

    keys: list[JWK] = Field(default_factory=list, description="Public verification keys.")


class OIDCProviderMetadata(BaseModel):
    """OpenID Provider metadata (the discovery document), per OpenID Connect
    Discovery 1.0, section 3.

    Every endpoint URL is derived from the request host so the advertised
    `issuer` and endpoints match the exact tenant host the relying party used.
    Only capabilities actually implemented today are advertised; logout,
    introspection, revocation, device grant, and dynamic registration are
    deliberately omitted (they belong to the separate OIDC Hardening item).
    """

    issuer: str = Field(..., description="The tenant issuer (its https host).")
    authorization_endpoint: str = Field(..., description="OAuth2 authorization endpoint URL.")
    token_endpoint: str = Field(..., description="OAuth2 token endpoint URL.")
    userinfo_endpoint: str = Field(..., description="OIDC userinfo endpoint URL.")
    jwks_uri: str = Field(..., description="JWKS endpoint URL (public verification keys).")
    scopes_supported: list[str] = Field(..., description="Scopes this provider recognises.")
    response_types_supported: list[str] = Field(
        ..., description="OAuth2 response types supported at the authorization endpoint."
    )
    grant_types_supported: list[str] = Field(
        ..., description="OAuth2 grant types supported at the token endpoint."
    )
    subject_types_supported: list[str] = Field(
        ..., description="Subject identifier types. Always ['public']."
    )
    id_token_signing_alg_values_supported: list[str] = Field(
        ..., description="ID-token signing algorithms. Always ['RS256']."
    )
    claims_supported: list[str] = Field(
        ..., description="Claims that may appear in ID tokens or userinfo responses."
    )


# ============================================================================
# OIDC client management schemas
# ============================================================================


class OIDCClientSettingsUpdate(BaseModel):
    """Request to change a client's OIDC settings.

    Both fields are optional; supply at least one. Sending only one field
    leaves the other unchanged.
    """

    oidc_enabled: bool | None = Field(
        None,
        description=(
            "Turn the client into an OpenID Provider relying party. When true, "
            "the token endpoint issues signed ID tokens (with the openid scope) "
            "and group-based access control is enforced at authorize time."
        ),
    )
    available_to_all: bool | None = Field(
        None,
        description=(
            "When true, every active tenant user may sign in to this OIDC client "
            "and group assignments become organisational only. When false, only "
            "members of assigned groups (and their descendants) may sign in."
        ),
    )


class OIDCClientDiscoveryInfo(BaseModel):
    """Read-only OIDC endpoint URLs for a tenant, for copying into a downstream app.

    All URLs are derived from the request host so they match the exact tenant
    surface the relying party will use.
    """

    issuer: str = Field(..., description="The tenant issuer (its https host).")
    discovery_url: str = Field(
        ...,
        description="OpenID Connect discovery document URL (/.well-known/openid-configuration).",
    )
    jwks_uri: str = Field(..., description="JWKS endpoint URL (public verification keys).")
    authorization_endpoint: str = Field(..., description="OAuth2 authorization endpoint URL.")
    token_endpoint: str = Field(..., description="OAuth2 token endpoint URL.")
    userinfo_endpoint: str = Field(..., description="OIDC userinfo endpoint URL.")


class OIDCClientGroupAssignment(BaseModel):
    """A single OIDC-client-to-group assignment."""

    id: str
    oauth2_client_id: str
    group_id: str
    group_name: str
    group_description: str | None = None
    group_type: str
    assigned_by: str
    assigned_at: datetime


class OIDCClientGroupAssignmentList(BaseModel):
    """List of group assignments for an OIDC client."""

    items: list[OIDCClientGroupAssignment]
    total: int


class OIDCClientGroupAssignAdd(BaseModel):
    """Request to assign a group to an OIDC client."""

    group_id: str = Field(..., min_length=1, max_length=36)


class OIDCClientGroupBulkAssign(BaseModel):
    """Request to bulk-assign groups to an OIDC client."""

    group_ids: list[Annotated[str, Field(min_length=1, max_length=36)]] = Field(
        ..., min_length=1, max_length=5000
    )


class OIDCSigningKeyRotationResult(BaseModel):
    """Result of an OIDC signing-key rotation.

    Carries only non-sensitive metadata; no key material is returned.
    """

    kid: str = Field(..., description="New active key id.")
    previous_kid: str = Field(..., description="Retired key id, still served in JWKS.")
    rotated_at: datetime = Field(..., description="When the rotation occurred.")
    grace_period_ends_at: datetime = Field(
        ..., description="When the retired key stops being published in JWKS."
    )


class OIDCSigningKeyStatus(BaseModel):
    """Public metadata about the tenant's OIDC signing key.

    Carries only non-sensitive metadata; no key material is returned. The kid
    values are already public via the tenant's JWKS endpoint.
    """

    kid: str = Field(..., description="Active key id.")
    algorithm: str = Field(..., description="Signing algorithm. Always 'RS256'.")
    created_at: datetime = Field(..., description="When the active key was created.")
    previous_kid: str | None = Field(
        None, description="Retired key id still served in JWKS, if a rotation is in grace."
    )
    previous_created_at: datetime | None = Field(
        None, description="When the retired key was originally created."
    )
    rotation_grace_period_ends_at: datetime | None = Field(
        None, description="When the retired key stops being published in JWKS."
    )
    rotation_in_progress: bool = Field(
        ..., description="True while a retired key is still within its grace period."
    )


class OIDCSigningKeyRotateRequest(BaseModel):
    """Request body for a manual OIDC signing-key rotation."""

    grace_period_hours: int = Field(
        24,
        ge=1,
        le=720,
        description=(
            "How long the retired key stays published in JWKS (1 hour to 30 days). "
            "Defaults to 24 hours."
        ),
    )


class OIDCSigningKeyCleanupResult(BaseModel):
    """Result of a manual retired-key cleanup request."""

    cleaned_up: bool = Field(
        ...,
        description=(
            "True if an expired retired key was removed; False if there was "
            "no retired key or its grace period has not ended yet."
        ),
    )
