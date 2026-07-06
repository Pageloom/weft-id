"""Pydantic schemas for the OIDC provider surface.

Iteration 1 covers the signing-key model and the JWKS document. Later
iterations add discovery, ID-token, userinfo, and client-management schemas.
"""

from datetime import datetime

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
