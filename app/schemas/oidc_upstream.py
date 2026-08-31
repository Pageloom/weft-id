"""Pydantic schemas for OIDC upstream (relying-party) connection management.

Mirrors the SAML IdP schema shape in ``schemas.saml`` for the consuming
direction of OIDC. The client secret is write-only: it is accepted on create
and update but never returned; read paths expose a ``client_secret_set``
boolean instead.
"""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

PROVIDER_TYPES = ("generic", "google", "entra")

DEFAULT_CLAIM_MAPPING = {
    "email": "email",
    "first_name": "given_name",
    "last_name": "family_name",
}


class OIDCConnectionCreate(BaseModel):
    """Request schema for creating an OIDC connection."""

    name: str = Field(..., min_length=1, max_length=120)
    provider_type: str = Field(..., max_length=50, pattern="^(generic|google|entra)$")
    issuer: str = Field(..., min_length=1, max_length=2048)
    discovery_url: str | None = Field(None, max_length=2048)
    authorization_endpoint: str | None = Field(None, max_length=2048)
    token_endpoint: str | None = Field(None, max_length=2048)
    userinfo_endpoint: str | None = Field(None, max_length=2048)
    jwks_uri: str | None = Field(None, max_length=2048)
    client_id: str | None = Field(None, max_length=255)
    # The column stores the *encrypted* secret (Fernet adds ~44 bytes + base64
    # expansion), so the plaintext bound must be lower than the column's 4096
    # CHECK. 3000 chars encrypts to ~4088, safely under the limit.
    client_secret: str | None = Field(None, max_length=3000)
    scopes: str | None = Field(None, max_length=500)
    claim_mapping: dict[
        Annotated[str, Field(max_length=255)], Annotated[str, Field(max_length=255)]
    ] = Field(default_factory=lambda: dict(DEFAULT_CLAIM_MAPPING))
    correlation_claim: str = Field("sub", max_length=50)
    group_claim_source: str | None = Field(None, max_length=255)
    hosted_domain: str | None = Field(None, max_length=253)
    entra_tenant_id: str | None = Field(None, max_length=100)
    is_enabled: bool = False
    is_default: bool = False
    require_platform_mfa: bool = False
    jit_provisioning: bool = False
    allow_email_linking: bool = False


class OIDCConnectionUpdate(BaseModel):
    """Request schema for updating an OIDC connection (all fields optional)."""

    name: str | None = Field(None, min_length=1, max_length=120)
    issuer: str | None = Field(None, min_length=1, max_length=2048)
    discovery_url: str | None = Field(None, max_length=2048)
    authorization_endpoint: str | None = Field(None, max_length=2048)
    token_endpoint: str | None = Field(None, max_length=2048)
    userinfo_endpoint: str | None = Field(None, max_length=2048)
    jwks_uri: str | None = Field(None, max_length=2048)
    client_id: str | None = Field(None, max_length=255)
    # See OIDCConnectionCreate: the encrypted form is what the column stores.
    client_secret: str | None = Field(None, max_length=3000)
    scopes: str | None = Field(None, max_length=500)
    claim_mapping: (
        dict[Annotated[str, Field(max_length=255)], Annotated[str, Field(max_length=255)]] | None
    ) = None
    correlation_claim: str | None = Field(None, max_length=50)
    group_claim_source: str | None = Field(None, max_length=255)
    hosted_domain: str | None = Field(None, max_length=253)
    entra_tenant_id: str | None = Field(None, max_length=100)
    require_platform_mfa: bool | None = None
    jit_provisioning: bool | None = None
    allow_email_linking: bool | None = None


class OIDCConnectionConfig(BaseModel):
    """Response schema for an OIDC connection configuration."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    provider_type: str
    issuer: str
    discovery_url: str | None
    authorization_endpoint: str | None
    token_endpoint: str | None
    userinfo_endpoint: str | None
    jwks_uri: str | None
    discovery_fetched_at: datetime | None
    discovery_error: str | None
    client_id: str | None
    client_secret_set: bool
    scopes: str | None
    claim_mapping: dict[str, str]
    correlation_claim: str
    group_claim_source: str | None
    hosted_domain: str | None
    entra_tenant_id: str | None
    is_enabled: bool
    is_default: bool
    require_platform_mfa: bool
    jit_provisioning: bool
    allow_email_linking: bool
    callback_url: str
    created_at: datetime
    updated_at: datetime


class OIDCConnectionListItem(BaseModel):
    """Simplified OIDC connection for list views."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    provider_type: str
    is_enabled: bool
    is_default: bool
    discovery_url: str | None
    discovery_fetched_at: datetime | None
    discovery_error: str | None
    created_at: datetime


class OIDCConnectionListResponse(BaseModel):
    """Response schema for the OIDC connection list."""

    items: list[OIDCConnectionListItem]
    total: int
