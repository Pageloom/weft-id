"""Pydantic schemas for OAuth2 client management and token responses."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# ============================================================================
# OAuth2 Client Management Schemas
# ============================================================================


class NormalClientCreate(BaseModel):
    """Request schema for creating a normal OAuth2 client (authorization code flow)."""

    name: str = Field(..., min_length=1, max_length=255, description="Client name")
    description: str | None = Field(None, max_length=500, description="Optional client description")
    redirect_uris: list[str] = Field(
        ...,
        min_length=1,
        description="List of exact redirect URIs (no wildcards)",
    )


class B2BClientCreate(BaseModel):
    """Request schema for creating a B2B OAuth2 client (client credentials flow)."""

    name: str = Field(..., min_length=1, max_length=255, description="Client name")
    description: str | None = Field(None, max_length=500, description="Optional client description")
    role: str = Field(
        ...,
        pattern="^(member|admin|super_admin)$",
        description="Role for the service user",
    )


class ClientUpdate(BaseModel):
    """Request schema for updating an OAuth2 client."""

    name: str | None = Field(None, min_length=1, max_length=255, description="Client name")
    description: str | None = Field(None, max_length=500, description="Optional client description")
    redirect_uris: list[str] | None = Field(
        None,
        min_length=1,
        description="List of exact redirect URIs (normal clients only)",
    )


class ClientRoleUpdate(BaseModel):
    """Request schema for updating a B2B client's service role."""

    role: str = Field(
        ...,
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
    service_user_id: str | None
    is_active: bool = True
    created_at: datetime


class ClientWithSecret(ClientResponse):
    """Response schema for OAuth2 client with secret (only returned on creation)."""

    client_secret: str = Field(..., description="Client secret - shown only once, store securely")


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


class TokenErrorResponse(BaseModel):
    """Standard OAuth2 error response."""

    error: str = Field(
        ...,
        description="Error code: invalid_request, invalid_client, invalid_grant, "
        "unauthorized_client, unsupported_grant_type",
    )
    error_description: str | None = Field(None, description="Human-readable error description")


# ============================================================================
# Authorization Endpoint Schemas
# ============================================================================


class AuthorizeParams(BaseModel):
    """Query parameters for OAuth2 authorization endpoint."""

    client_id: str
    redirect_uri: str
    state: str | None = None
    code_challenge: str | None = Field(None, description="PKCE code challenge")
    code_challenge_method: str | None = Field(
        None, pattern="^(S256|plain)$", description="PKCE challenge method"
    )


class AuthorizeForm(BaseModel):
    """Form data for OAuth2 authorization approval."""

    client_id: str
    redirect_uri: str
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    action: str = Field(..., pattern="^(allow|deny)$")
