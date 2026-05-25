"""Pydantic schemas for inbound SCIM admin endpoints.

Backs the per-IdP "SCIM Provisioning" tab and
`/api/v1/saml-identity-providers/{idp_id}/inbound-scim/credentials`
endpoints. The schemas here cover only token lifecycle metadata; SCIM
2.0 resource shapes (Users, Groups, Schemas) ship in iteration 2.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class ScimInboundToken(BaseModel):
    """One inbound SCIM token row (no plaintext, no hash)."""

    id: str
    idp_id: str
    name: str | None
    created_by_user_id: str
    created_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None


class ScimInboundTokenList(BaseModel):
    """List response for inbound SCIM token listings."""

    items: list[ScimInboundToken]
    total: int


class ScimInboundTokenCreate(BaseModel):
    """Create-token request body.

    Only an optional human-readable label is accepted. The token plaintext
    is minted server-side and returned exactly once.
    """

    name: str | None = Field(
        None,
        max_length=255,
        description=(
            "Optional admin-facing label for the token, e.g. 'Okta production'. "
            "Helps operators identify which receiver a token is paired with when "
            "rotating."
        ),
    )


class ScimInboundTokenCreated(BaseModel):
    """Response for a token-create call. Carries the plaintext ONCE."""

    id: str
    idp_id: str
    name: str | None
    created_at: datetime
    plaintext: str = Field(
        ...,
        description=(
            "The bearer token plaintext. Shown exactly once at creation time -- "
            "there is no way to recover it later (storage is hash-only). Copy "
            "this value into the upstream IdP's SCIM connector configuration "
            "immediately."
        ),
    )
