"""Pydantic schemas for outbound SCIM admin endpoints.

Kept separate from `schemas/service_providers.py` so the SAML SP surface
stays focused. These schemas back the `/api/v1/service-providers/{sp_id}/scim/`
endpoints and the admin UI templates.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ScimKind = Literal["generic", "slack", "github", "atlassian", "gitlab"]
ScimMembershipMode = Literal["effective", "direct"]
ScimLogRetention = Literal["3", "6", "12", "24", "forever"]
ScimSyncStatus = Literal["pending", "running", "done", "failed", "dead_letter"]
ScimResourceType = Literal["user", "group"]


# ============================================================================
# Config
# ============================================================================


class ScimConfig(BaseModel):
    """Outbound SCIM configuration for a single service provider."""

    sp_id: str
    scim_enabled: bool
    scim_target_url: str | None
    scim_kind: ScimKind
    scim_membership_mode: ScimMembershipMode
    scim_log_retention: ScimLogRetention


class ScimConfigUpdate(BaseModel):
    """Patch shape for `PUT /api/v1/service-providers/{sp_id}/scim/config`.

    Every field is optional; only provided fields are written. `scim_kind`
    accepts any string of length <= 50 and falls back to `generic` at
    runtime, but the API closes that to the dropdown values to prevent
    typos. UI flows pass only the fields that changed.
    """

    scim_enabled: bool | None = None
    scim_target_url: str | None = Field(None, max_length=2048)
    scim_kind: ScimKind | None = Field(None, max_length=50)
    scim_membership_mode: ScimMembershipMode | None = Field(None, max_length=20)
    scim_log_retention: ScimLogRetention | None = Field(None, max_length=10)


# ============================================================================
# Credentials
# ============================================================================


class ScimCredential(BaseModel):
    """One credential row (no plaintext)."""

    id: str
    sp_id: str
    created_by_user_id: str
    created_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None


class ScimCredentialList(BaseModel):
    """List response for credential listings."""

    items: list[ScimCredential]
    total: int


class ScimCredentialCreate(BaseModel):
    """Create-token request body (no input fields today).

    A new credential is minted server-side; the request carries no payload.
    """

    pass


class ScimCredentialCreated(BaseModel):
    """Response from creating or rotating a credential.

    `plaintext` is shown ONCE at creation and never persisted in cleartext
    after the response is generated. Clients must capture it; subsequent
    GETs only return the metadata.
    """

    id: str
    sp_id: str
    created_at: datetime
    plaintext: str = Field(
        ...,
        description="Bearer token plaintext. Shown once. Capture and store securely.",
    )
    rotated_from_id: str | None = Field(
        None,
        description="When set, the prior credential id whose revocation has been scheduled.",
    )
    rotated_from_revoke_at: datetime | None = Field(
        None,
        description="When the prior credential will be fully revoked.",
    )


# ============================================================================
# Sync activity
# ============================================================================


class ScimSyncLogEntry(BaseModel):
    """One row of the per-SP sync activity log."""

    id: str
    sp_id: str
    resource_type: ScimResourceType
    resource_id: str
    status: ScimSyncStatus
    attempt: int
    error: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ScimSyncLogList(BaseModel):
    """Paginated sync log response."""

    items: list[ScimSyncLogEntry]
    total: int
    page: int
    page_size: int


class ScimQueueStatus(BaseModel):
    """Snapshot of the push queue for one SP."""

    sp_id: str
    pending: int
    dead_lettered: int


class ScimRetryResult(BaseModel):
    """Result of a retry-dead-lettered action."""

    sp_id: str
    revived: int = Field(..., description="How many queue rows had their dead_letter_at cleared.")
