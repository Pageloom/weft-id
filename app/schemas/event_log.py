"""Pydantic schemas for event log API."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventLogItem(BaseModel):
    """Single event log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    actor_user_id: str
    actor_name: str = Field(..., description="Display name of the actor")
    artifact_type: str
    artifact_id: str
    artifact_name: str | None = Field(
        None, description="Human-readable artifact name (for user artifacts)"
    )
    artifact_email: str | None = Field(
        None, description="Email of artifact user (if artifact is a user)"
    )
    event_type: str
    event_description: str | None = Field(
        None, description="Human-readable description of the event type"
    )
    metadata: dict[str, Any] | None = Field(
        None, description="Full metadata (request fields + custom event data)"
    )
    created_at: datetime
    # Convenience fields extracted from metadata for template display
    remote_address: str | None = Field(None, description="IP address from request metadata")
    user_agent: str | None = Field(None, description="User agent from request metadata")
    device: str | None = Field(None, description="Device from request metadata")
    session_id_hash: str | None = Field(None, description="Hashed session ID from request metadata")
    # API client fields (only present for OAuth2 token-authenticated requests)
    api_client_id: str | None = Field(None, description="OAuth2 client ID (for API requests)")
    api_client_name: str | None = Field(None, description="OAuth2 client name (for API requests)")
    api_client_type: str | None = Field(None, description="OAuth2 client type: normal or b2b")

    @property
    def is_api_request(self) -> bool:
        """True if this event was triggered by an API request (OAuth2 token)."""
        return self.api_client_id is not None


class EventLogListResponse(BaseModel):
    """Paginated list of event logs."""

    items: list[EventLogItem]
    total: int
    page: int
    limit: int


class ExportFileItem(BaseModel):
    """Single export file entry."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    storage_type: str
    file_size: int | None = None
    content_type: str
    expires_at: datetime
    created_at: datetime
    downloaded_at: datetime | None = None


class ExportListResponse(BaseModel):
    """List of export files."""

    items: list[ExportFileItem]
    total: int
