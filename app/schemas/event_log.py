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
    event_type: str
    metadata: dict[str, Any] | None = None
    created_at: datetime


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
