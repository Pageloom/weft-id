"""Pydantic schemas for reactivation requests."""

from datetime import datetime

from pydantic import BaseModel, Field


class ReactivationRequestCreate(BaseModel):
    """Schema for creating a reactivation request."""

    user_id: str = Field(..., description="User ID requesting reactivation")


class ReactivationRequest(BaseModel):
    """Schema for a reactivation request."""

    id: str = Field(..., description="Request UUID")
    user_id: str = Field(..., description="User ID who made the request")
    first_name: str = Field(..., description="User's first name")
    last_name: str = Field(..., description="User's last name")
    email: str | None = Field(None, description="User's primary email")
    requested_at: datetime = Field(..., description="When the request was submitted")
    decision: str | None = Field(None, description="Decision: approved, denied, or null if pending")

    model_config = {"from_attributes": True}
