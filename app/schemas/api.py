"""Pydantic schemas for common API models (user profile, errors, etc)."""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

# ============================================================================
# Error Response Schemas
# ============================================================================


class ErrorDetail(BaseModel):
    """Standard API error response."""

    detail: str = Field(..., description="Error message")
    error_code: str | None = Field(None, description="Machine-readable error code")


# ============================================================================
# User Profile Schemas
# ============================================================================


class UserProfile(BaseModel):
    """User profile response schema."""

    id: str
    email: str
    first_name: str
    last_name: str
    role: str
    timezone: str
    locale: str
    mfa_enabled: bool
    mfa_method: str | None
    created_at: datetime
    last_login: datetime | None

    class Config:
        from_attributes = True


class UserProfileUpdate(BaseModel):
    """User profile update request schema."""

    first_name: str | None = Field(None, min_length=1, max_length=255)
    last_name: str | None = Field(None, min_length=1, max_length=255)
    timezone: str | None = Field(None, description="IANA timezone (e.g., 'America/New_York')")
    locale: str | None = Field(None, pattern="^[a-z]{2}$", description="Two-letter locale code")


# ============================================================================
# Email Management Schemas
# ============================================================================


class EmailInfo(BaseModel):
    """Email address information."""

    id: str
    email: EmailStr
    is_primary: bool
    verified_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


class EmailList(BaseModel):
    """List of user email addresses."""

    items: list[EmailInfo]


class EmailCreate(BaseModel):
    """Request to add a new email address."""

    email: EmailStr


# ============================================================================
# Pagination Schemas
# ============================================================================


class PaginatedResponse(BaseModel):
    """Generic paginated response."""

    items: list[dict]
    total: int
    page: int
    limit: int
