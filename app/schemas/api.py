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
    timezone: str | None = Field(None, description="IANA timezone (e.g., 'America/New_York')")
    locale: str | None = Field(None, description="Two-letter locale code")
    mfa_enabled: bool
    mfa_method: str | None = None
    created_at: datetime
    last_login: datetime | None = None

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


# ============================================================================
# User Management Schemas (Admin API)
# ============================================================================


class UserSummary(BaseModel):
    """User summary for list views."""

    id: str = Field(..., description="User UUID")
    email: str | None = Field(None, description="Primary email address")
    first_name: str = Field(..., description="User's first name")
    last_name: str = Field(..., description="User's last name")
    role: str = Field(..., description="User role (member, admin, super_admin)")
    created_at: datetime = Field(..., description="Account creation timestamp")
    last_login: datetime | None = Field(None, description="Last login timestamp")


class UserListResponse(BaseModel):
    """Paginated list of users."""

    items: list[UserSummary] = Field(..., description="List of users")
    total: int = Field(..., description="Total number of matching users")
    page: int = Field(..., description="Current page number (1-indexed)")
    limit: int = Field(..., description="Page size limit")


class UserDetail(BaseModel):
    """Detailed user information including emails."""

    id: str = Field(..., description="User UUID")
    email: str | None = Field(None, description="Primary email address")
    first_name: str = Field(..., description="User's first name")
    last_name: str = Field(..., description="User's last name")
    role: str = Field(..., description="User role (member, admin, super_admin)")
    timezone: str | None = Field(None, description="IANA timezone")
    locale: str | None = Field(None, description="Two-letter locale code")
    mfa_enabled: bool = Field(..., description="Whether MFA is enabled")
    mfa_method: str | None = Field(None, description="MFA method (totp, email)")
    created_at: datetime = Field(..., description="Account creation timestamp")
    last_login: datetime | None = Field(None, description="Last login timestamp")
    emails: list[EmailInfo] = Field(default_factory=list, description="User's email addresses")
    is_service_user: bool = Field(False, description="Whether this is a B2B service account")


class UserCreate(BaseModel):
    """Request to create a new user (admin operation)."""

    first_name: str = Field(..., min_length=1, max_length=255, description="User's first name")
    last_name: str = Field(..., min_length=1, max_length=255, description="User's last name")
    email: EmailStr = Field(..., description="Primary email address")
    role: str = Field(
        "member",
        pattern="^(member|admin|super_admin)$",
        description="User role (defaults to member)",
    )


class UserUpdate(BaseModel):
    """Request to update a user (admin operation)."""

    first_name: str | None = Field(
        None, min_length=1, max_length=255, description="User's first name"
    )
    last_name: str | None = Field(
        None, min_length=1, max_length=255, description="User's last name"
    )
    role: str | None = Field(
        None,
        pattern="^(member|admin|super_admin)$",
        description="User role (requires super_admin to set super_admin)",
    )
