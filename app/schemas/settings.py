"""Pydantic schemas for settings API endpoints."""

from datetime import datetime

from pydantic import BaseModel, Field

# =============================================================================
# Privileged Domains
# =============================================================================


class PrivilegedDomain(BaseModel):
    """Response schema for a privileged domain."""

    id: str = Field(..., description="Domain UUID")
    domain: str = Field(..., description="The privileged domain (e.g., 'company.com')")
    created_at: datetime = Field(..., description="When the domain was added")
    created_by_name: str | None = Field(None, description="Name of user who added the domain")


class PrivilegedDomainCreate(BaseModel):
    """Request schema for adding a privileged domain."""

    domain: str = Field(
        ...,
        min_length=3,
        max_length=253,
        description="Domain to add (e.g., 'company.com' or '@company.com')",
    )


# =============================================================================
# Tenant Security Settings
# =============================================================================


class TenantSecuritySettings(BaseModel):
    """Response schema for tenant security settings."""

    session_timeout_seconds: int | None = Field(
        None, description="Session timeout in seconds (null = indefinite)"
    )
    persistent_sessions: bool = Field(
        True, description="Whether sessions persist after browser close"
    )
    allow_users_edit_profile: bool = Field(
        True, description="Whether users can edit their own profile"
    )
    allow_users_add_emails: bool = Field(
        True, description="Whether users can add alternative email addresses"
    )


class TenantSecuritySettingsUpdate(BaseModel):
    """Request schema for updating tenant security settings."""

    session_timeout_seconds: int | None = Field(
        None, ge=1, description="Session timeout in seconds (null = indefinite)"
    )
    persistent_sessions: bool | None = Field(
        None, description="Whether sessions persist after browser close"
    )
    allow_users_edit_profile: bool | None = Field(
        None, description="Whether users can edit their own profile"
    )
    allow_users_add_emails: bool | None = Field(
        None, description="Whether users can add alternative email addresses"
    )
