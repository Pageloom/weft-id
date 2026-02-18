"""Pydantic schemas for settings API endpoints."""

from datetime import datetime
from typing import Literal

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
    bound_idp_id: str | None = Field(None, description="ID of bound IdP, if any")
    bound_idp_name: str | None = Field(None, description="Name of bound IdP, if any")


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
    inactivity_threshold_days: int | None = Field(
        None,
        description="Days of inactivity before auto-inactivation (null = disabled)",
    )
    max_certificate_lifetime_years: int = Field(
        10,
        description="Lifetime in years for newly generated signing certificates",
    )
    certificate_rotation_window_days: int = Field(
        90,
        description="Days before expiry to trigger auto-rotation and grace period duration",
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
    inactivity_threshold_days: int | None = Field(
        None,
        ge=1,
        description="Days of inactivity before auto-inactivation (null = disabled)",
    )
    max_certificate_lifetime_years: Literal[1, 2, 3, 5, 10] | None = Field(
        None,
        description="Lifetime in years for newly generated signing certificates",
    )
    certificate_rotation_window_days: Literal[14, 30, 60, 90] | None = Field(
        None,
        description="Days before expiry to trigger auto-rotation and grace period duration",
    )
