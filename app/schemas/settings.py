"""Pydantic schemas for settings API endpoints."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# =============================================================================
# Privileged Domains
# =============================================================================


class DomainGroupLink(BaseModel):
    """Response schema for a domain-group link."""

    id: str = Field(..., description="Link UUID")
    domain_id: str = Field(..., description="Privileged domain UUID")
    group_id: str = Field(..., description="Group UUID")
    group_name: str = Field(..., description="Group name")
    created_at: datetime = Field(..., description="When the link was created")
    created_by_name: str | None = Field(None, description="Name of user who created the link")


class DomainGroupLinkCreate(BaseModel):
    """Request schema for linking a group to a privileged domain."""

    group_id: str = Field(..., max_length=50, description="Group UUID to link")


class PrivilegedDomain(BaseModel):
    """Response schema for a privileged domain."""

    id: str = Field(..., description="Domain UUID")
    domain: str = Field(..., description="The privileged domain (e.g., 'company.com')")
    created_at: datetime = Field(..., description="When the domain was added")
    created_by_name: str | None = Field(None, description="Name of user who added the domain")
    bound_idp_id: str | None = Field(None, description="ID of bound IdP, if any")
    bound_idp_name: str | None = Field(None, description="Name of bound IdP, if any")
    linked_groups: list[DomainGroupLink] = Field(
        default_factory=list, description="Groups linked for auto-assignment"
    )


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
    minimum_password_length: int = Field(
        14,
        description="Minimum password length required for new passwords",
    )
    minimum_zxcvbn_score: int = Field(
        3,
        description="Minimum zxcvbn strength score (3 = strong, 4 = very strong)",
    )
    group_assertion_scope: Literal["all", "trunk", "access_relevant"] = Field(
        "access_relevant",
        description=(
            "Which groups to include in SAML assertions: "
            "all (every effective group), trunk (user's topmost memberships), "
            "or access_relevant (only groups granting SP access)"
        ),
    )


class VersionInfo(BaseModel):
    """Response schema for version information."""

    version: str = Field(..., description="Current Weft ID version")


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
    minimum_password_length: Literal[8, 10, 12, 14, 16, 18, 20] | None = Field(
        None,
        description="Minimum password length required for new passwords",
    )
    minimum_zxcvbn_score: Literal[3, 4] | None = Field(
        None,
        description="Minimum zxcvbn strength score (3 = strong, 4 = very strong)",
    )
    group_assertion_scope: Literal["all", "trunk", "access_relevant"] | None = Field(
        None,
        description=("Which groups to include in SAML assertions: all, trunk, or access_relevant"),
    )
