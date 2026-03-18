"""Pydantic schemas for common API models (user profile, errors, etc)."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

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

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    first_name: str
    last_name: str
    role: str
    timezone: str | None = Field(None, description="IANA timezone (e.g., 'America/New_York')")
    locale: str | None = Field(None, description="Two-letter locale code")
    theme: str | None = Field(None, description="Theme preference: system, light, or dark")
    mfa_enabled: bool
    mfa_method: str | None = None
    created_at: datetime
    last_login: datetime | None = None


class UserProfileUpdate(BaseModel):
    """User profile update request schema."""

    first_name: str | None = Field(None, min_length=1, max_length=255)
    last_name: str | None = Field(None, min_length=1, max_length=255)
    timezone: str | None = Field(
        None, max_length=50, description="IANA timezone (e.g., 'America/New_York')"
    )
    locale: str | None = Field(
        None,
        max_length=10,
        pattern="^[a-z]{2}(_[A-Z]{2})?$",
        description="Locale code (e.g., 'en' or 'en_US')",
    )
    theme: str | None = Field(
        None,
        max_length=6,
        pattern="^(system|light|dark)$",
        description="Theme preference: system, light, or dark",
    )


# ============================================================================
# Password Schemas
# ============================================================================


class PasswordChange(BaseModel):
    """Password change request schema."""

    current_password: str = Field(..., min_length=1, max_length=255, description="Current password")
    new_password: str = Field(..., min_length=8, max_length=255, description="New password")


class PasswordResetForce(BaseModel):
    """Empty body for force password reset (all info is in the URL)."""

    pass


# ============================================================================
# Email Management Schemas
# ============================================================================


class EmailInfo(BaseModel):
    """Email address information."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    is_primary: bool
    verified_at: datetime | None
    created_at: datetime


class EmailList(BaseModel):
    """List of user email addresses."""

    items: list[EmailInfo]


class EmailCreate(BaseModel):
    """Request to add a new email address."""

    email: EmailStr = Field(..., max_length=320)


class EmailVerifyRequest(BaseModel):
    """Request to verify an email address with nonce."""

    nonce: int = Field(..., description="Verification nonce from email link")


# ============================================================================
# MFA Management Schemas
# ============================================================================


class MFAStatus(BaseModel):
    """MFA status response."""

    enabled: bool = Field(..., description="Whether MFA is enabled")
    method: str | None = Field(None, description="MFA method (totp, email)")
    has_backup_codes: bool = Field(..., description="Whether user has backup codes")
    backup_codes_remaining: int = Field(0, description="Number of unused backup codes")


class MFAEnableResponse(BaseModel):
    """Response when enabling email MFA (may require verification for downgrade)."""

    status: MFAStatus | None = Field(None, description="MFA status if enabled directly")
    pending_verification: bool = Field(
        False, description="True if email verification required (TOTP downgrade)"
    )
    message: str | None = Field(None, description="Message explaining next steps")


class TOTPSetupResponse(BaseModel):
    """Response with TOTP setup details."""

    secret: str = Field(..., description="Base32-encoded secret for manual entry")
    uri: str = Field(..., description="otpauth:// URI for QR code generation")


class TOTPVerifyRequest(BaseModel):
    """Request to verify TOTP code."""

    code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP code")


class EmailOTPVerifyRequest(BaseModel):
    """Request to verify email OTP code (for MFA downgrade)."""

    code: str = Field(..., min_length=6, max_length=6, description="6-digit email OTP code")


class BackupCodesResponse(BaseModel):
    """Response with backup codes (only shown once after generation)."""

    codes: list[str] = Field(..., description="Plain text backup codes")
    count: int = Field(..., description="Number of codes generated")


class BackupCodeStatus(BaseModel):
    """Status of a single backup code."""

    id: str
    used: bool = Field(..., description="Whether the code has been used")


class BackupCodesStatusResponse(BaseModel):
    """Response with backup codes status (not the actual codes)."""

    total: int = Field(..., description="Total number of backup codes")
    used: int = Field(..., description="Number of used backup codes")
    remaining: int = Field(..., description="Number of remaining backup codes")


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
    last_activity_at: datetime | None = Field(None, description="Last activity timestamp")
    is_inactivated: bool = Field(False, description="Whether user is inactivated")
    is_anonymized: bool = Field(False, description="Whether user is anonymized (GDPR)")


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
    is_inactivated: bool = Field(False, description="Whether user is inactivated")
    is_anonymized: bool = Field(False, description="Whether user is anonymized (GDPR)")
    inactivated_at: datetime | None = Field(None, description="When user was inactivated")
    anonymized_at: datetime | None = Field(None, description="When user was anonymized")
    saml_idp_id: str | None = Field(None, description="Assigned SAML IdP UUID")
    saml_idp_name: str | None = Field(None, description="Assigned SAML IdP name")
    has_password: bool = Field(False, description="Whether user has a password set")
    password_reset_required: bool = Field(
        False, description="Whether user must change password on next login"
    )


class UserCreate(BaseModel):
    """Request to create a new user (admin operation)."""

    first_name: str = Field(..., min_length=1, max_length=255, description="User's first name")
    last_name: str = Field(..., min_length=1, max_length=255, description="User's last name")
    email: EmailStr = Field(..., max_length=320, description="Primary email address")
    role: str = Field(
        "member",
        max_length=50,
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
        max_length=50,
        pattern="^(member|admin|super_admin)$",
        description="User role (requires super_admin to set super_admin)",
    )
