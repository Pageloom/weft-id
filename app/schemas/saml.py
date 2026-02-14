"""Pydantic schemas for SAML IdP management and authentication."""

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

# ============================================================================
# Provider Type Constants
# ============================================================================

PROVIDER_TYPES = ("okta", "azure_ad", "google", "generic")

DEFAULT_ATTRIBUTE_MAPPING = {
    "email": "email",
    "first_name": "firstName",
    "last_name": "lastName",
    "groups": "groups",
}

# Provider-specific attribute mapping presets (Phase 4)
PROVIDER_ATTRIBUTE_PRESETS: dict[str, dict[str, str]] = {
    "okta": {
        "email": "email",
        "first_name": "firstName",
        "last_name": "lastName",
        "groups": "groups",
    },
    "azure_ad": {
        "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "first_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "last_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        "groups": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
    },
    "google": {
        "email": "email",
        "first_name": "first_name",
        "last_name": "last_name",
        "groups": "groups",
    },
    "generic": DEFAULT_ATTRIBUTE_MAPPING,
}

# Provider setup guide URLs (Phase 4)
PROVIDER_SETUP_GUIDES: dict[str, str | None] = {
    "okta": "https://developer.okta.com/docs/guides/build-sso-integration/saml2/main/",
    "azure_ad": "https://learn.microsoft.com/en-us/entra/identity/saas-apps/tutorial-list",
    "google": "https://support.google.com/a/answer/6087519",
    "generic": None,
}


# ============================================================================
# IdP Configuration Schemas
# ============================================================================


class IdPCreate(BaseModel):
    """Request schema for creating an IdP."""

    name: str = Field(..., min_length=1, max_length=255)
    provider_type: str = Field(..., pattern="^(okta|azure_ad|google|generic)$")
    entity_id: str = Field(..., min_length=1)
    sso_url: str = Field(..., min_length=1)
    slo_url: str | None = None
    certificate_pem: str = Field(..., min_length=1)
    metadata_url: str | None = Field(None, description="Optional IdP metadata URL for auto-refresh")
    metadata_xml: str | None = Field(None, description="Raw metadata XML from import")
    attribute_mapping: dict[str, str] = Field(default_factory=lambda: DEFAULT_ATTRIBUTE_MAPPING)
    is_enabled: bool = False
    is_default: bool = False
    require_platform_mfa: bool = False
    jit_provisioning: bool = False


class IdPUpdate(BaseModel):
    """Request schema for updating an IdP."""

    name: str | None = None
    sso_url: str | None = None
    slo_url: str | None = None
    certificate_pem: str | None = None
    metadata_url: str | None = None
    attribute_mapping: dict[str, str] | None = None
    require_platform_mfa: bool | None = None
    jit_provisioning: bool | None = None


class IdPConfig(BaseModel):
    """Response schema for IdP configuration."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    provider_type: str
    entity_id: str
    sso_url: str
    slo_url: str | None
    certificate_pem: str
    metadata_url: str | None
    metadata_xml: str | None
    metadata_last_fetched_at: datetime | None
    metadata_fetch_error: str | None
    sp_entity_id: str
    sp_acs_url: str  # Computed from sp_entity_id (shared ACS URL for all IdPs)
    attribute_mapping: dict[str, str]
    is_enabled: bool
    is_default: bool
    require_platform_mfa: bool
    jit_provisioning: bool
    created_at: datetime
    updated_at: datetime


class IdPListItem(BaseModel):
    """Simplified IdP for list views."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    provider_type: str
    is_enabled: bool
    is_default: bool
    metadata_url: str | None
    metadata_last_fetched_at: datetime | None
    metadata_fetch_error: str | None
    created_at: datetime


class IdPListResponse(BaseModel):
    """Response schema for IdP list."""

    items: list[IdPListItem]
    total: int


# ============================================================================
# SP Certificate Schemas
# ============================================================================


class SPCertificate(BaseModel):
    """SP certificate info (no private key exposed)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    certificate_pem: str
    expires_at: datetime
    created_at: datetime


class SPMetadata(BaseModel):
    """SP metadata info for display in admin UI."""

    entity_id: str
    acs_url: str
    metadata_url: str
    certificate_pem: str
    certificate_expires_at: datetime


# ============================================================================
# IdP Metadata Import Schemas
# ============================================================================


class IdPMetadataParsed(BaseModel):
    """Parsed IdP metadata from URL or XML."""

    entity_id: str
    sso_url: str
    slo_url: str | None
    certificate_pem: str
    metadata_xml: str | None = None


class IdPMetadataImport(BaseModel):
    """Request schema for importing IdP from metadata URL."""

    name: str = Field(..., min_length=1, max_length=255)
    provider_type: str = Field(..., pattern="^(okta|azure_ad|google|generic)$")
    metadata_url: str = Field(..., min_length=1)


class IdPMetadataImportXML(BaseModel):
    """Request schema for importing IdP from raw metadata XML."""

    name: str = Field(..., min_length=1, max_length=255)
    provider_type: str = Field(..., pattern="^(okta|azure_ad|google|generic)$")
    metadata_xml: str = Field(..., min_length=1, description="Raw SAML metadata XML content")


# ============================================================================
# SAML Response Schemas
# ============================================================================


class SAMLAttributes(BaseModel):
    """Extracted SAML assertion attributes."""

    email: str
    first_name: str | None = None
    last_name: str | None = None
    name_id: str
    groups: list[str] = Field(default_factory=list)


class SAMLAuthResult(BaseModel):
    """Result of SAML authentication processing."""

    attributes: SAMLAttributes
    session_index: str | None = None
    name_id_format: str | None = None  # Needed for SLO (Phase 4)
    idp_id: str
    idp_name: str | None = None  # For group sync logging
    user_id: str | None = None  # Set after user lookup
    requires_mfa: bool = False
    groups: list[str] = Field(default_factory=list)  # Group claims from assertion


class SAMLTestResult(BaseModel):
    """Result of SAML connection test.

    Used by the connection testing feature to display detailed
    assertion information without creating a session or provisioning users.
    """

    success: bool
    error_type: str | None = None
    error_detail: str | None = None

    # Assertion details (only populated on success)
    name_id: str | None = None
    name_id_format: str | None = None
    session_index: str | None = None
    attributes: dict[str, list[str]] | None = None  # Raw SAML attributes

    # Parsed attributes using IdP's attribute mapping
    parsed_email: str | None = None
    parsed_first_name: str | None = None
    parsed_last_name: str | None = None


# ============================================================================
# Metadata Refresh Schemas
# ============================================================================


class MetadataRefreshResult(BaseModel):
    """Result of a single IdP metadata refresh."""

    idp_id: str
    idp_name: str
    success: bool
    error: str | None = None
    updated_fields: list[str] | None = None


class MetadataRefreshSummary(BaseModel):
    """Summary of bulk metadata refresh operation."""

    total: int
    successful: int
    failed: int
    results: list[MetadataRefreshResult]


# ============================================================================
# Login Flow Schemas
# ============================================================================


class IdPForLogin(BaseModel):
    """Minimal IdP info for login page display."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    provider_type: str


# ============================================================================
# Domain Binding Schemas (Phase 3)
# ============================================================================


class DomainBinding(BaseModel):
    """Domain-to-IdP binding info."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    domain_id: str
    domain: str
    idp_id: str
    created_at: datetime


class DomainBindingCreate(BaseModel):
    """Request to bind a domain to an IdP."""

    domain_id: str = Field(..., description="UUID of the privileged domain to bind")


class DomainBindingList(BaseModel):
    """List of domain bindings."""

    items: list[DomainBinding]


class UnboundDomain(BaseModel):
    """Privileged domain not bound to any IdP."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    domain: str


# ============================================================================
# Authentication Routing Schemas (Phase 3)
# ============================================================================


class AuthRouteResult(BaseModel):
    """Result of authentication route determination.

    Every user is either:
    - Password user (saml_idp_id = NULL) → route to password form
    - IdP user (saml_idp_id = UUID) → route to that IdP

    For unknown users:
    - If domain is bound to IdP with JIT → route to domain's IdP
    - If default IdP has JIT → route to default IdP
    - Otherwise → not found
    """

    route_type: str = Field(
        ...,
        description="Route type: password, idp, idp_jit, idp_disabled, "
        "not_found, inactivated, no_auth_method, invalid_email",
    )
    idp_id: str | None = Field(None, description="IdP UUID if route_type is idp or idp_jit")
    idp_name: str | None = Field(None, description="IdP name for display")
    user_id: str | None = Field(None, description="User UUID if user exists (internal use)")


class EmailCheckRequest(BaseModel):
    """Request to check authentication route for email."""

    email: str = Field(..., min_length=1, description="Email address to check")


class EmailCheckResponse(BaseModel):
    """Response with authentication route info (public-facing, no user_id)."""

    route_type: str
    idp_id: str | None = None
    idp_name: str | None = None


# ============================================================================
# User IdP Assignment Schemas (Phase 3)
# ============================================================================


class UserIdpAssignment(BaseModel):
    """Request to assign user to an IdP or set as password-only.

    Every user must be either:
    - Password user (saml_idp_id = null) - authenticates with password
    - IdP user (saml_idp_id = UUID) - authenticates via SAML
    """

    saml_idp_id: str | None = Field(
        None,
        description="IdP UUID to assign, or null for password-only user",
    )


# ============================================================================
# Provider Presets Schemas (Phase 4)
# ============================================================================


class ProviderPresets(BaseModel):
    """Provider-specific attribute presets and setup info."""

    provider_type: str
    attribute_mapping: dict[str, str]
    setup_guide_url: str | None = None


# ============================================================================
# Certificate Rotation Schemas (Phase 4)
# ============================================================================


class SPCertificateWithRotation(BaseModel):
    """SP certificate info with rotation details."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    certificate_pem: str
    expires_at: datetime
    created_at: datetime
    # Rotation fields
    previous_certificate_pem: str | None = None
    previous_expires_at: datetime | None = None
    rotation_grace_period_ends_at: datetime | None = None

    @property
    def is_in_rotation_grace_period(self) -> bool:
        """Check if certificate is currently in rotation grace period."""
        if not self.rotation_grace_period_ends_at:
            return False

        return datetime.now(UTC) < self.rotation_grace_period_ends_at


class CertificateRotationResult(BaseModel):
    """Result of SP certificate rotation."""

    new_certificate_pem: str
    new_expires_at: datetime
    grace_period_ends_at: datetime
    warning: str = "Update your IdP metadata configuration within the grace period."


# ============================================================================
# SAML Debug Schemas (Phase 4)
# ============================================================================


class SAMLDebugEntry(BaseModel):
    """A stored SAML debug entry for failed authentications."""

    timestamp: datetime
    saml_response_xml: str | None = None
    error_type: str
    error_detail: str | None = None
    idp_id: str | None = None
    idp_name: str | None = None


class SAMLDebugList(BaseModel):
    """List of SAML debug entries."""

    items: list[SAMLDebugEntry]
    total: int
