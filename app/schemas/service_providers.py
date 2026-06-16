"""Pydantic schemas for downstream SAML Service Provider management."""

from datetime import datetime
from typing import Annotated, Literal

from constants.user_attributes import ATTRIBUTE_KEYS, FIXED_SP_ATTRIBUTE_KEYS
from pydantic import BaseModel, Field, field_validator


def _validate_sp_attribute_mapping_keys(
    value: dict[str, str] | None,
) -> dict[str, str] | None:
    """Reject mapping keys outside the fixed SP set or the standard registry.

    Iteration 6: ensures tenants cannot persist mappings for unknown logical
    names that the assertion builder has no value source for.

    Allowed mapping keys = fixed SP set (camelCase wire names) ∪ standard
    attribute registry keys (snake_case logical names).
    """
    if value is None:
        return value
    allowed = FIXED_SP_ATTRIBUTE_KEYS | ATTRIBUTE_KEYS
    bad = sorted(k for k in value if k not in allowed)
    if bad:
        raise ValueError(
            "attribute_mapping contains unknown keys: " + ", ".join(bad),
        )
    return value


# ============================================================================
# Request Schemas
# ============================================================================


class SPCreate(BaseModel):
    """Manual SP registration. entity_id and acs_url are optional for step-by-step flow."""

    name: str = Field(..., min_length=1, max_length=255)
    entity_id: str | None = Field(None, min_length=1, max_length=2048)
    acs_url: str | None = Field(None, min_length=1, max_length=2048)
    description: str | None = Field(None, max_length=2000)
    slo_url: str | None = Field(None, max_length=2048)


class SPMetadataImportXML(BaseModel):
    """SP registration from pasted metadata XML."""

    name: str = Field(..., min_length=1, max_length=255)
    metadata_xml: str = Field(..., min_length=1, max_length=1000000)


class SPMetadataImportURL(BaseModel):
    """SP registration from metadata URL."""

    name: str = Field(..., min_length=1, max_length=255)
    metadata_url: str = Field(..., min_length=1, max_length=2048)


class SPEstablishTrustURL(BaseModel):
    """Establish trust with an SP by fetching its metadata URL."""

    metadata_url: str = Field(..., min_length=1, max_length=2048)


class SPEstablishTrustXML(BaseModel):
    """Establish trust with an SP by providing metadata XML."""

    metadata_xml: str = Field(..., min_length=1, max_length=1000000)


class SPEstablishTrustManual(BaseModel):
    """Establish trust with an SP by manually providing entity_id and acs_url."""

    entity_id: str = Field(..., min_length=1, max_length=2048)
    acs_url: str = Field(..., min_length=1, max_length=2048)
    slo_url: str | None = Field(None, max_length=2048)


class SPUpdate(BaseModel):
    """Update SP configuration. At least one field must be provided."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    acs_url: str | None = Field(None, min_length=1, max_length=2048)
    slo_url: str | None = Field(None, max_length=2048)
    nameid_format: Literal["emailAddress", "persistent", "transient", "unspecified"] | None = Field(
        None, max_length=50
    )
    include_group_claims: bool | None = None
    group_assertion_scope: Literal["all", "trunk", "access_relevant"] | None = None
    available_to_all: bool | None = None
    assertion_encryption_algorithm: Literal["aes256-cbc", "aes256-gcm"] | None = None
    attribute_mapping: (
        dict[Annotated[str, Field(max_length=255)], Annotated[str, Field(max_length=255)]] | None
    ) = None

    @field_validator("attribute_mapping")
    @classmethod
    def _check_mapping_keys(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        return _validate_sp_attribute_mapping_keys(value)


# ============================================================================
# Response Schemas
# ============================================================================


class SPConfig(BaseModel):
    """Full SP configuration response."""

    id: str
    name: str
    description: str | None = None
    entity_id: str | None = None
    acs_url: str | None = None
    slo_url: str | None = None
    certificate_pem: str | None = None
    encryption_certificate_pem: str | None = None
    assertion_encryption_algorithm: str = "aes256-cbc"
    nameid_format: str
    include_group_claims: bool = False
    group_assertion_scope: Literal["all", "trunk", "access_relevant"] | None = None
    sp_requested_attributes: list[dict] | None = None
    attribute_mapping: dict[str, str] | None = None
    metadata_url: str | None = None
    metadata_xml: str | None = None
    enabled: bool = True
    trust_established: bool = False
    available_to_all: bool = False
    signing_cert_expires_at: datetime | None = None
    has_logo: bool = Field(False, description="Whether a custom logo is uploaded for this SP")
    logo_updated_at: datetime | None = Field(None, description="When the SP logo was last updated")
    created_at: datetime
    updated_at: datetime


class SPListItem(BaseModel):
    """SP list item (summary view)."""

    id: str
    name: str
    entity_id: str | None = None
    enabled: bool = True
    trust_established: bool = True
    available_to_all: bool = False
    signing_cert_expires_at: datetime | None = None
    assigned_group_count: int = 0
    user_access_count: int = 0
    has_logo: bool = Field(False, description="Whether a custom logo is uploaded for this SP")
    logo_updated_at: datetime | None = Field(None, description="When the SP logo was last updated")
    created_at: datetime


class SPListResponse(BaseModel):
    """Paginated SP list response."""

    items: list[SPListItem]
    total: int


# ============================================================================
# SP Metadata Lifecycle Schemas
# ============================================================================


class SPMetadataFieldChange(BaseModel):
    """A single field change in a metadata refresh/reimport preview."""

    field: str
    old_value: str | None = None
    new_value: str | None = None


class SPMetadataChangePreview(BaseModel):
    """Preview of changes from a metadata refresh or reimport."""

    sp_id: str
    sp_name: str
    source: str  # "url" or "xml"
    changes: list[SPMetadataFieldChange]
    has_changes: bool


class SPMetadataReimport(BaseModel):
    """Request body for metadata reimport from XML."""

    metadata_xml: str = Field(..., min_length=1, max_length=1000000)


# ============================================================================
# Per-SP Signing Certificate Schemas
# ============================================================================


class SPSigningCertificate(BaseModel):
    """SP signing certificate info (no private key exposed)."""

    id: str
    sp_id: str
    certificate_pem: str
    expires_at: datetime
    created_at: datetime
    has_previous_certificate: bool = False
    rotation_grace_period_ends_at: datetime | None = None


class SPSigningCertificateRotationResult(BaseModel):
    """Result of an SP signing certificate rotation."""

    new_certificate_pem: str
    new_expires_at: datetime
    grace_period_ends_at: datetime


class SPMetadataURLInfo(BaseModel):
    """Per-SP metadata URL info for API consumers."""

    metadata_url: str
    entity_id: str
    sso_url: str
    sp_id: str
    sp_name: str


# ============================================================================
# SP Group Assignment Schemas
# ============================================================================


class SPGroupAssignment(BaseModel):
    """A single SP-to-group assignment."""

    id: str
    sp_id: str
    group_id: str
    group_name: str
    group_description: str | None = None
    group_type: str
    assigned_by: str
    assigned_at: datetime


class SPGroupAssignmentList(BaseModel):
    """List of group assignments for an SP."""

    items: list[SPGroupAssignment]
    total: int


class GroupSPAssignment(BaseModel):
    """A single group-to-SP assignment (from the group's perspective)."""

    id: str
    sp_id: str
    group_id: str
    sp_name: str
    sp_entity_id: str | None = None
    sp_description: str | None = None
    assigned_by: str
    assigned_at: datetime


class GroupSPAssignmentList(BaseModel):
    """List of SP assignments for a group."""

    items: list[GroupSPAssignment]
    total: int


class SPGroupAssignAdd(BaseModel):
    """Request to assign a group to an SP."""

    group_id: str = Field(..., min_length=1, max_length=36)


class SPGroupBulkAssign(BaseModel):
    """Request to bulk-assign groups to an SP."""

    group_ids: list[Annotated[str, Field(min_length=1, max_length=36)]] = Field(
        ..., min_length=1, max_length=5000
    )


class UserApp(BaseModel):
    """An application accessible to the user.

    Covers both SAML service providers (``kind="saml"``) and forward-auth
    proxy apps (``kind="proxy"``). ``launch_url`` is computed server-side so
    consumers do not need to know the per-kind URL convention: SAML apps launch
    via ``/saml/idp/launch/{id}``, proxy apps launch by navigating to their
    external URL (which trips the forward-auth handshake). The SAML-only fields
    (``entity_id``, ``has_logo``, ``logo_updated_at``) are absent/false for
    proxy rows.
    """

    id: str
    name: str
    description: str | None = None
    kind: Literal["saml", "proxy"] = "saml"
    launch_url: str
    entity_id: str | None = None
    has_logo: bool = Field(False, description="Whether a custom logo is uploaded for this SP")
    logo_updated_at: datetime | None = Field(None, description="When the SP logo was last updated")


class UserAppList(BaseModel):
    """List of apps accessible to a user."""

    items: list[UserApp]
    total: int


# ============================================================================
# User Accessible Apps (Admin View with Attribution)
# ============================================================================


class GrantingGroup(BaseModel):
    """A group that grants access to a service provider."""

    id: str
    name: str


class UserAccessibleApp(BaseModel):
    """An application accessible to a user, with group attribution."""

    id: str
    name: str
    description: str | None = None
    entity_id: str | None = None
    available_to_all: bool = False
    granting_groups: list[GrantingGroup] = []


class UserAccessibleAppList(BaseModel):
    """List of apps accessible to a user with attribution details."""

    items: list[UserAccessibleApp]
    total: int


# ============================================================================
# Assertion Preview Schemas
# ============================================================================


class AssertionPreview(BaseModel):
    """Preview of what a SAML assertion would contain for a user + SP pair.

    Used by super admins to debug attribute mapping and access without
    performing an actual SSO flow.
    """

    user_id: str
    user_email: str
    user_first_name: str
    user_last_name: str
    name_id: str
    name_id_format: str
    attributes: dict[str, str | list[str]]
    attribute_mapping: dict[str, str] | None = None
    group_names: list[str]
    group_assertion_scope: str
    has_access: bool
    assertion_encrypted: bool
    encryption_algorithm: str | None = None
    sp_name: str
    sp_entity_id: str | None = None
