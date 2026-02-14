"""Pydantic schemas for downstream SAML Service Provider management."""

from datetime import datetime

from pydantic import BaseModel, Field

# ============================================================================
# Request Schemas
# ============================================================================


class SPCreate(BaseModel):
    """Manual SP registration."""

    name: str = Field(..., min_length=1, max_length=255)
    entity_id: str = Field(..., min_length=1)
    acs_url: str = Field(..., min_length=1)
    description: str | None = None
    slo_url: str | None = None


class SPMetadataImportXML(BaseModel):
    """SP registration from pasted metadata XML."""

    name: str = Field(..., min_length=1, max_length=255)
    metadata_xml: str = Field(..., min_length=1)


class SPMetadataImportURL(BaseModel):
    """SP registration from metadata URL."""

    name: str = Field(..., min_length=1, max_length=255)
    metadata_url: str = Field(..., min_length=1)


class SPUpdate(BaseModel):
    """Update SP configuration. At least one field must be provided."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    acs_url: str | None = Field(None, min_length=1)
    slo_url: str | None = Field(None, min_length=1)
    include_group_claims: bool | None = None
    attribute_mapping: dict[str, str] | None = None


# ============================================================================
# Response Schemas
# ============================================================================


class SPConfig(BaseModel):
    """Full SP configuration response."""

    id: str
    name: str
    description: str | None = None
    entity_id: str
    acs_url: str
    slo_url: str | None = None
    certificate_pem: str | None = None
    nameid_format: str
    include_group_claims: bool = False
    sp_requested_attributes: list[dict] | None = None
    attribute_mapping: dict[str, str] | None = None
    enabled: bool = True
    signing_cert_expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class SPListItem(BaseModel):
    """SP list item (summary view)."""

    id: str
    name: str
    entity_id: str
    enabled: bool = True
    signing_cert_expires_at: datetime | None = None
    assigned_group_count: int = 0
    created_at: datetime


class SPListResponse(BaseModel):
    """Paginated SP list response."""

    items: list[SPListItem]
    total: int


class IdPMetadataInfo(BaseModel):
    """IdP metadata URL info for API consumers."""

    metadata_url: str
    entity_id: str
    sso_url: str
    slo_url: str


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
    sp_entity_id: str
    sp_description: str | None = None
    assigned_by: str
    assigned_at: datetime


class GroupSPAssignmentList(BaseModel):
    """List of SP assignments for a group."""

    items: list[GroupSPAssignment]
    total: int


class SPGroupAssignAdd(BaseModel):
    """Request to assign a group to an SP."""

    group_id: str = Field(..., min_length=1)


class SPGroupBulkAssign(BaseModel):
    """Request to bulk-assign groups to an SP."""

    group_ids: list[str] = Field(..., min_length=1)


class UserApp(BaseModel):
    """An application accessible to the user."""

    id: str
    name: str
    description: str | None = None
    entity_id: str


class UserAppList(BaseModel):
    """List of apps accessible to a user."""

    items: list[UserApp]
    total: int
