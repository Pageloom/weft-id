"""Pydantic schemas for downstream SAML Service Provider management."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field

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
    slo_url: str | None = Field(None, min_length=1, max_length=2048)
    include_group_claims: bool | None = None
    attribute_mapping: (
        dict[Annotated[str, Field(max_length=255)], Annotated[str, Field(max_length=255)]] | None
    ) = None


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
    nameid_format: str
    include_group_claims: bool = False
    sp_requested_attributes: list[dict] | None = None
    attribute_mapping: dict[str, str] | None = None
    metadata_url: str | None = None
    metadata_xml: str | None = None
    enabled: bool = True
    trust_established: bool = False
    signing_cert_expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class SPListItem(BaseModel):
    """SP list item (summary view)."""

    id: str
    name: str
    entity_id: str | None = None
    enabled: bool = True
    trust_established: bool = True
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

    group_ids: list[Annotated[str, Field(min_length=1, max_length=36)]] = Field(..., min_length=1)


class UserApp(BaseModel):
    """An application accessible to the user."""

    id: str
    name: str
    description: str | None = None
    entity_id: str | None = None


class UserAppList(BaseModel):
    """List of apps accessible to a user."""

    items: list[UserApp]
    total: int
