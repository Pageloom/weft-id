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


class SPMetadataImportXML(BaseModel):
    """SP registration from pasted metadata XML."""

    name: str = Field(..., min_length=1, max_length=255)
    metadata_xml: str = Field(..., min_length=1)


class SPMetadataImportURL(BaseModel):
    """SP registration from metadata URL."""

    name: str = Field(..., min_length=1, max_length=255)
    metadata_url: str = Field(..., min_length=1)


# ============================================================================
# Response Schemas
# ============================================================================


class SPConfig(BaseModel):
    """Full SP configuration response."""

    id: str
    name: str
    entity_id: str
    acs_url: str
    certificate_pem: str | None = None
    nameid_format: str
    signing_cert_expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class SPListItem(BaseModel):
    """SP list item (summary view)."""

    id: str
    name: str
    entity_id: str
    signing_cert_expires_at: datetime | None = None
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
