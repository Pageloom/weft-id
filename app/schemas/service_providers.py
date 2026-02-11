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
    created_at: datetime
    updated_at: datetime


class SPListItem(BaseModel):
    """SP list item (summary view)."""

    id: str
    name: str
    entity_id: str
    created_at: datetime


class SPListResponse(BaseModel):
    """Paginated SP list response."""

    items: list[SPListItem]
    total: int
