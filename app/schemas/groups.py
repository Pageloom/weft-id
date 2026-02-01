"""Pydantic schemas for group management."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# ============================================================================
# Group Schemas
# ============================================================================


class GroupCreate(BaseModel):
    """Request to create a new group."""

    name: str = Field(..., min_length=1, max_length=200, description="Group name")
    description: str | None = Field(
        None, max_length=2000, description="Optional group description"
    )


class GroupUpdate(BaseModel):
    """Request to update a group."""

    name: str | None = Field(
        None, min_length=1, max_length=200, description="Group name"
    )
    description: str | None = Field(
        None, max_length=2000, description="Group description (empty string to clear)"
    )


class GroupSummary(BaseModel):
    """Group summary for list views."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Group UUID")
    name: str = Field(..., description="Group name")
    description: str | None = Field(None, description="Group description")
    group_type: str = Field(..., description="Group type (weftid or idp)")
    is_valid: bool = Field(True, description="Whether group is valid (IdP groups)")
    member_count: int = Field(0, description="Number of direct members")
    created_at: datetime = Field(..., description="Creation timestamp")


class GroupDetail(BaseModel):
    """Detailed group information."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Group UUID")
    name: str = Field(..., description="Group name")
    description: str | None = Field(None, description="Group description")
    group_type: str = Field(..., description="Group type (weftid or idp)")
    idp_id: str | None = Field(None, description="Source IdP UUID (for IdP groups)")
    is_valid: bool = Field(True, description="Whether group is valid")
    member_count: int = Field(0, description="Number of direct members")
    parent_count: int = Field(0, description="Number of parent groups")
    child_count: int = Field(0, description="Number of child groups")
    created_by: str | None = Field(None, description="User who created the group")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


class GroupListResponse(BaseModel):
    """Paginated list of groups."""

    items: list[GroupSummary] = Field(..., description="List of groups")
    total: int = Field(..., description="Total number of matching groups")
    page: int = Field(..., description="Current page number (1-indexed)")
    limit: int = Field(..., description="Page size limit")


# ============================================================================
# Group Membership Schemas
# ============================================================================


class GroupMember(BaseModel):
    """Group member information."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Membership UUID")
    user_id: str = Field(..., description="User UUID")
    email: str | None = Field(None, description="User's primary email")
    first_name: str = Field(..., description="User's first name")
    last_name: str = Field(..., description="User's last name")
    created_at: datetime = Field(..., description="When user joined the group")


class GroupMemberAdd(BaseModel):
    """Request to add a member to a group."""

    user_id: str = Field(..., description="User UUID to add")


class GroupMemberList(BaseModel):
    """List of group members."""

    items: list[GroupMember] = Field(..., description="List of members")
    total: int = Field(..., description="Total number of members")


# ============================================================================
# Group Relationship Schemas
# ============================================================================


class GroupRelationship(BaseModel):
    """Group relationship information (parent or child)."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Relationship UUID")
    group_id: str = Field(..., description="Related group UUID")
    name: str = Field(..., description="Related group name")
    group_type: str = Field(..., description="Related group type")
    member_count: int = Field(0, description="Number of direct members")
    created_at: datetime = Field(..., description="When relationship was created")


class GroupRelationshipAdd(BaseModel):
    """Request to add a child group."""

    child_group_id: str = Field(..., description="Child group UUID to add")


class GroupParentsList(BaseModel):
    """List of parent groups."""

    items: list[GroupRelationship] = Field(..., description="List of parent groups")
    total: int = Field(..., description="Total number of parents")


class GroupChildrenList(BaseModel):
    """List of child groups."""

    items: list[GroupRelationship] = Field(..., description="List of child groups")
    total: int = Field(..., description="Total number of children")


# ============================================================================
# Group Ancestry Schemas (from lineage table)
# ============================================================================


class GroupAncestor(BaseModel):
    """Ancestor group with depth information."""

    model_config = ConfigDict(from_attributes=True)

    group_id: str = Field(..., description="Ancestor group UUID")
    name: str = Field(..., description="Ancestor group name")
    depth: int = Field(..., description="Distance from descendant (0=self, 1=direct)")
