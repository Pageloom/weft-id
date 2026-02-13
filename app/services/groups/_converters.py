"""Row-to-schema conversion helpers for groups service.

These private helpers convert database rows to Pydantic schemas.
They are used by multiple modules in the groups package.
"""

from schemas.groups import (
    GroupDetail,
    GroupMember,
    GroupMemberDetail,
    GroupRelationship,
    GroupSummary,
)


def _row_to_summary(row: dict) -> GroupSummary:
    """Convert database row to GroupSummary."""
    return GroupSummary(
        id=str(row["id"]),
        name=row["name"],
        description=row.get("description"),
        group_type=row["group_type"],
        idp_id=str(row["idp_id"]) if row.get("idp_id") else None,
        idp_name=row.get("idp_name"),
        is_valid=row.get("is_valid", True),
        member_count=row.get("member_count", 0),
        created_at=row["created_at"],
    )


def _row_to_detail(row: dict) -> GroupDetail:
    """Convert database row to GroupDetail."""
    return GroupDetail(
        id=str(row["id"]),
        name=row["name"],
        description=row.get("description"),
        group_type=row["group_type"],
        idp_id=str(row["idp_id"]) if row.get("idp_id") else None,
        idp_name=row.get("idp_name"),
        is_valid=row.get("is_valid", True),
        member_count=row.get("member_count", 0),
        parent_count=row.get("parent_count", 0),
        child_count=row.get("child_count", 0),
        created_by=str(row["created_by"]) if row.get("created_by") else None,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_member(row: dict) -> GroupMember:
    """Convert database row to GroupMember."""
    return GroupMember(
        id=str(row["id"]),
        user_id=str(row["user_id"]),
        email=row.get("email"),
        first_name=row.get("first_name", ""),
        last_name=row.get("last_name", ""),
        created_at=row["created_at"],
    )


def _row_to_member_detail(row: dict) -> GroupMemberDetail:
    """Convert database row to GroupMemberDetail."""
    return GroupMemberDetail(
        id=str(row["id"]),
        user_id=str(row["user_id"]),
        email=row.get("email"),
        first_name=row.get("first_name", ""),
        last_name=row.get("last_name", ""),
        role=row.get("role", "member"),
        is_inactivated=row.get("is_inactivated", False),
        is_anonymized=row.get("is_anonymized", False),
        created_at=row["created_at"],
    )


def _row_to_relationship(row: dict) -> GroupRelationship:
    """Convert database row to GroupRelationship."""
    return GroupRelationship(
        id=str(row["id"]),
        group_id=str(row["group_id"]),
        name=row["name"],
        group_type=row["group_type"],
        member_count=row.get("member_count", 0),
        created_at=row["created_at"],
    )
