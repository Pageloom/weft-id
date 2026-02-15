"""Row-to-schema conversion helpers for service_providers service.

These private helpers convert database rows to Pydantic schemas.
They are used by multiple modules in the service_providers package.
"""

from schemas.service_providers import SPConfig, SPListItem


def _row_to_config(row: dict) -> SPConfig:
    """Convert database row to SPConfig schema."""
    return SPConfig(
        id=str(row["id"]),
        name=row["name"],
        description=row.get("description"),
        entity_id=row.get("entity_id"),
        acs_url=row.get("acs_url"),
        slo_url=row.get("slo_url"),
        certificate_pem=row.get("certificate_pem"),
        nameid_format=row["nameid_format"],
        include_group_claims=row.get("include_group_claims", False),
        sp_requested_attributes=row.get("sp_requested_attributes"),
        attribute_mapping=row.get("attribute_mapping"),
        metadata_url=row.get("metadata_url"),
        metadata_xml=row.get("metadata_xml"),
        enabled=row.get("enabled", True),
        trust_established=row.get("trust_established", False),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_list_item(
    row: dict, signing_cert_expires_at=None, assigned_group_count: int = 0
) -> SPListItem:
    """Convert database row to SPListItem schema."""
    return SPListItem(
        id=str(row["id"]),
        name=row["name"],
        entity_id=row.get("entity_id"),
        enabled=row.get("enabled", True),
        trust_established=row.get("trust_established", True),
        signing_cert_expires_at=signing_cert_expires_at,
        assigned_group_count=assigned_group_count,
        created_at=row["created_at"],
    )
