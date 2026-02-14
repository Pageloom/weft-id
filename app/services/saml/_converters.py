"""Row-to-schema conversion helpers for SAML service.

These private helpers convert database rows to Pydantic schemas.
They are used by multiple modules in the saml package.
"""

from schemas.saml import IdPConfig, IdPListItem


def idp_row_to_config(row: dict) -> IdPConfig:
    """Convert database row to IdPConfig schema."""
    # Compute sp_acs_url from sp_entity_id (shared ACS URL for all IdPs)
    sp_entity_id = row["sp_entity_id"]
    sp_acs_url = sp_entity_id.replace("/saml/metadata", "/saml/acs")

    return IdPConfig(
        id=str(row["id"]),
        name=row["name"],
        provider_type=row["provider_type"],
        entity_id=row["entity_id"],
        sso_url=row["sso_url"],
        slo_url=row["slo_url"],
        certificate_pem=row["certificate_pem"],
        metadata_url=row["metadata_url"],
        metadata_xml=row.get("metadata_xml"),
        metadata_last_fetched_at=row["metadata_last_fetched_at"],
        metadata_fetch_error=row["metadata_fetch_error"],
        sp_entity_id=sp_entity_id,
        sp_acs_url=sp_acs_url,
        attribute_mapping=row["attribute_mapping"],
        is_enabled=row["is_enabled"],
        is_default=row["is_default"],
        require_platform_mfa=row["require_platform_mfa"],
        jit_provisioning=row["jit_provisioning"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def idp_row_to_list_item(row: dict) -> IdPListItem:
    """Convert database row to IdPListItem schema."""
    return IdPListItem(
        id=str(row["id"]),
        name=row["name"],
        provider_type=row["provider_type"],
        is_enabled=row["is_enabled"],
        is_default=row["is_default"],
        metadata_url=row["metadata_url"],
        metadata_last_fetched_at=row["metadata_last_fetched_at"],
        metadata_fetch_error=row["metadata_fetch_error"],
        created_at=row["created_at"],
    )
