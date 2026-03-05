"""Downstream SAML Service Provider database operations."""

import json

from database._core import TenantArg, execute, fetchall, fetchone

_SP_COLUMNS = """id, tenant_id, name, description, entity_id, acs_url,
               certificate_pem, nameid_format, metadata_xml, metadata_url,
               slo_url, include_group_claims, sp_requested_attributes,
               attribute_mapping, enabled, trust_established, available_to_all,
               created_by, created_at, updated_at"""


def list_service_providers(tenant_id: TenantArg) -> list[dict]:
    """List all service providers for a tenant.

    Returns:
        List of SP dicts ordered by created_at desc
    """
    return fetchall(
        tenant_id,
        f"""
        select {_SP_COLUMNS}
        from service_providers
        order by created_at desc
        """,
        {},
    )


def get_service_provider(tenant_id: TenantArg, sp_id: str) -> dict | None:
    """Get a service provider by ID.

    Returns:
        SP dict or None if not found
    """
    return fetchone(
        tenant_id,
        f"""
        select {_SP_COLUMNS}
        from service_providers
        where id = :sp_id
        """,
        {"sp_id": sp_id},
    )


def get_service_provider_by_entity_id(tenant_id: TenantArg, entity_id: str) -> dict | None:
    """Get a service provider by entity ID.

    Returns:
        SP dict or None if not found
    """
    return fetchone(
        tenant_id,
        f"""
        select {_SP_COLUMNS}
        from service_providers
        where entity_id = :entity_id
        """,
        {"entity_id": entity_id},
    )


def create_service_provider(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    created_by: str,
    entity_id: str | None = None,
    acs_url: str | None = None,
    certificate_pem: str | None = None,
    nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    metadata_xml: str | None = None,
    metadata_url: str | None = None,
    description: str | None = None,
    slo_url: str | None = None,
    sp_requested_attributes: list[dict] | None = None,
    attribute_mapping: dict[str, str] | None = None,
    trust_established: bool = False,
) -> dict | None:
    """Create a new service provider.

    Returns:
        Dict with created SP details
    """
    return fetchone(
        tenant_id,
        f"""
        insert into service_providers (
            tenant_id, name, description, entity_id, acs_url,
            certificate_pem, nameid_format, metadata_xml, metadata_url,
            slo_url, sp_requested_attributes, attribute_mapping,
            trust_established, created_by
        )
        values (
            :tenant_id, :name, :description, :entity_id, :acs_url,
            :certificate_pem, :nameid_format, :metadata_xml, :metadata_url,
            :slo_url, :sp_requested_attributes, :attribute_mapping,
            :trust_established, :created_by
        )
        returning {_SP_COLUMNS}
        """,
        {
            "tenant_id": tenant_id_value,
            "name": name,
            "description": description,
            "entity_id": entity_id,
            "acs_url": acs_url,
            "certificate_pem": certificate_pem,
            "nameid_format": nameid_format,
            "metadata_xml": metadata_xml,
            "metadata_url": metadata_url,
            "slo_url": slo_url,
            "sp_requested_attributes": json.dumps(sp_requested_attributes)
            if sp_requested_attributes
            else None,
            "attribute_mapping": json.dumps(attribute_mapping) if attribute_mapping else None,
            "trust_established": trust_established,
            "created_by": created_by,
        },
    )


def update_service_provider(
    tenant_id: TenantArg,
    sp_id: str,
    **fields: str | bool | None,
) -> dict | None:
    """Update a service provider's mutable fields.

    Only the provided keyword arguments are updated. Allowed keys:
    name, description, acs_url, enabled.

    Returns:
        Updated SP dict, or None if not found
    """
    allowed = {
        "name",
        "description",
        "acs_url",
        "slo_url",
        "nameid_format",
        "include_group_claims",
        "attribute_mapping",
        "enabled",
        "available_to_all",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_service_provider(tenant_id, sp_id)

    # Serialize JSONB fields
    if "attribute_mapping" in updates:
        updates["attribute_mapping"] = json.dumps(updates["attribute_mapping"])

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    params = {**updates, "sp_id": sp_id}

    return fetchone(
        tenant_id,
        f"""
        update service_providers
        set {set_clause}, updated_at = now()
        where id = :sp_id
        returning {_SP_COLUMNS}
        """,
        params,
    )


def set_service_provider_enabled(tenant_id: TenantArg, sp_id: str, enabled: bool) -> dict | None:
    """Toggle the enabled flag on a service provider.

    Returns:
        Updated SP dict, or None if not found
    """
    return update_service_provider(tenant_id, sp_id, enabled=enabled)


def refresh_sp_metadata_fields(
    tenant_id: TenantArg,
    sp_id: str,
    acs_url: str,
    certificate_pem: str | None = None,
    nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    metadata_xml: str | None = None,
    slo_url: str | None = None,
    sp_requested_attributes: list[dict] | None = None,
    attribute_mapping: dict[str, str] | None = None,
) -> dict | None:
    """Update metadata-derived fields on an SP after a refresh or reimport.

    Does NOT touch name, description, entity_id, enabled, or metadata_url.

    Returns:
        Updated SP dict, or None if not found
    """
    return fetchone(
        tenant_id,
        f"""
        update service_providers
        set acs_url = :acs_url,
            certificate_pem = :certificate_pem,
            nameid_format = :nameid_format,
            metadata_xml = :metadata_xml,
            slo_url = :slo_url,
            sp_requested_attributes = :sp_requested_attributes,
            attribute_mapping = :attribute_mapping,
            updated_at = now()
        where id = :sp_id
        returning {_SP_COLUMNS}
        """,
        {
            "sp_id": sp_id,
            "acs_url": acs_url,
            "certificate_pem": certificate_pem,
            "nameid_format": nameid_format,
            "metadata_xml": metadata_xml,
            "slo_url": slo_url,
            "sp_requested_attributes": json.dumps(sp_requested_attributes)
            if sp_requested_attributes
            else None,
            "attribute_mapping": json.dumps(attribute_mapping) if attribute_mapping else None,
        },
    )


def establish_trust(
    tenant_id: TenantArg,
    sp_id: str,
    entity_id: str,
    acs_url: str,
    certificate_pem: str | None = None,
    nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    metadata_xml: str | None = None,
    metadata_url: str | None = None,
    slo_url: str | None = None,
    sp_requested_attributes: list[dict] | None = None,
    attribute_mapping: dict[str, str] | None = None,
) -> dict | None:
    """Establish trust with a pending SP by setting entity_id, acs_url, and metadata fields.

    Only updates SPs where trust_established = false.

    Returns:
        Updated SP dict, or None if not found or already established
    """
    return fetchone(
        tenant_id,
        f"""
        update service_providers
        set entity_id = :entity_id,
            acs_url = :acs_url,
            certificate_pem = :certificate_pem,
            nameid_format = :nameid_format,
            metadata_xml = :metadata_xml,
            metadata_url = :metadata_url,
            slo_url = :slo_url,
            sp_requested_attributes = :sp_requested_attributes,
            attribute_mapping = :attribute_mapping,
            trust_established = true,
            updated_at = now()
        where id = :sp_id and trust_established = false
        returning {_SP_COLUMNS}
        """,
        {
            "sp_id": sp_id,
            "entity_id": entity_id,
            "acs_url": acs_url,
            "certificate_pem": certificate_pem,
            "nameid_format": nameid_format,
            "metadata_xml": metadata_xml,
            "metadata_url": metadata_url,
            "slo_url": slo_url,
            "sp_requested_attributes": json.dumps(sp_requested_attributes)
            if sp_requested_attributes
            else None,
            "attribute_mapping": json.dumps(attribute_mapping) if attribute_mapping else None,
        },
    )


def delete_service_provider(tenant_id: TenantArg, sp_id: str) -> int:
    """Delete a service provider.

    Returns:
        Number of rows deleted
    """
    return execute(
        tenant_id,
        "delete from service_providers where id = :sp_id",
        {"sp_id": sp_id},
    )
