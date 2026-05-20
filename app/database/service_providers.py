"""Downstream SAML Service Provider database operations."""

import json

from database._core import UNSCOPED, TenantArg, execute, fetchall, fetchone

_SP_COLUMNS = """id, tenant_id, name, description, entity_id, acs_url,
               certificate_pem, encryption_certificate_pem,
               assertion_encryption_algorithm,
               nameid_format, metadata_xml, metadata_url,
               slo_url, include_group_claims, group_assertion_scope,
               sp_requested_attributes,
               attribute_mapping, enabled, trust_established, available_to_all,
               scim_enabled, scim_target_url, scim_kind,
               scim_membership_mode, scim_log_retention,
               created_by, created_at, updated_at"""

# Qualified columns for queries with JOINs (avoids ambiguous column errors)
_SP_COLUMNS_Q = """sp.id, sp.tenant_id, sp.name, sp.description, sp.entity_id, sp.acs_url,
               sp.certificate_pem, sp.encryption_certificate_pem,
               sp.assertion_encryption_algorithm,
               sp.nameid_format, sp.metadata_xml, sp.metadata_url,
               sp.slo_url, sp.include_group_claims, sp.group_assertion_scope,
               sp.sp_requested_attributes,
               sp.attribute_mapping, sp.enabled, sp.trust_established, sp.available_to_all,
               sp.scim_enabled, sp.scim_target_url, sp.scim_kind,
               sp.scim_membership_mode, sp.scim_log_retention,
               sp.created_by, sp.created_at, sp.updated_at"""


def list_service_providers(tenant_id: TenantArg) -> list[dict]:
    """List all service providers for a tenant.

    Returns:
        List of SP dicts ordered by created_at desc
    """
    return fetchall(
        tenant_id,
        f"""
        select {_SP_COLUMNS_Q},
               (spl.sp_id IS NOT NULL) AS has_logo,
               spl.updated_at AS logo_updated_at
        from service_providers sp
        left join sp_logos spl on spl.sp_id = sp.id
        order by sp.created_at desc
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
        select {_SP_COLUMNS_Q},
               (spl.sp_id IS NOT NULL) AS has_logo,
               spl.updated_at AS logo_updated_at
        from service_providers sp
        left join sp_logos spl on spl.sp_id = sp.id
        where sp.id = :sp_id
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
    encryption_certificate_pem: str | None = None,
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
            certificate_pem, encryption_certificate_pem,
            nameid_format, metadata_xml, metadata_url,
            slo_url, sp_requested_attributes, attribute_mapping,
            trust_established, created_by
        )
        values (
            :tenant_id, :name, :description, :entity_id, :acs_url,
            :certificate_pem, :encryption_certificate_pem,
            :nameid_format, :metadata_xml, :metadata_url,
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
            "encryption_certificate_pem": encryption_certificate_pem,
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
        "group_assertion_scope",
        "assertion_encryption_algorithm",
        "attribute_mapping",
        "enabled",
        "available_to_all",
        # Outbound SCIM columns (iter-5).
        "scim_enabled",
        "scim_target_url",
        "scim_kind",
        "scim_membership_mode",
        "scim_log_retention",
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
    encryption_certificate_pem: str | None = None,
    nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    metadata_xml: str | None = None,
    slo_url: str | None = None,
    sp_requested_attributes: list[dict] | None = None,
    attribute_mapping: dict[str, str] | None = None,
    assertion_encryption_algorithm: str | None = None,
) -> dict | None:
    """Update metadata-derived fields on an SP after a refresh or reimport.

    Does NOT touch name, description, entity_id, enabled, or metadata_url.
    assertion_encryption_algorithm is only updated when explicitly provided
    (auto-detected from SP metadata EncryptionMethod declarations).

    Returns:
        Updated SP dict, or None if not found
    """
    # Build SET clause dynamically so we only touch algorithm when auto-detected
    set_parts = [
        "acs_url = :acs_url",
        "certificate_pem = :certificate_pem",
        "encryption_certificate_pem = :encryption_certificate_pem",
        "nameid_format = :nameid_format",
        "metadata_xml = :metadata_xml",
        "slo_url = :slo_url",
        "sp_requested_attributes = :sp_requested_attributes",
        "attribute_mapping = :attribute_mapping",
    ]
    params: dict = {
        "sp_id": sp_id,
        "acs_url": acs_url,
        "certificate_pem": certificate_pem,
        "encryption_certificate_pem": encryption_certificate_pem,
        "nameid_format": nameid_format,
        "metadata_xml": metadata_xml,
        "slo_url": slo_url,
        "sp_requested_attributes": json.dumps(sp_requested_attributes)
        if sp_requested_attributes
        else None,
        "attribute_mapping": json.dumps(attribute_mapping) if attribute_mapping else None,
    }
    if assertion_encryption_algorithm is not None:
        set_parts.append("assertion_encryption_algorithm = :assertion_encryption_algorithm")
        params["assertion_encryption_algorithm"] = assertion_encryption_algorithm

    set_clause = ", ".join(set_parts)

    return fetchone(
        tenant_id,
        f"""
        update service_providers
        set {set_clause},
            updated_at = now()
        where id = :sp_id
        returning {_SP_COLUMNS}
        """,
        params,
    )


def establish_trust(
    tenant_id: TenantArg,
    sp_id: str,
    entity_id: str,
    acs_url: str,
    certificate_pem: str | None = None,
    encryption_certificate_pem: str | None = None,
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
            encryption_certificate_pem = :encryption_certificate_pem,
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
            "encryption_certificate_pem": encryption_certificate_pem,
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


def get_scim_target(tenant_id: TenantArg, sp_id: str) -> dict | None:
    """Get the SCIM transport-relevant columns for one SP.

    Returns the subset of `service_providers` columns the SCIM client and
    push worker need: id, name, scim_enabled, scim_target_url, scim_kind,
    scim_membership_mode, scim_log_retention, available_to_all. Returns
    None when the SP does not exist.
    """
    return fetchone(
        tenant_id,
        """
        select id, name, scim_enabled, scim_target_url, scim_kind,
               scim_membership_mode, scim_log_retention, available_to_all
        from service_providers
        where id = :sp_id
        """,
        {"sp_id": sp_id},
    )


def list_scim_enabled_sps(tenant_id: TenantArg) -> list[dict]:
    """List all SCIM-enabled SPs for a tenant.

    Returns id and scim_log_retention only -- this is the data the cleanup
    job needs. Used by `cleanup_scim_sync_log`.
    """
    return fetchall(
        tenant_id,
        """
        select id, scim_log_retention
        from service_providers
        where scim_enabled = true
        """,
    )


def list_scim_enabled_sps_all_tenants() -> list[dict]:
    """Cross-tenant scan of every SCIM-enabled SP plus its retention policy.

    Returns id, tenant_id, and scim_log_retention. Used by the nightly
    sync-log cleanup job to walk every SP across every tenant.

    Routes through the `list_scim_enabled_sps_all_tenants_unscoped()`
    SECURITY DEFINER function (migration 0040). The function is owned by
    `appowner` (the table owner, which is exempt from RLS) and exposes
    exactly the three columns the cleanup job needs. The
    `service_providers` table's normal RLS policy is otherwise strict and
    rejects unscoped reads, so this is the only sanctioned cross-tenant
    accessor for SCIM cleanup.
    """
    return fetchall(
        UNSCOPED,
        """
        select id, tenant_id, scim_log_retention
        from list_scim_enabled_sps_all_tenants_unscoped()
        """,
    )
