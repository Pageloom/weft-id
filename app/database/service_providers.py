"""Downstream SAML Service Provider database operations."""

from database._core import TenantArg, execute, fetchall, fetchone


def list_service_providers(tenant_id: TenantArg) -> list[dict]:
    """List all service providers for a tenant.

    Returns:
        List of SP dicts ordered by created_at desc
    """
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, name, entity_id, acs_url,
               certificate_pem, nameid_format, metadata_xml,
               created_by, created_at, updated_at
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
        """
        select id, tenant_id, name, entity_id, acs_url,
               certificate_pem, nameid_format, metadata_xml,
               created_by, created_at, updated_at
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
        """
        select id, tenant_id, name, entity_id, acs_url,
               certificate_pem, nameid_format, metadata_xml,
               created_by, created_at, updated_at
        from service_providers
        where entity_id = :entity_id
        """,
        {"entity_id": entity_id},
    )


def create_service_provider(
    tenant_id: TenantArg,
    tenant_id_value: str,
    name: str,
    entity_id: str,
    acs_url: str,
    created_by: str,
    certificate_pem: str | None = None,
    nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    metadata_xml: str | None = None,
) -> dict | None:
    """Create a new service provider.

    Returns:
        Dict with created SP details
    """
    return fetchone(
        tenant_id,
        """
        insert into service_providers (
            tenant_id, name, entity_id, acs_url,
            certificate_pem, nameid_format, metadata_xml,
            created_by
        )
        values (
            :tenant_id, :name, :entity_id, :acs_url,
            :certificate_pem, :nameid_format, :metadata_xml,
            :created_by
        )
        returning id, tenant_id, name, entity_id, acs_url,
                  certificate_pem, nameid_format, metadata_xml,
                  created_by, created_at, updated_at
        """,
        {
            "tenant_id": tenant_id_value,
            "name": name,
            "entity_id": entity_id,
            "acs_url": acs_url,
            "certificate_pem": certificate_pem,
            "nameid_format": nameid_format,
            "metadata_xml": metadata_xml,
            "created_by": created_by,
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
