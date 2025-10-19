"""General settings database operations (privileged domains, etc.)."""

from ._core import TenantArg, execute, fetchall, fetchone


def list_privileged_domains(tenant_id: TenantArg) -> list[dict]:
    """
    List all privileged domains for a tenant.

    Returns:
        List of dicts with id, domain, created_at, first_name, last_name
    """
    return fetchall(
        tenant_id,
        """
        select pd.id, pd.domain, pd.created_at, u.first_name, u.last_name
        from tenant_privileged_domains pd
        left join users u on pd.created_by = u.id
        order by pd.created_at desc
        """,
    )


def privileged_domain_exists(tenant_id: TenantArg, domain: str) -> bool:
    """
    Check if a privileged domain already exists for a tenant.

    Returns:
        True if domain exists, False otherwise
    """
    result = fetchone(
        tenant_id,
        "select id from tenant_privileged_domains where domain = :domain",
        {"domain": domain},
    )
    return result is not None


def add_privileged_domain(
    tenant_id: TenantArg, domain: str, created_by: str, tenant_id_value: str
) -> int:
    """
    Add a privileged domain for a tenant.

    Args:
        tenant_id: Tenant ID for scoping
        domain: Domain name to add
        created_by: User ID of the person adding the domain
        tenant_id_value: The actual tenant ID value to store in the record

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        insert into tenant_privileged_domains (tenant_id, domain, created_by)
        values (:tenant_id, :domain, :created_by)
        """,
        {"tenant_id": tenant_id_value, "domain": domain, "created_by": created_by},
    )


def delete_privileged_domain(tenant_id: TenantArg, domain_id: str) -> int:
    """
    Delete a privileged domain.

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "delete from tenant_privileged_domains where id = :domain_id",
        {"domain_id": domain_id},
    )
