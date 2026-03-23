"""Tenant database operations."""

from ._core import UNSCOPED, TenantArg, execute, fetchone


def get_tenant_by_subdomain(subdomain: str) -> dict | None:
    """
    Get a tenant by subdomain.

    This query is always unscoped since we're looking up the tenant itself.

    Returns:
        Dict with id field, or None if not found
    """
    return fetchone(
        UNSCOPED,
        "select id from tenants where subdomain = :subdomain",
        {"subdomain": subdomain},
    )


def get_tenant_by_id(tenant_id: TenantArg) -> dict | None:
    """
    Get a tenant by ID.

    Returns:
        Dict with tenant details, or None if not found
    """
    return fetchone(
        tenant_id,
        "select id, subdomain, name from tenants where id = :tenant_id",
        {"tenant_id": tenant_id},
    )


def update_tenant_name(tenant_id: str, name: str) -> int:
    """
    Update a tenant's display name.

    Returns:
        Number of rows affected.
    """
    return execute(
        UNSCOPED,
        "UPDATE tenants SET name = :name WHERE id = :tenant_id",
        {"tenant_id": tenant_id, "name": name},
    )
