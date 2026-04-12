"""Health check service."""

import database
import database.tenants


def check_db_connectivity() -> None:
    """Verify that the database is reachable. Raises on failure."""
    database.fetchone(database.UNSCOPED, "SELECT 1")


def check_subdomain_exists(subdomain: str) -> bool:
    """Check whether a tenant with the given subdomain exists."""
    return database.tenants.get_tenant_by_subdomain(subdomain) is not None
