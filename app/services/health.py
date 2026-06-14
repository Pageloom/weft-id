"""Health check service."""

import database
import database.tenants


def check_db_connectivity() -> None:
    """Verify that the database is reachable. Raises on failure."""
    database.fetchone(database.UNSCOPED, "SELECT 1")


def check_subdomain_exists(subdomain: str) -> bool:
    """Check whether a tenant with the given subdomain exists."""
    return database.tenants.get_tenant_by_subdomain(subdomain) is not None


def is_admittable_portal_host(host: str) -> bool:
    """Check whether *host* is a verified protected-domain portal host.

    Used by the Caddy on-demand-TLS ask endpoint to admit cert issuance for a
    forward-auth portal host (e.g. auth.acme-corp.com). Fails closed: only hosts
    that map to a verified, enabled protected domain are admitted.
    """
    from services import protected_domains as protected_domains_service

    return protected_domains_service.is_verified_portal_host(host)
