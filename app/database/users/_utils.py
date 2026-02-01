"""User database utility functions."""

from database._core import TenantArg, fetchone


def check_collation_exists(tenant_id: TenantArg, collation: str) -> bool:
    """
    Check if a collation exists in the database.

    Args:
        tenant_id: Tenant ID (or UNSCOPED for system-wide check)
        collation: Collation name (e.g., "sv-SE-x-icu")

    Returns:
        True if collation exists, False otherwise
    """
    result = fetchone(
        tenant_id,
        "select 1 from pg_collation where collname = :collation",
        {"collation": collation},
    )
    return result is not None
