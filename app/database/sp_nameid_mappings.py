"""Per-SP persistent NameID mapping database operations."""

import uuid

from database._core import TenantArg, fetchone


def get_nameid_mapping(tenant_id: TenantArg, user_id: str, sp_id: str) -> dict | None:
    """Get existing persistent NameID mapping for a user-SP pair.

    Returns:
        Mapping dict or None if not found
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, user_id, sp_id, nameid_value, created_at
        from sp_nameid_mappings
        where user_id = :user_id and sp_id = :sp_id
        """,
        {"user_id": user_id, "sp_id": sp_id},
    )


def get_or_create_nameid_mapping(
    tenant_id: TenantArg,
    tenant_id_value: str,
    user_id: str,
    sp_id: str,
) -> dict:
    """Get or create a persistent NameID mapping for a user-SP pair.

    Uses INSERT ... ON CONFLICT DO NOTHING followed by a SELECT for race safety.

    Returns:
        Mapping dict (always succeeds)
    """
    nameid_value = str(uuid.uuid4())

    # Try to insert; silently skip on conflict (another request won the race)
    fetchone(
        tenant_id,
        """
        insert into sp_nameid_mappings (tenant_id, user_id, sp_id, nameid_value)
        values (:tenant_id, :user_id, :sp_id, :nameid_value)
        on conflict (tenant_id, user_id, sp_id) do nothing
        returning id
        """,
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "sp_id": sp_id,
            "nameid_value": nameid_value,
        },
    )

    # Always read back (either the row we just inserted or the pre-existing one)
    row = get_nameid_mapping(tenant_id, user_id, sp_id)
    assert row is not None, "NameID mapping should exist after insert-or-conflict"
    return row
