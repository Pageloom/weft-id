"""Database layer for tenant_attribute_config.

Per-tenant per-attribute toggles: ``enabled``, ``required``, and
``send_to_sps_default``. Rows are seeded for every attribute in the registry
when the tenant is created (see migration 0033). The service layer is the
single writer.
"""

from __future__ import annotations

from ._core import TenantArg, execute, fetchall, fetchone


def list_config(tenant_id: TenantArg) -> list[dict]:
    """Return all attribute config rows for one tenant.

    Order is by category (in registry-friendly order) then attribute_key, so
    grouping the result in Python yields stable category ordering.
    """
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, attribute_key, category, enabled, required,
               send_to_sps_default, updated_at
        from tenant_attribute_config
        order by
            case category
                when 'contact' then 1
                when 'professional' then 2
                when 'location' then 3
                when 'profile' then 4
                else 99
            end,
            attribute_key
        """,
    )


def get_config(tenant_id: TenantArg, attribute_key: str) -> dict | None:
    """Return one attribute config row or ``None`` if missing."""
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, attribute_key, category, enabled, required,
               send_to_sps_default, updated_at
        from tenant_attribute_config
        where attribute_key = :attribute_key
        """,
        {"attribute_key": attribute_key},
    )


def update_config(
    tenant_id: TenantArg,
    attribute_key: str,
    enabled: bool,
    required: bool,
    send_to_sps_default: bool,
) -> int:
    """Update one attribute config row. Returns affected row count (0 or 1).

    The seeded row is guaranteed to exist by migration 0033, but new tenants
    created via direct INSERT (e.g. tests) may skip the seed -- callers
    should treat 0 as "config row missing, use defaults".
    """
    return execute(
        tenant_id,
        """
        update tenant_attribute_config
        set enabled = :enabled,
            required = :required,
            send_to_sps_default = :send_to_sps_default,
            updated_at = now()
        where attribute_key = :attribute_key
        """,
        {
            "attribute_key": attribute_key,
            "enabled": enabled,
            "required": required,
            "send_to_sps_default": send_to_sps_default,
        },
    )
