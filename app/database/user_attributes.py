"""Database layer for user_attributes.

Stores the canonical user attribute set: one row per (user, attribute_key).
Values are text-serialized via ``app/constants/user_attributes.py``.

This table holds whatever the user/admin set, plus values mirrored in by
the IdP login flow when the tenant has ``mirror_from_idp=true`` for that
attribute. There is no per-row source enum; the read-only IdP-mirror
audit copy lives in ``user_idp_attributes``.
"""

from __future__ import annotations

from ._core import TenantArg, execute, fetchall, fetchone


def list_attributes(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """List all attribute rows for one user, in attribute_key order."""
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, user_id, attribute_key, value, updated_at
        from user_attributes
        where user_id = :user_id
        order by attribute_key
        """,
        {"user_id": user_id},
    )


def get_attribute(tenant_id: TenantArg, user_id: str, attribute_key: str) -> dict | None:
    """Return one attribute row or ``None`` if missing."""
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, user_id, attribute_key, value, updated_at
        from user_attributes
        where user_id = :user_id and attribute_key = :attribute_key
        """,
        {"user_id": user_id, "attribute_key": attribute_key},
    )


def upsert_attribute(
    tenant_id: TenantArg,
    tenant_id_value: str,
    user_id: str,
    attribute_key: str,
    value: str,
) -> dict:
    """Insert or update one attribute row.

    Authorization (e.g. lock checks) is the service layer's job; this
    function only writes whatever it is given.

    Returns:
        The full upserted row.
    """
    result = fetchone(
        tenant_id,
        """
        insert into user_attributes (
            tenant_id, user_id, attribute_key, value
        ) values (
            :tenant_id, :user_id, :attribute_key, :value
        )
        on conflict (user_id, attribute_key) do update set
            value = excluded.value,
            updated_at = now()
        returning id, tenant_id, user_id, attribute_key, value, updated_at
        """,
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "attribute_key": attribute_key,
            "value": value,
        },
    )
    assert result is not None  # INSERT ... RETURNING always yields a row
    return result


def delete_attribute(tenant_id: TenantArg, user_id: str, attribute_key: str) -> int:
    """Delete one attribute row. Returns affected row count (0 or 1)."""
    return execute(
        tenant_id,
        """
        delete from user_attributes
        where user_id = :user_id and attribute_key = :attribute_key
        """,
        {"user_id": user_id, "attribute_key": attribute_key},
    )
