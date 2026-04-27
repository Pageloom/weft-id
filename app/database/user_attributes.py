"""Database layer for user_attributes.

Stores one row per (user, attribute_key). Values are text-serialized via
``app/constants/user_attributes.py``. Source tracking distinguishes IdP-set
values (read-only to admins/users) from admin- and self-set values.
"""

from __future__ import annotations

from ._core import TenantArg, execute, fetchall, fetchone


def list_attributes(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """List all attribute rows for one user, in attribute_key order."""
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, user_id, attribute_key, value, source,
               source_idp_id, updated_at
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
        select id, tenant_id, user_id, attribute_key, value, source,
               source_idp_id, updated_at
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
    source: str,
    source_idp_id: str | None,
) -> dict:
    """Insert or update one attribute row.

    Args:
        source: ``'idp'`` | ``'admin'`` | ``'self'``. Caller must enforce
            authorization rules; this function only writes whatever it is
            given (subject to the DB CHECK that ``source = 'idp'`` requires
            a non-null ``source_idp_id`` and other sources require null).

    Returns:
        The full upserted row.
    """
    result = fetchone(
        tenant_id,
        """
        insert into user_attributes (
            tenant_id, user_id, attribute_key, value, source, source_idp_id
        ) values (
            :tenant_id, :user_id, :attribute_key, :value, :source, :source_idp_id
        )
        on conflict (user_id, attribute_key) do update set
            value = excluded.value,
            source = excluded.source,
            source_idp_id = excluded.source_idp_id,
            updated_at = now()
        returning id, tenant_id, user_id, attribute_key, value, source,
                  source_idp_id, updated_at
        """,
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "attribute_key": attribute_key,
            "value": value,
            "source": source,
            "source_idp_id": source_idp_id,
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
