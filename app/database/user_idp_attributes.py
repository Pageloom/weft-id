"""Database layer for user_idp_attributes.

Read-only audit/info copy of what each connected IdP last sent for each
user. One row per (user, idp_id, attribute_key). The service layer
``apply_idp_attributes`` is the only writer; admin and user edits never
touch this table.

CASCADE on user delete and IdP delete keeps it consistent without manual
cleanup.
"""

from __future__ import annotations

from ._core import TenantArg, execute, fetchall, session


def list_attributes(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """List all IdP-mirror rows for one user, ordered by idp_id then key."""
    return fetchall(
        tenant_id,
        """
        select tenant_id, user_id, idp_id, attribute_key, value, updated_at
        from user_idp_attributes
        where user_id = :user_id
        order by idp_id, attribute_key
        """,
        {"user_id": user_id},
    )


def list_attributes_for_idp(
    tenant_id: TenantArg,
    user_id: str,
    idp_id: str,
) -> list[dict]:
    """List IdP-mirror rows for one (user, idp_id), in attribute_key order."""
    return fetchall(
        tenant_id,
        """
        select tenant_id, user_id, idp_id, attribute_key, value, updated_at
        from user_idp_attributes
        where user_id = :user_id and idp_id = :idp_id
        order by attribute_key
        """,
        {"user_id": user_id, "idp_id": idp_id},
    )


def replace_idp_attributes(
    tenant_id: TenantArg,
    tenant_id_value: str,
    user_id: str,
    idp_id: str,
    attributes: dict[str, str],
) -> None:
    """Atomically replace the user's IdP-mirror snapshot for one IdP.

    Each IdP login carries the complete current attribute set. Keys absent
    from ``attributes`` are deleted from the snapshot for this IdP; keys
    present are upserted. The whole replacement runs in a single
    transaction so observers never see a partial state.
    """
    with session(tenant_id=tenant_id) as cur:
        # Delete keys no longer present (handles both shrink and re-key).
        if attributes:
            cur.execute(
                """
                delete from user_idp_attributes
                where user_id = %(user_id)s
                  and idp_id = %(idp_id)s
                  and attribute_key <> all(%(keys)s)
                """,
                {
                    "user_id": user_id,
                    "idp_id": idp_id,
                    "keys": list(attributes.keys()),
                },
            )
        else:
            cur.execute(
                """
                delete from user_idp_attributes
                where user_id = %(user_id)s and idp_id = %(idp_id)s
                """,
                {"user_id": user_id, "idp_id": idp_id},
            )

        # Upsert each (key, value) for this IdP.
        for key, value in attributes.items():
            cur.execute(
                """
                insert into user_idp_attributes (
                    tenant_id, user_id, idp_id, attribute_key, value
                ) values (
                    %(tenant_id)s, %(user_id)s, %(idp_id)s,
                    %(attribute_key)s, %(value)s
                )
                on conflict (user_id, idp_id, attribute_key) do update set
                    value = excluded.value,
                    updated_at = now()
                """,
                {
                    "tenant_id": tenant_id_value,
                    "user_id": user_id,
                    "idp_id": idp_id,
                    "attribute_key": key,
                    "value": value,
                },
            )


def delete_for_user(tenant_id: TenantArg, user_id: str) -> int:
    """Delete all IdP-mirror rows for one user. Returns row count."""
    return execute(
        tenant_id,
        """
        delete from user_idp_attributes
        where user_id = :user_id
        """,
        {"user_id": user_id},
    )
