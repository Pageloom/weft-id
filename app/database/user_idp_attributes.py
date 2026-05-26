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


# ---------------------------------------------------------------------------
# Upstream-id storage
#
# Inbound SCIM clients send their own `externalId` (Okta's user id, Entra's
# objectId, etc). We store it in `user_idp_attributes` under a synthetic
# attribute key prefixed with `__` (illegal in the standard registry) so it
# travels with the rest of the IdP-mirror snapshot but doesn't accidentally
# get serialized as a canonical attribute. Read paths (SCIM /Users
# externalId filter, payload externalId emission) look it up via the
# helpers below.
# ---------------------------------------------------------------------------

# Reserved attribute_key used to store the upstream-assigned externalId.
EXTERNAL_ID_KEY = "__external_id"


def set_external_id(
    tenant_id: TenantArg,
    tenant_id_value: str,
    user_id: str,
    idp_id: str,
    external_id: str,
) -> None:
    """Upsert the upstream-assigned externalId for one (user, idp_id).

    Stored in `user_idp_attributes` so the row CASCADEs on user/IdP delete
    without bespoke cleanup. The standard attribute mirror path
    (`apply_idp_attributes`) filters out non-standard keys, so this row
    never leaks into the canonical `user_attributes` table.
    """
    execute(
        tenant_id,
        """
        insert into user_idp_attributes (
            tenant_id, user_id, idp_id, attribute_key, value
        ) values (
            :tenant_id, :user_id, :idp_id, :attribute_key, :value
        )
        on conflict (user_id, idp_id, attribute_key) do update set
            value = excluded.value,
            updated_at = now()
        """,
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "idp_id": idp_id,
            "attribute_key": EXTERNAL_ID_KEY,
            "value": external_id,
        },
    )


def get_external_id(
    tenant_id: TenantArg,
    user_id: str,
    idp_id: str,
) -> str | None:
    """Return the upstream externalId stored for one (user, idp_id), or None."""
    from ._core import fetchone

    row = fetchone(
        tenant_id,
        """
        select value
        from user_idp_attributes
        where user_id = :user_id
          and idp_id = :idp_id
          and attribute_key = :attribute_key
        """,
        {
            "user_id": user_id,
            "idp_id": idp_id,
            "attribute_key": EXTERNAL_ID_KEY,
        },
    )
    return row["value"] if row else None


def get_user_id_by_external_id(
    tenant_id: TenantArg,
    idp_id: str,
    external_id: str,
) -> str | None:
    """Reverse lookup: find the WeftID user bound to an upstream externalId.

    Used by SCIM POST merge to detect an existing user matched on
    externalId before falling back to canonical email.
    """
    from ._core import fetchone

    row = fetchone(
        tenant_id,
        """
        select user_id
        from user_idp_attributes
        where idp_id = :idp_id
          and attribute_key = :attribute_key
          and value = :external_id
        limit 1
        """,
        {
            "idp_id": idp_id,
            "attribute_key": EXTERNAL_ID_KEY,
            "external_id": external_id,
        },
    )
    return str(row["user_id"]) if row else None


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
