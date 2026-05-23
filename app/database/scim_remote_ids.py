"""WeftID UUID -> SP-assigned SCIM `id` mappings.

WeftID's UUID is the *externalId* in every SCIM payload. After a successful
POST, the receiver returns its own server-minted `id` -- the canonical
reference for every subsequent PUT / PATCH / DELETE against that resource,
and for `members[].value` / `$ref` when the receiver does not conflate `id`
with `externalId`.

This module is the persistence primitive. The worker reads it before each
push to decide POST-vs-PUT and to resolve member references; on a successful
POST it upserts the mapping; on a 404 against a known mapping it deletes
the row so the next attempt re-POSTs.

Rows are tenant-scoped (RLS). Per-row scope is `(sp_id, resource_type,
weftid_id)`; the UNIQUE constraint upholds that. There is no enforced
relation from `weftid_id` to `users.id` / `groups.id` because the worker
sometimes runs after a resource is hard-deleted (the queue row carries the
last-known id); the FK on `sp_id` cascades on SP deletion so mappings for
removed SPs do not stay around.
"""

from typing import Any

from ._core import TenantArg, execute, fetchall, fetchone


def get_one(
    tenant_id: TenantArg,
    sp_id: str,
    resource_type: str,
    weftid_id: str,
) -> dict | None:
    """Return the mapping row for one (sp, resource_type, weftid_id) tuple.

    Returns None when no mapping has been recorded yet (the resource has
    never been successfully POSTed to this SP, or the mapping was
    invalidated by a 404).
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, sp_id, resource_type, weftid_id, remote_id,
               created_at, updated_at
        from sp_scim_remote_ids
        where sp_id = :sp_id
          and resource_type = :resource_type
          and weftid_id = :weftid_id
        """,
        {
            "sp_id": sp_id,
            "resource_type": resource_type,
            "weftid_id": weftid_id,
        },
    )


def get_for_users(
    tenant_id: TenantArg,
    sp_id: str,
    weftid_ids: list[str],
) -> dict[str, str]:
    """Batch-fetch user mappings for a Group payload build.

    Returns a `{weftid_id: remote_id}` dict; missing keys mean "no mapping
    recorded" -- the caller decides whether to skip the member or fall
    back to the WeftID UUID. An empty input list returns an empty dict
    without round-tripping the database.
    """
    if not weftid_ids:
        return {}

    params: dict[str, Any] = {"sp_id": sp_id}
    placeholders: list[str] = []
    for i, wid in enumerate(weftid_ids):
        placeholder = f"wid_{i}"
        placeholders.append(f":{placeholder}")
        params[placeholder] = wid

    rows = fetchall(
        tenant_id,
        f"""
        select weftid_id, remote_id
        from sp_scim_remote_ids
        where sp_id = :sp_id
          and resource_type = 'user'
          and weftid_id in ({", ".join(placeholders)})
        """,
        params,
    )
    return {str(row["weftid_id"]): str(row["remote_id"]) for row in rows}


def upsert(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sp_id: str,
    resource_type: str,
    weftid_id: str,
    remote_id: str,
) -> tuple[dict, bool]:
    """Upsert a mapping. Returns (row, was_inserted).

    `was_inserted=True` when this is the first time we have recorded a
    mapping for the (sp, resource_type, weftid_id) tuple. The caller uses
    this to decide whether to emit the `scim_remote_id_mapped` audit
    event -- only on the first map, so resync churn does not spam the log.
    """
    result = fetchone(
        tenant_id,
        """
        insert into sp_scim_remote_ids (
            tenant_id, sp_id, resource_type, weftid_id, remote_id
        ) values (
            :tenant_id, :sp_id, :resource_type, :weftid_id, :remote_id
        )
        on conflict (sp_id, resource_type, weftid_id) do update set
            remote_id = excluded.remote_id,
            updated_at = now()
        returning id, tenant_id, sp_id, resource_type, weftid_id, remote_id,
                  created_at, updated_at,
                  (xmax = 0) as was_inserted
        """,
        {
            "tenant_id": tenant_id_value,
            "sp_id": sp_id,
            "resource_type": resource_type,
            "weftid_id": weftid_id,
            "remote_id": remote_id,
        },
    )
    assert result is not None
    was_inserted = bool(result.pop("was_inserted"))
    return result, was_inserted


def delete(
    tenant_id: TenantArg,
    sp_id: str,
    resource_type: str,
    weftid_id: str,
) -> int:
    """Invalidate a mapping. Called after a 404 against a known mapping.

    Returns the number of rows deleted (0 if no mapping was recorded;
    1 in the normal case).
    """
    return execute(
        tenant_id,
        """
        delete from sp_scim_remote_ids
        where sp_id = :sp_id
          and resource_type = :resource_type
          and weftid_id = :weftid_id
        """,
        {
            "sp_id": sp_id,
            "resource_type": resource_type,
            "weftid_id": weftid_id,
        },
    )
