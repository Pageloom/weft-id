"""Database layer for user_attributes.

Stores the canonical user attribute set: one row per (user, attribute_key).
Values are text-serialized via ``app/constants/user_attributes.py``.

This table holds whatever the user/admin set, plus values mirrored in by
the IdP login flow when the tenant has ``mirror_from_idp=true`` for that
attribute. Each row carries a ``source`` enum ('idp' | 'admin' | 'self')
recording who last set the value; the assertion builder reads it to decide
whether a value may cross into a signed assertion. The read-only IdP-mirror
audit copy lives in ``user_idp_attributes``.
"""

from __future__ import annotations

from ._core import TenantArg, execute, fetchall, fetchone


def list_attributes(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """List all attribute rows for one user, in attribute_key order."""
    return fetchall(
        tenant_id,
        """
        select id, tenant_id, user_id, attribute_key, value, source, updated_at
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
        select id, tenant_id, user_id, attribute_key, value, source, updated_at
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
    source: str = "admin",
) -> dict:
    """Insert or update one attribute row.

    Authorization (e.g. lock checks) is the service layer's job; this
    function only writes whatever it is given. ``source`` records the
    provenance of this value ('idp' | 'admin' | 'self') and is overwritten
    on every upsert so the row always reflects who last set it. It defaults
    to 'admin' (the trusted, always-emitted provenance) for callers that
    don't track it; the sole production caller (``set_user_attribute``)
    always passes it explicitly, so the default only ever applies in tests.

    Returns:
        The full upserted row.
    """
    result = fetchone(
        tenant_id,
        """
        insert into user_attributes (
            tenant_id, user_id, attribute_key, value, source
        ) values (
            :tenant_id, :user_id, :attribute_key, :value, :source
        )
        on conflict (user_id, attribute_key) do update set
            value = excluded.value,
            source = excluded.source,
            updated_at = now()
        returning id, tenant_id, user_id, attribute_key, value, source, updated_at
        """,
        {
            "tenant_id": tenant_id_value,
            "user_id": user_id,
            "attribute_key": attribute_key,
            "value": value,
            "source": source,
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


def list_missing_required_for_tenant(tenant_id: TenantArg) -> list[dict]:
    """Return rows for every (user, required_attribute) pair with no value.

    Iterates the tenant's enabled+required ``tenant_attribute_config`` rows
    cross-joined with active users, then filters to pairs where the user
    has no row (or a NULL/empty value) in ``user_attributes``. Used by the
    admin Todo view to surface incomplete profiles without firing N+1
    queries.

    Returns a list of dicts with:
        - user_id (str)
        - first_name (str)
        - last_name (str)
        - email (str | None)
        - attribute_key (str)
        - locked_for_users (bool)

    Inactivated and anonymized users are excluded. Service users (linked
    to OAuth2 clients) are excluded.
    """
    return fetchall(
        tenant_id,
        """
        select u.id as user_id,
               u.first_name,
               u.last_name,
               ue.email,
               c.attribute_key,
               c.locked_for_users
          from tenant_attribute_config c
          cross join users u
          left join user_attributes ua
                 on ua.user_id = u.id
                and ua.attribute_key = c.attribute_key
          left join user_emails ue
                 on ue.user_id = u.id
                and ue.is_primary = true
         where c.enabled = true
           and c.required = true
           and u.is_inactivated = false
           and u.is_anonymized = false
           and not exists (
               select 1 from oauth2_clients oc
                where oc.service_user_id = u.id
           )
           and (ua.value is null or btrim(ua.value) = '')
         order by u.last_name, u.first_name, c.attribute_key
        """,
        {},
    )
