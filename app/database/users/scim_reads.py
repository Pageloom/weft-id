"""User listing / lookup helpers for the inbound SCIM read endpoints.

The inbound SCIM endpoint family at `/scim/v2/inbound/{idp_id}/Users`
projects WeftID users that are JIT-provisioned (or future SCIM-
provisioned) under a specific SAML IdP connection. These functions
return only the columns SCIM cares about, scoped to one IdP, with
SCIM-style 1-indexed pagination and a fixed sort that gives stable
paging (`created_at`, `id` as tiebreaker).

Tokens authenticate against an IdP connection; the resulting endpoint
must NEVER leak users that belong to a different IdP (or to no IdP at
all). That filter is the joint responsibility of these queries and the
service-layer caller.
"""

from __future__ import annotations

from database._core import TenantArg, fetchall, fetchone

# Columns we project for SCIM responses. Kept in one place so the
# list/get pair stay in lockstep -- a column added here must appear in
# the SCIM payload builder, and vice versa.
_SCIM_USER_COLS = """
    u.id,
    u.first_name,
    u.last_name,
    u.is_inactivated,
    u.is_anonymized,
    u.created_at,
    u.saml_idp_id,
    ue.email
"""


def count_users_for_idp(
    tenant_id: TenantArg,
    idp_id: str,
    *,
    user_name: str | None = None,
    external_id: str | None = None,
) -> int:
    """Count users matching the SCIM filter for one IdP.

    Filter precedence: if both `user_name` and `external_id` are
    provided, both are applied (AND). SCIM filters are typically a
    single `eq` predicate so this rarely matters in practice, but the
    AND is safer than an implicit OR.

    `external_id`: iteration 2 has no upstream-external-id column on
    `users` yet (that's iteration 3's user_idp_attributes / NameID
    mapping path). For now, an externalId filter is honoured as a
    literal match against `users.id` -- this gives SCIM clients a way
    to look up the resource by the id WeftID minted.
    """
    where = ["u.saml_idp_id = :idp_id"]
    params: dict = {"idp_id": idp_id}

    if user_name is not None:
        where.append("ue.email = :user_name")
        params["user_name"] = user_name
    if external_id is not None:
        # psycopg interprets `::text` as a named parameter, so cast
        # via cast() instead. We compare the textual representation
        # because the externalId filter value is a free-form string
        # (iteration 3 stores upstream-assigned ids that may not
        # parse as UUIDs).
        where.append("cast(u.id as text) = :external_id")
        params["external_id"] = external_id

    row = fetchone(
        tenant_id,
        f"""
        select count(distinct u.id) as count
        from users u
        left join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where {" and ".join(where)}
        """,
        params,
    )
    return int(row["count"]) if row else 0


def list_users_for_idp(
    tenant_id: TenantArg,
    idp_id: str,
    *,
    user_name: str | None = None,
    external_id: str | None = None,
    start_index: int = 1,
    count: int = 100,
) -> list[dict]:
    """List users for one IdP in SCIM shape.

    Returns the page of users matching the filter. `start_index` is
    1-indexed per SCIM 2.0 (RFC 7644 §3.4.2); we convert it to a
    0-indexed SQL OFFSET internally.

    `count` is capped at the limits the metadata advertises. We don't
    enforce that cap here -- the router does -- so this function will
    happily return any positive integer.
    """
    where = ["u.saml_idp_id = :idp_id"]
    params: dict = {"idp_id": idp_id}

    if user_name is not None:
        where.append("ue.email = :user_name")
        params["user_name"] = user_name
    if external_id is not None:
        # psycopg interprets `::text` as a named parameter, so cast
        # via cast() instead. We compare the textual representation
        # because the externalId filter value is a free-form string
        # (iteration 3 stores upstream-assigned ids that may not
        # parse as UUIDs).
        where.append("cast(u.id as text) = :external_id")
        params["external_id"] = external_id

    offset = max(start_index - 1, 0)
    params["limit"] = count
    params["offset"] = offset

    return fetchall(
        tenant_id,
        f"""
        select {_SCIM_USER_COLS}
        from users u
        left join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where {" and ".join(where)}
        order by u.created_at asc, u.id asc
        limit :limit offset :offset
        """,
        params,
    )


def get_user_for_idp(
    tenant_id: TenantArg,
    idp_id: str,
    user_id: str,
) -> dict | None:
    """Fetch a single user belonging to `idp_id` (or None if not bound).

    Returns None for any user whose `saml_idp_id` doesn't match the
    caller's IdP, even if the user exists in the tenant. SCIM clients
    authenticated against IdP A must not be able to see users created
    via IdP B.
    """
    return fetchone(
        tenant_id,
        f"""
        select {_SCIM_USER_COLS}
        from users u
        left join user_emails ue on ue.user_id = u.id and ue.is_primary = true
        where u.id = :user_id and u.saml_idp_id = :idp_id
        """,
        {"user_id": user_id, "idp_id": idp_id},
    )
