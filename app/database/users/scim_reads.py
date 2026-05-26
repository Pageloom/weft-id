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
    u.updated_at,
    u.saml_idp_id,
    ue.email,
    uia.value as external_id
"""

# JOIN snippet that pulls the upstream-assigned externalId (stored under the
# reserved `__external_id` attribute_key in user_idp_attributes) into the
# SCIM user projection. LEFT JOIN because not every user has one yet (SAML-
# JIT-only users have no SCIM externalId stored).
_SCIM_USER_JOINS = """
    left join user_emails ue on ue.user_id = u.id and ue.is_primary = true
    left join user_idp_attributes uia
        on uia.user_id = u.id
        and uia.idp_id = u.saml_idp_id
        and uia.attribute_key = '__external_id'
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

    `external_id`: prefers the upstream-assigned externalId stored in
    `user_idp_attributes` under the reserved `__external_id` key. Falls
    back to a literal match against `users.id` so SCIM clients that
    never sent their own externalId can still look up the resource by
    WeftID's minted id.
    """
    where = ["u.saml_idp_id = :idp_id"]
    params: dict = {"idp_id": idp_id}

    if user_name is not None:
        where.append("ue.email = :user_name")
        params["user_name"] = user_name
    if external_id is not None:
        # Prefer upstream externalId (uia.value), fall back to the
        # WeftID-minted id. cast() avoids psycopg's `:text` ambiguity.
        where.append("(uia.value = :external_id or cast(u.id as text) = :external_id)")
        params["external_id"] = external_id

    row = fetchone(
        tenant_id,
        f"""
        select count(distinct u.id) as count
        from users u
        {_SCIM_USER_JOINS}
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
        # Prefer upstream externalId (uia.value), fall back to the
        # WeftID-minted id (see count_users_for_idp).
        where.append("(uia.value = :external_id or cast(u.id as text) = :external_id)")
        params["external_id"] = external_id

    offset = max(start_index - 1, 0)
    params["limit"] = count
    params["offset"] = offset

    return fetchall(
        tenant_id,
        f"""
        select {_SCIM_USER_COLS}
        from users u
        {_SCIM_USER_JOINS}
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
        {_SCIM_USER_JOINS}
        where u.id = :user_id and u.saml_idp_id = :idp_id
        """,
        {"user_id": user_id, "idp_id": idp_id},
    )
