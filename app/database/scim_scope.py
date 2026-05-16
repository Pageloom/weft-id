"""SCIM-scope resolution queries.

Cross-table reads that resolve "which SCIM-enabled SPs grant access to this
user" and "which users have access to this SP via this group". The closure
table (`group_lineage`) makes the recursive group hierarchy cheap to
traverse: every ancestor-descendant pair is materialised, so each query
here is a straight indexed join.

All callers are in `services.scim.dispatch`. Each function answers exactly
one dispatch-trigger question, so the dispatch layer stays free of SQL.
"""

from __future__ import annotations

from ._core import TenantArg, fetchall


def scim_sps_granting_user(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """SCIM-enabled SPs that this user has access to.

    A user has access to an SP when ANY of:
    - The SP is flagged `available_to_all=true` (tenant-wide grant), OR
    - The SP grants access to a group G, the user is a direct member of a
      group M, and G is an ancestor-or-self of M (via `group_lineage`).

    Returns one row per SP, with `id` and `scim_membership_mode`.

    `available_to_all` SPs are included so SCIM push covers tenant-wide
    apps (Slack, Notion, company wiki) that admins reasonably expect to
    receive deprovisioning when a user leaves WeftID. Group-grant SPs are
    included via the closure-table join as before.
    """
    return fetchall(
        tenant_id,
        """
        select distinct sp.id, sp.scim_membership_mode
        from service_providers sp
        left join sp_group_assignments sga on sga.sp_id = sp.id
        left join group_lineage gl on gl.ancestor_id = sga.group_id
        left join group_memberships gm
               on gm.group_id = gl.descendant_id
              and gm.user_id = :user_id
        where sp.scim_enabled = true
          and (sp.available_to_all = true or gm.user_id is not null)
        """,
        {"user_id": user_id},
    )


def scim_sps_granting_via_group(tenant_id: TenantArg, group_id: str) -> list[dict]:
    """SCIM-enabled SPs that grant access via this group or any ancestor.

    Used by membership-change dispatch: when a user is added to or removed
    from group G, every SP whose grant-group is G or an ancestor of G
    needs the user's resource re-pushed.

    Returns one row per SP, with `id` and `scim_membership_mode`.
    """
    return fetchall(
        tenant_id,
        """
        select distinct sp.id, sp.scim_membership_mode
        from service_providers sp
        join sp_group_assignments sga on sga.sp_id = sp.id
        join group_lineage gl on gl.ancestor_id = sga.group_id
        where sp.scim_enabled = true
          and gl.descendant_id = :group_id
        """,
        {"group_id": group_id},
    )


def transitive_user_ids_for_group(tenant_id: TenantArg, group_id: str) -> list[str]:
    """All user ids that are members of this group or any descendant.

    Used by grant-fan-out dispatch: when an SP gains a new group grant,
    every effective member of that group (direct + via descendants) must
    be enqueued.
    """
    rows = fetchall(
        tenant_id,
        """
        select distinct gm.user_id
        from group_memberships gm
        join group_lineage gl on gl.descendant_id = gm.group_id
        where gl.ancestor_id = :group_id
        """,
        {"group_id": group_id},
    )
    return [str(row["user_id"]) for row in rows]


def is_scim_enabled_sp(tenant_id: TenantArg, sp_id: str) -> bool:
    """Return True if the SP exists and has SCIM enabled.

    Used to early-exit fan-out triggers when the SP is not provisioned for
    SCIM (no queue rows to write).
    """
    rows = fetchall(
        tenant_id,
        """
        select 1 as ok
        from service_providers
        where id = :sp_id and scim_enabled = true
        limit 1
        """,
        {"sp_id": sp_id},
    )
    return bool(rows)
