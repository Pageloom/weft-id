"""SP-to-Group assignment database operations.

Controls which groups (and by extension, users) have access to downstream
service providers. Leverages the group_lineage closure table for hierarchical
access checks.
"""

from database._core import TenantArg, execute, fetchall, fetchone


def list_assignments_for_sp(tenant_id: TenantArg, sp_id: str) -> list[dict]:
    """List group assignments for a service provider.

    Returns:
        List of assignment dicts joined with group info, ordered by group name.
    """
    return fetchall(
        tenant_id,
        """
        select sga.id, sga.sp_id, sga.group_id, sga.assigned_by, sga.assigned_at,
               g.name as group_name, g.description as group_description,
               g.group_type
        from sp_group_assignments sga
        join groups g on g.id = sga.group_id
        where sga.sp_id = :sp_id
        order by g.name
        """,
        {"sp_id": sp_id},
    )


def list_assignments_for_group(tenant_id: TenantArg, group_id: str) -> list[dict]:
    """List SP assignments for a group.

    Returns:
        List of assignment dicts joined with SP info, ordered by SP name.
    """
    return fetchall(
        tenant_id,
        """
        select sga.id, sga.sp_id, sga.group_id, sga.assigned_by, sga.assigned_at,
               sp.name as sp_name, sp.entity_id as sp_entity_id,
               sp.description as sp_description
        from sp_group_assignments sga
        join service_providers sp on sp.id = sga.sp_id
        where sga.group_id = :group_id
        order by sp.name
        """,
        {"group_id": group_id},
    )


def create_assignment(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sp_id: str,
    group_id: str,
    assigned_by: str,
) -> dict | None:
    """Create a single SP-group assignment.

    Returns:
        Created assignment dict, or None on failure.
    """
    return fetchone(
        tenant_id,
        """
        insert into sp_group_assignments (tenant_id, sp_id, group_id, assigned_by)
        values (:tenant_id, :sp_id, :group_id, :assigned_by)
        returning id, tenant_id, sp_id, group_id, assigned_by, assigned_at
        """,
        {
            "tenant_id": tenant_id_value,
            "sp_id": sp_id,
            "group_id": group_id,
            "assigned_by": assigned_by,
        },
    )


def delete_assignment(tenant_id: TenantArg, sp_id: str, group_id: str) -> int:
    """Delete an SP-group assignment.

    Returns:
        Number of rows deleted.
    """
    return execute(
        tenant_id,
        """
        delete from sp_group_assignments
        where sp_id = :sp_id and group_id = :group_id
        """,
        {"sp_id": sp_id, "group_id": group_id},
    )


def bulk_create_assignments(
    tenant_id: TenantArg,
    tenant_id_value: str,
    sp_id: str,
    group_ids: list[str],
    assigned_by: str,
) -> int:
    """Bulk-create SP-group assignments, skipping duplicates.

    Returns:
        Number of new assignments created.
    """
    if not group_ids:
        return 0

    # Build VALUES clause for bulk insert
    values_parts = []
    params: dict = {"tenant_id": tenant_id_value, "sp_id": sp_id, "assigned_by": assigned_by}
    for i, gid in enumerate(group_ids):
        param_name = f"gid_{i}"
        values_parts.append(f"(:tenant_id, :sp_id, :{param_name}, :assigned_by)")
        params[param_name] = gid

    values_clause = ", ".join(values_parts)

    return execute(
        tenant_id,
        f"""
        insert into sp_group_assignments (tenant_id, sp_id, group_id, assigned_by)
        values {values_clause}
        on conflict (sp_id, group_id) do nothing
        """,
        params,
    )


def user_can_access_sp(tenant_id: TenantArg, user_id: str, sp_id: str) -> bool:
    """Check if a user can access a service provider via group assignments.

    Uses the group_lineage closure table: a user has access if they belong to
    any group that is a descendant of (or equal to) an assigned group.

    Returns:
        True if user has access, False otherwise.
    """
    row = fetchone(
        tenant_id,
        """
        select exists (
            select 1 from service_providers
            where id = :sp_id and available_to_all = true
        ) or exists (
            select 1
            from group_memberships gm
            join group_lineage gl on gl.descendant_id = gm.group_id
            join sp_group_assignments sga on sga.group_id = gl.ancestor_id
            where gm.user_id = :user_id and sga.sp_id = :sp_id
        ) as has_access
        """,
        {"user_id": user_id, "sp_id": sp_id},
    )
    return bool(row and row["has_access"])


def get_accessible_sps_for_user(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """Get all service providers a user can access via group assignments.

    Returns:
        List of SP dicts the user can access, ordered by name.
    """
    return fetchall(
        tenant_id,
        """
        select distinct sp.id, sp.name, sp.description, sp.entity_id
        from service_providers sp
        join sp_group_assignments sga on sga.sp_id = sp.id
        join group_lineage gl on gl.ancestor_id = sga.group_id
        join group_memberships gm on gm.group_id = gl.descendant_id
        where gm.user_id = :user_id
          and sp.enabled = true
          and sp.trust_established = true
        union
        select sp.id, sp.name, sp.description, sp.entity_id
        from service_providers sp
        where sp.available_to_all = true
          and sp.enabled = true
          and sp.trust_established = true
        order by name
        """,
        {"user_id": user_id},
    )


def get_accessible_sps_with_attribution(tenant_id: TenantArg, user_id: str) -> list[dict]:
    """Get accessible SPs for a user with granting group attribution.

    Returns one row per SP-group pair for group-based access, plus one row
    per available_to_all SP. Caller should aggregate by SP id.

    Returns:
        List of dicts with sp id/name/description/entity_id,
        available_to_all flag, and granting_group_id/name.
    """
    return fetchall(
        tenant_id,
        """
        select sp.id, sp.name, sp.description, sp.entity_id,
               false as available_to_all,
               g.id as granting_group_id, g.name as granting_group_name
        from service_providers sp
        join sp_group_assignments sga on sga.sp_id = sp.id
        join group_lineage gl on gl.ancestor_id = sga.group_id
        join group_memberships gm on gm.group_id = gl.descendant_id
        join groups g on g.id = sga.group_id
        where gm.user_id = :user_id
          and sp.enabled = true
          and sp.trust_established = true

        union all

        select sp.id, sp.name, sp.description, sp.entity_id,
               true as available_to_all,
               null as granting_group_id, null as granting_group_name
        from service_providers sp
        where sp.available_to_all = true
          and sp.enabled = true
          and sp.trust_established = true

        order by name, granting_group_name
        """,
        {"user_id": user_id},
    )


def count_assignments_for_sp(tenant_id: TenantArg, sp_id: str) -> int:
    """Count group assignments for a service provider.

    Returns:
        Number of group assignments.
    """
    row = fetchone(
        tenant_id,
        """
        select count(*) as cnt
        from sp_group_assignments
        where sp_id = :sp_id
        """,
        {"sp_id": sp_id},
    )
    return row["cnt"] if row else 0


def count_assignments_for_sps(tenant_id: TenantArg) -> dict[str, int]:
    """Get assignment counts for all SPs in a tenant.

    Returns:
        Dict mapping sp_id (str) to assignment count.
    """
    rows = fetchall(
        tenant_id,
        """
        select sp_id, count(*) as cnt
        from sp_group_assignments
        group by sp_id
        """,
        {},
    )
    return {str(row["sp_id"]): row["cnt"] for row in rows}
