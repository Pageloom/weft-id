"""User search and listing database operations."""

from typing import Any

from database._core import TenantArg, fetchall, fetchone


def count_users(
    tenant_id: TenantArg,
    search: str | None = None,
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
) -> int:
    """
    Count users, optionally filtered by search term, roles, and statuses.

    Args:
        tenant_id: Tenant ID
        search: Search term to filter by (searches first_name, last_name, email)
        roles: List of roles to filter by (member, admin, super_admin)
        statuses: List of statuses to filter by (active, inactivated, anonymized)

    Returns:
        Total count of matching users
    """
    where_clauses: list[str] = []
    params: dict[str, Any] = {}

    if search:
        where_clauses.append(
            "(u.first_name ilike :search or u.last_name ilike :search or ue.email ilike :search)"
        )
        params["search"] = f"%{search}%"

    if roles:
        # Filter by roles using ANY for array matching
        allowed_roles = {"member", "admin", "super_admin"}
        valid_roles = [r for r in roles if r in allowed_roles]
        if valid_roles:
            where_clauses.append("u.role = ANY(:roles)")
            params["roles"] = valid_roles

    if statuses:
        # Build status conditions based on boolean flags
        status_conditions: list[str] = []
        if "active" in statuses:
            status_conditions.append("(u.is_inactivated = false and u.is_anonymized = false)")
        if "inactivated" in statuses:
            status_conditions.append("(u.is_inactivated = true and u.is_anonymized = false)")
        if "anonymized" in statuses:
            status_conditions.append("u.is_anonymized = true")
        if status_conditions:
            where_clauses.append(f"({' or '.join(status_conditions)})")

    where_clause = ""
    if where_clauses:
        where_clause = "where " + " and ".join(where_clauses)

    query = f"""
        select count(distinct u.id) as count
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        {where_clause}
    """

    result = fetchone(tenant_id, query, params)
    return result["count"] if result else 0


def list_users(
    tenant_id: TenantArg,
    search: str | None = None,
    sort_field: str = "created_at",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 25,
    collation: str | None = None,
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
) -> list[dict]:
    """
    List users with pagination, sorting, search, and filtering.

    Args:
        tenant_id: Tenant ID
        search: Search term to filter by (searches first_name, last_name, email)
        sort_field: Field to sort by (name, email, role, status, last_login,
                   last_activity_at, created_at)
        sort_order: Sort order (asc or desc)
        page: Page number (1-indexed)
        page_size: Number of results per page
        collation: Optional collation for text sorting (e.g., "sv-SE-x-icu")
        roles: List of roles to filter by (member, admin, super_admin)
        statuses: List of statuses to filter by (active, inactivated, anonymized)

    Returns:
        List of user dicts with id, first_name, last_name, role, created_at,
        last_login, last_activity_at, is_inactivated, is_anonymized, email,
        saml_idp_id, saml_idp_name, require_platform_mfa, has_password,
        mfa_enabled, and mfa_method
    """
    # Build WHERE clause
    where_clauses: list[str] = []
    params: dict[str, Any] = {}

    if search:
        where_clauses.append(
            "(u.first_name ilike :search or u.last_name ilike :search or ue.email ilike :search)"
        )
        params["search"] = f"%{search}%"

    if roles:
        # Filter by roles using ANY for array matching
        allowed_roles = {"member", "admin", "super_admin"}
        valid_roles = [r for r in roles if r in allowed_roles]
        if valid_roles:
            where_clauses.append("u.role = ANY(:roles)")
            params["roles"] = valid_roles

    if statuses:
        # Build status conditions based on boolean flags
        status_conditions: list[str] = []
        if "active" in statuses:
            status_conditions.append("(u.is_inactivated = false and u.is_anonymized = false)")
        if "inactivated" in statuses:
            status_conditions.append("(u.is_inactivated = true and u.is_anonymized = false)")
        if "anonymized" in statuses:
            status_conditions.append("u.is_anonymized = true")
        if status_conditions:
            where_clauses.append(f"({' or '.join(status_conditions)})")

    where_clause = ""
    if where_clauses:
        where_clause = "where " + " and ".join(where_clauses)

    # SECURITY: Dynamic collation and field names in ORDER BY clause.
    #
    # Collation safety (line 301):
    # - collation parameter is validated via check_collation_exists() in router
    # - Only database-recognized collations are allowed (SQL injection impossible)
    # - Still wrapped in double quotes as defense-in-depth
    #
    # Field name safety (lines 308-316):
    # - sort_field is validated against a whitelist dictionary
    # - Only pre-defined keys are accepted: name, email, role, status, etc.
    # - Values in the dict are controlled template strings, not user input
    #
    # Sort order safety (lines 321-322):
    # - sort_order validated against literal ['asc', 'desc']
    # - Any other value defaults to 'desc'
    #
    # DO NOT add new sort fields without adding to the whitelist.
    # DO NOT use user input directly in ORDER BY.

    # Build ORDER BY clause
    collate_clause = f' COLLATE "{collation}"' if collation else ""
    # Status sort: Active=1, Inactivated=2, Anonymized=3
    status_case = """CASE
        WHEN u.is_anonymized = true THEN 3
        WHEN u.is_inactivated = true THEN 2
        ELSE 1
    END"""
    sort_field_map = {
        "name": f"u.last_name{collate_clause} {{order}}, u.first_name{collate_clause} {{order}}",
        "email": f"ue.email{collate_clause} {{order}}",
        "role": "u.role {order}",  # ENUM type - cannot use COLLATE
        "status": f"{status_case} {{order}}",
        "last_login": "u.last_login {order}",
        "last_activity_at": "ua.last_activity_at {order}",
        "created_at": "u.created_at {order}",
    }

    if sort_field not in sort_field_map:
        sort_field = "created_at"

    if sort_order not in ["asc", "desc"]:
        sort_order = "desc"

    order_by_clause = sort_field_map[sort_field].format(order=sort_order)

    # Calculate pagination
    offset = (page - 1) * page_size
    params["limit"] = page_size
    params["offset"] = offset

    query = f"""
        select u.id, u.first_name, u.last_name, u.role, u.created_at, u.last_login,
               u.is_inactivated, u.is_anonymized,
               ue.email,
               ua.last_activity_at,
               u.saml_idp_id, idp.name as saml_idp_name,
               idp.require_platform_mfa,
               u.password_hash is not null as has_password,
               u.mfa_enabled,
               u.mfa_method
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        left join user_activity ua on u.id = ua.user_id
        left join saml_identity_providers idp on u.saml_idp_id = idp.id
        {where_clause}
        order by {order_by_clause}
        limit :limit offset :offset
    """

    return fetchall(tenant_id, query, params)
