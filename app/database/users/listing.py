"""User search and listing database operations."""

from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from database._core import TenantArg, escape_like, fetchall, fetchone


def _build_search_clauses(
    search: str | None,
    where_clauses: list[str],
    params: dict[str, Any],
) -> None:
    """Build tokenized search WHERE clauses.

    Splits search on whitespace. Each token must match at least one of
    first_name, last_name, or email (AND across tokens, OR within a token).
    Single-word searches produce identical behavior to the previous
    implementation.
    """
    if not search:
        return

    tokens = search.split()
    for i, token in enumerate(tokens):
        param_name = f"search_{i}"
        where_clauses.append(
            f"(u.first_name ilike :{param_name}"
            f" or u.last_name ilike :{param_name}"
            f" or ue.email ilike :{param_name})"
        )
        params[param_name] = f"%{escape_like(token)}%"


def _build_auth_method_clauses(
    auth_methods: list[str] | None,
    where_clauses: list[str],
    params: dict[str, Any],
) -> None:
    """Build auth method filter WHERE clauses.

    Auth method keys:
      - password_email: has password, no TOTP
      - password_totp: has password, TOTP enabled
      - idp:<uuid>: SAML IdP user without platform MFA
      - idp:<uuid>_totp: SAML IdP user with platform MFA TOTP
      - unverified: no password, no IdP
    """
    if not auth_methods:
        return

    conditions: list[str] = []
    idp_ids: list[str] = []
    idp_totp_ids: list[str] = []

    for method in auth_methods:
        if method == "password_email":
            conditions.append(
                "(u.password_hash is not null and u.saml_idp_id is null"
                " and (u.mfa_method is null or u.mfa_method != 'totp'))"
            )
        elif method == "password_totp":
            conditions.append(
                "(u.password_hash is not null and u.saml_idp_id is null and u.mfa_method = 'totp')"
            )
        elif method == "unverified":
            conditions.append("(u.password_hash is null and u.saml_idp_id is null)")
        elif method.startswith("idp:"):
            remainder = method[4:]
            if remainder.endswith("_totp"):
                idp_totp_ids.append(remainder[:-5])
            else:
                idp_ids.append(remainder)

    if idp_ids:
        params["auth_idp_ids"] = idp_ids
        conditions.append(
            "(u.saml_idp_id = ANY(:auth_idp_ids)"
            " and (idp.require_platform_mfa is not true"
            " or u.mfa_method is null or u.mfa_method != 'totp'))"
        )

    if idp_totp_ids:
        params["auth_idp_totp_ids"] = idp_totp_ids
        conditions.append(
            "(u.saml_idp_id = ANY(:auth_idp_totp_ids)"
            " and idp.require_platform_mfa = true"
            " and u.mfa_method = 'totp')"
        )

    if conditions:
        where_clauses.append(f"({' or '.join(conditions)})")


def _build_domain_clause(
    domain: str | None,
    where_clauses: list[str],
    params: dict[str, Any],
) -> None:
    """Filter by email domain (matches any email, primary or secondary)."""
    if not domain:
        return
    where_clauses.append(
        "exists (select 1 from user_emails ue_d"
        " where ue_d.user_id = u.id and ue_d.domain = lower(:domain))"
    )
    params["domain"] = domain


def _build_group_clause(
    group_id: str | None,
    where_clauses: list[str],
    params: dict[str, Any],
) -> None:
    """Filter by group membership."""
    if not group_id:
        return
    where_clauses.append(
        "exists (select 1 from group_memberships gm_f"
        " where gm_f.user_id = u.id and gm_f.group_id = :filter_group_id)"
    )
    params["filter_group_id"] = group_id


def _build_secondary_email_clause(
    has_secondary_email: bool | str | None,
    where_clauses: list[str],
    params: dict[str, Any],
) -> None:
    """Filter by presence of secondary email addresses.

    Accepts bool (has/doesn't have any secondary) or a string starting
    with "domain:" to filter for users with a secondary at that domain.
    """
    if has_secondary_email is None:
        return
    if isinstance(has_secondary_email, str) and has_secondary_email.startswith("domain:"):
        domain_val = has_secondary_email[7:]
        where_clauses.append(
            "exists (select 1 from user_emails ue2 where ue2.user_id = u.id"
            " and ue2.is_primary = false and ue2.domain = :sec_domain)"
        )
        params["sec_domain"] = domain_val
    elif has_secondary_email:
        where_clauses.append(
            "exists (select 1 from user_emails ue2"
            " where ue2.user_id = u.id and ue2.is_primary = false)"
        )
    else:
        where_clauses.append(
            "not exists (select 1 from user_emails ue2"
            " where ue2.user_id = u.id and ue2.is_primary = false)"
        )


def _build_activity_date_clauses(
    activity_start: date | None,
    activity_end: date | None,
    where_clauses: list[str],
    params: dict[str, Any],
) -> None:
    """Filter by last activity date range (inclusive)."""
    if activity_start:
        where_clauses.append("ua.last_activity_at >= :activity_start")
        params["activity_start"] = datetime.combine(activity_start, time.min, tzinfo=UTC)
    if activity_end:
        where_clauses.append("ua.last_activity_at < :activity_end_exclusive")
        params["activity_end_exclusive"] = datetime.combine(
            activity_end + timedelta(days=1), time.min, tzinfo=UTC
        )


def count_users(
    tenant_id: TenantArg,
    search: str | None = None,
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
    auth_methods: list[str] | None = None,
    domain: str | None = None,
    group_id: str | None = None,
    has_secondary_email: bool | str | None = None,
    activity_start: date | None = None,
    activity_end: date | None = None,
) -> int:
    """
    Count users, optionally filtered by search term, roles, statuses,
    auth methods, domain, group, secondary email, and activity date range.

    Args:
        tenant_id: Tenant ID
        search: Search term to filter by (searches first_name, last_name, email)
        roles: List of roles to filter by (member, admin, super_admin)
        statuses: List of statuses to filter by (active, inactivated, anonymized)
        auth_methods: List of auth method keys to filter by
        domain: Email domain to filter by
        group_id: Group UUID to filter by membership
        has_secondary_email: Filter by presence of secondary email addresses
        activity_start: Filter by activity on or after this date (inclusive)
        activity_end: Filter by activity on or before this date (inclusive)

    Returns:
        Total count of matching users
    """
    where_clauses: list[str] = [
        "not exists (select 1 from oauth2_clients oc where oc.service_user_id = u.id)",
    ]
    params: dict[str, Any] = {}

    _build_search_clauses(search, where_clauses, params)

    if roles:
        allowed_roles = {"member", "admin", "super_admin"}
        valid_roles = [r for r in roles if r in allowed_roles]
        if valid_roles:
            where_clauses.append("u.role = ANY(:roles)")
            params["roles"] = valid_roles

    if statuses:
        status_conditions: list[str] = []
        if "active" in statuses:
            status_conditions.append("(u.is_inactivated = false and u.is_anonymized = false)")
        if "inactivated" in statuses:
            status_conditions.append("(u.is_inactivated = true and u.is_anonymized = false)")
        if "anonymized" in statuses:
            status_conditions.append("u.is_anonymized = true")
        if status_conditions:
            where_clauses.append(f"({' or '.join(status_conditions)})")

    _build_auth_method_clauses(auth_methods, where_clauses, params)
    _build_domain_clause(domain, where_clauses, params)
    _build_group_clause(group_id, where_clauses, params)
    _build_secondary_email_clause(has_secondary_email, where_clauses, params)
    _build_activity_date_clauses(activity_start, activity_end, where_clauses, params)

    where_clause = "where " + " and ".join(where_clauses)

    # Need IdP join for auth method filtering
    idp_join = ""
    if auth_methods:
        idp_join = "left join saml_identity_providers idp on u.saml_idp_id = idp.id"

    # Need activity join for activity date filtering
    activity_join = ""
    if activity_start or activity_end:
        activity_join = "left join user_activity ua on u.id = ua.user_id"

    query = f"""
        select count(distinct u.id) as count
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        {idp_join}
        {activity_join}
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
    auth_methods: list[str] | None = None,
    domain: str | None = None,
    group_id: str | None = None,
    has_secondary_email: bool | str | None = None,
    activity_start: date | None = None,
    activity_end: date | None = None,
) -> list[dict]:
    """
    List users with pagination, sorting, search, and filtering.

    Args:
        tenant_id: Tenant ID
        search: Search term to filter by (searches first_name, last_name, email).
                Multiple words are tokenized: each token must match at least one
                of first_name, last_name, or email.
        sort_field: Field to sort by (name, email, role, status, last_login,
                   last_activity_at, created_at)
        sort_order: Sort order (asc or desc)
        page: Page number (1-indexed)
        page_size: Number of results per page
        collation: Optional collation for text sorting (e.g., "sv-SE-x-icu")
        roles: List of roles to filter by (member, admin, super_admin)
        statuses: List of statuses to filter by (active, inactivated, anonymized)
        auth_methods: List of auth method keys to filter by
        domain: Email domain to filter by
        group_id: Group UUID to filter by membership
        has_secondary_email: Filter by presence of secondary email addresses
        activity_start: Filter by activity on or after this date (inclusive)
        activity_end: Filter by activity on or before this date (inclusive)

    Returns:
        List of user dicts with id, first_name, last_name, role, created_at,
        last_login, last_activity_at, is_inactivated, is_anonymized, email,
        saml_idp_id, saml_idp_name, require_platform_mfa, has_password,
        mfa_enabled, and mfa_method
    """
    # Build WHERE clause — always exclude service accounts (B2B OAuth2 clients)
    where_clauses: list[str] = [
        "not exists (select 1 from oauth2_clients oc where oc.service_user_id = u.id)",
    ]
    params: dict[str, Any] = {}

    _build_search_clauses(search, where_clauses, params)

    if roles:
        allowed_roles = {"member", "admin", "super_admin"}
        valid_roles = [r for r in roles if r in allowed_roles]
        if valid_roles:
            where_clauses.append("u.role = ANY(:roles)")
            params["roles"] = valid_roles

    if statuses:
        status_conditions: list[str] = []
        if "active" in statuses:
            status_conditions.append("(u.is_inactivated = false and u.is_anonymized = false)")
        if "inactivated" in statuses:
            status_conditions.append("(u.is_inactivated = true and u.is_anonymized = false)")
        if "anonymized" in statuses:
            status_conditions.append("u.is_anonymized = true")
        if status_conditions:
            where_clauses.append(f"({' or '.join(status_conditions)})")

    _build_auth_method_clauses(auth_methods, where_clauses, params)
    _build_domain_clause(domain, where_clauses, params)
    _build_group_clause(group_id, where_clauses, params)
    _build_secondary_email_clause(has_secondary_email, where_clauses, params)
    _build_activity_date_clauses(activity_start, activity_end, where_clauses, params)

    where_clause = "where " + " and ".join(where_clauses)

    # SECURITY: Dynamic collation and field names in ORDER BY clause.
    #
    # Collation safety:
    # - collation parameter is validated via check_collation_exists() in router
    # - Only database-recognized collations are allowed (SQL injection impossible)
    # - Still wrapped in double quotes as defense-in-depth
    #
    # Field name safety:
    # - sort_field is validated against a whitelist dictionary
    # - Only pre-defined keys are accepted: name, email, role, status, etc.
    # - Values in the dict are controlled template strings, not user input
    #
    # Sort order safety:
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
               u.mfa_method,
               coalesce(gc.group_count, 0) as group_count
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        left join user_activity ua on u.id = ua.user_id
        left join saml_identity_providers idp on u.saml_idp_id = idp.id
        left join (
            select user_id, count(*) as group_count
            from group_memberships
            group by user_id
        ) gc on u.id = gc.user_id
        {where_clause}
        order by {order_by_clause}
        limit :limit offset :offset
    """

    return fetchall(tenant_id, query, params)


def list_users_by_ids(
    tenant_id: TenantArg,
    user_ids: list[str],
) -> list[dict]:
    """Fetch users by a list of IDs with their primary email.

    Args:
        tenant_id: Tenant ID
        user_ids: List of user UUIDs to fetch

    Returns:
        List of dicts with id, first_name, last_name, email (primary).
        Ordered by last_name, first_name.
    """
    if not user_ids:
        return []
    return fetchall(
        tenant_id,
        """
        select u.id, u.first_name, u.last_name, ue.email
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        where u.id = any(:user_ids)
        order by u.last_name asc, u.first_name asc
        """,
        {"user_ids": user_ids},
    )


def list_all_users_for_export(tenant_id: TenantArg) -> list[dict]:
    """List all active, non-anonymized users with their primary email.

    Returns all users without pagination, suitable for spreadsheet generation.
    Excludes service accounts, inactivated users, and anonymized users.

    Args:
        tenant_id: Tenant ID

    Returns:
        List of dicts with id, first_name, last_name, email
    """
    return fetchall(
        tenant_id,
        """
        select u.id, u.first_name, u.last_name, ue.email
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        where u.is_inactivated = false
          and u.is_anonymized = false
          and not exists (
              select 1 from oauth2_clients oc where oc.service_user_id = u.id
          )
        order by u.last_name asc, u.first_name asc
        """,
        {},
    )
