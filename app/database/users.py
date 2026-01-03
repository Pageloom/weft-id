"""User account database operations."""

from typing import Any

from ._core import TenantArg, execute, fetchall, fetchone


def get_user_by_id(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get a user by ID.

    Returns:
        User record with id, tenant_id, first_name, last_name, role, created_at,
        last_login, mfa_enabled, mfa_method, tz, locale, is_inactivated, is_anonymized,
        inactivated_at, anonymized_at, reactivation_denied_at
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, first_name, last_name, role, created_at, last_login,
               mfa_enabled, mfa_method, tz, locale,
               is_inactivated, is_anonymized, inactivated_at, anonymized_at,
               reactivation_denied_at
        from users
        where id = :user_id
        """,
        {"user_id": user_id},
    )


def get_user_by_email(tenant_id: TenantArg, email: str) -> dict | None:
    """
    Get a user by email address (for login).

    Returns:
        Dict with user_id and password_hash, or None if not found or email not verified
    """
    return fetchone(
        tenant_id,
        """
        select ue.user_id, u.password_hash
        from user_emails ue
        join users u on u.id = ue.user_id
        where ue.email = :email and ue.verified_at is not null
        """,
        {"email": email},
    )


def update_user_profile(tenant_id: TenantArg, user_id: str, first_name: str, last_name: str) -> int:
    """Update user's first name and last name."""
    return execute(
        tenant_id,
        """
        update users
        set first_name = :first_name, last_name = :last_name
        where id = :user_id
        """,
        {"first_name": first_name, "last_name": last_name, "user_id": user_id},
    )


def update_user_timezone(tenant_id: TenantArg, user_id: str, timezone: str) -> int:
    """Update user's timezone."""
    return execute(
        tenant_id,
        "update users set tz = :tz where id = :user_id",
        {"tz": timezone, "user_id": user_id},
    )


def update_user_locale(tenant_id: TenantArg, user_id: str, locale: str) -> int:
    """Update user's locale."""
    return execute(
        tenant_id,
        "update users set locale = :locale where id = :user_id",
        {"locale": locale, "user_id": user_id},
    )


def update_user_timezone_and_locale(
    tenant_id: TenantArg, user_id: str, timezone: str, locale: str
) -> int:
    """Update user's timezone and locale."""
    return execute(
        tenant_id,
        "update users set tz = :tz, locale = :locale where id = :user_id",
        {"tz": timezone, "locale": locale, "user_id": user_id},
    )


def update_last_login(tenant_id: TenantArg, user_id: str) -> int:
    """Update user's last_login timestamp to now."""
    return execute(
        tenant_id,
        "update users set last_login = now() where id = :user_id",
        {"user_id": user_id},
    )


def update_timezone_and_last_login(tenant_id: TenantArg, user_id: str, timezone: str) -> int:
    """Update user's timezone and last_login timestamp."""
    return execute(
        tenant_id,
        "update users set tz = :tz, last_login = now() where id = :user_id",
        {"tz": timezone, "user_id": user_id},
    )


def update_locale_and_last_login(tenant_id: TenantArg, user_id: str, locale: str) -> int:
    """Update user's locale and last_login timestamp."""
    return execute(
        tenant_id,
        "update users set locale = :locale, last_login = now() where id = :user_id",
        {"locale": locale, "user_id": user_id},
    )


def update_timezone_locale_and_last_login(
    tenant_id: TenantArg, user_id: str, timezone: str, locale: str
) -> int:
    """Update user's timezone, locale, and last_login timestamp."""
    return execute(
        tenant_id,
        "update users set tz = :tz, locale = :locale, last_login = now() where id = :user_id",
        {"tz": timezone, "locale": locale, "user_id": user_id},
    )


def check_collation_exists(tenant_id: TenantArg, collation: str) -> bool:
    """
    Check if a collation exists in the database.

    Args:
        tenant_id: Tenant ID (or UNSCOPED for system-wide check)
        collation: Collation name (e.g., "sv-SE-x-icu")

    Returns:
        True if collation exists, False otherwise
    """
    result = fetchone(
        tenant_id,
        "select 1 from pg_collation where collname = :collation",
        {"collation": collation},
    )
    return result is not None


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
        last_login, last_activity_at, is_inactivated, is_anonymized, and email
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
               ua.last_activity_at
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
        left join user_activity ua on u.id = ua.user_id
        {where_clause}
        order by {order_by_clause}
        limit :limit offset :offset
    """

    return fetchall(tenant_id, query, params)


def update_user_role(tenant_id: TenantArg, user_id: str, role: str) -> int:
    """
    Update a user's role (admin operation).

    Args:
        tenant_id: Tenant ID
        user_id: User ID to update
        role: New role ('member', 'admin', or 'super_admin')

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set role = :role where id = :user_id",
        {"role": role, "user_id": user_id},
    )


def update_password(tenant_id: TenantArg, user_id: str, password_hash: str) -> int:
    """
    Update a user's password hash.

    Args:
        tenant_id: Tenant ID
        user_id: User ID to update
        password_hash: New hashed password

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set password_hash = :password_hash where id = :user_id",
        {"password_hash": password_hash, "user_id": user_id},
    )


def create_user(
    tenant_id: TenantArg,
    tenant_id_value: str,
    first_name: str,
    last_name: str,
    email: str,
    role: str = "member",
) -> dict | None:
    """
    Create a new user account (admin operation).

    This creates a user WITHOUT a password. The user will need to set their password
    via the password reset flow when they receive their invitation email.

    Args:
        tenant_id: Tenant ID for scoping
        tenant_id_value: The actual tenant ID value to store in the record
        first_name: User's first name
        last_name: User's last name
        email: User's primary email address
        role: User role ('member', 'admin', or 'super_admin'). Defaults to 'member'.

    Returns:
        Dict with user_id and email_id, or None if insert failed
    """
    # Create user without password_hash (NULL)
    user = fetchone(
        tenant_id,
        """
        insert into users (tenant_id, first_name, last_name, role, password_hash)
        values (:tenant_id, :first_name, :last_name, :role, null)
        returning id
        """,
        {
            "tenant_id": tenant_id_value,
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
        },
    )

    if not user:
        return None

    return {"user_id": user["id"]}


def delete_user(tenant_id: TenantArg, user_id: str) -> int:
    """
    Delete a user and all associated data.

    This relies on cascading deletes for related records (emails, tokens, etc.).

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to delete

    Returns:
        Number of rows deleted (0 or 1)

    Note:
        Service users (linked to OAuth2 clients) should not be deleted directly.
        Delete the OAuth2 client first to unlink the service user.
    """
    return execute(
        tenant_id,
        "delete from users where id = :user_id",
        {"user_id": user_id},
    )


def is_service_user(tenant_id: TenantArg, user_id: str) -> bool:
    """
    Check if a user is a service user (linked to a B2B OAuth2 client).

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to check

    Returns:
        True if user is a service user, False otherwise
    """
    result = fetchone(
        tenant_id,
        """
        select 1 from oauth2_clients
        where service_user_id = :user_id
        limit 1
        """,
        {"user_id": user_id},
    )
    return result is not None


def update_mfa_status(tenant_id: TenantArg, user_id: str, enabled: bool) -> int:
    """
    Update a user's MFA enabled status.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to update
        enabled: Whether MFA is enabled

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        "update users set mfa_enabled = :enabled where id = :user_id",
        {"enabled": enabled, "user_id": user_id},
    )


def count_active_super_admins(tenant_id: TenantArg) -> int:
    """
    Count active (non-inactivated) super_admin users.

    Args:
        tenant_id: Tenant ID for scoping

    Returns:
        Number of active super_admin users
    """
    result = fetchone(
        tenant_id,
        """
        select count(*) as count from users
        where role = 'super_admin' and is_inactivated = false
        """,
        {},
    )
    return result["count"] if result else 0


def inactivate_user(tenant_id: TenantArg, user_id: str) -> int:
    """
    Inactivate a user account (soft-disable login).

    Inactivated users cannot sign in but retain all their data.
    This operation is reversible via reactivate_user().

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to inactivate

    Returns:
        Number of rows affected (0 if user not found or already inactivated)
    """
    return execute(
        tenant_id,
        """
        update users
        set is_inactivated = true, inactivated_at = now()
        where id = :user_id and is_inactivated = false
        """,
        {"user_id": user_id},
    )


def reactivate_user(tenant_id: TenantArg, user_id: str) -> int:
    """
    Reactivate an inactivated user account.

    Cannot reactivate anonymized users (anonymization is irreversible).

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to reactivate

    Returns:
        Number of rows affected (0 if user not found, not inactivated, or anonymized)
    """
    return execute(
        tenant_id,
        """
        update users
        set is_inactivated = false, inactivated_at = null
        where id = :user_id and is_inactivated = true and is_anonymized = false
        """,
        {"user_id": user_id},
    )


def anonymize_user(tenant_id: TenantArg, user_id: str) -> int:
    """
    Anonymize a user account (GDPR right to be forgotten).

    This is IRREVERSIBLE. Scrubs all PII from the user record:
    - first_name → '[Anonymized]'
    - last_name → 'User'
    - password_hash → NULL
    - mfa_enabled → false
    - mfa_method → NULL
    - tz, locale → NULL

    The user is also inactivated. Related data (emails, MFA secrets) must be
    handled separately by the service layer.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to anonymize

    Returns:
        Number of rows affected (0 if user not found or already anonymized)
    """
    return execute(
        tenant_id,
        """
        update users
        set is_inactivated = true,
            is_anonymized = true,
            first_name = '[Anonymized]',
            last_name = 'User',
            inactivated_at = coalesce(inactivated_at, now()),
            anonymized_at = now(),
            password_hash = null,
            mfa_enabled = false,
            mfa_method = null,
            tz = null,
            locale = null
        where id = :user_id and is_anonymized = false
        """,
        {"user_id": user_id},
    )


def set_reactivation_denied(tenant_id: TenantArg, user_id: str) -> int:
    """
    Mark a user as having been denied reactivation.

    This prevents them from submitting new reactivation requests.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to mark as denied

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update users
        set reactivation_denied_at = now()
        where id = :user_id
        """,
        {"user_id": user_id},
    )


def clear_reactivation_denied(tenant_id: TenantArg, user_id: str) -> int:
    """
    Clear the reactivation denied flag for a user.

    Called when a user is manually reactivated by an admin.

    Args:
        tenant_id: Tenant ID for scoping
        user_id: User ID to clear denial for

    Returns:
        Number of rows affected
    """
    return execute(
        tenant_id,
        """
        update users
        set reactivation_denied_at = null
        where id = :user_id
        """,
        {"user_id": user_id},
    )


def get_idle_users_for_tenant(
    tenant_id: TenantArg,
    threshold_days: int,
) -> list[dict]:
    """
    Get active users who have been idle beyond the threshold.

    This returns users who:
    - Are not inactivated or anonymized
    - Have last_activity_at older than threshold_days ago
    - Are not service users (no associated OAuth2 B2B client)

    Args:
        tenant_id: Tenant ID for scoping
        threshold_days: Number of days of inactivity before inclusion

    Returns:
        List of dicts with user_id, first_name, last_name, last_activity_at
    """
    return fetchall(
        tenant_id,
        """
        select u.id as user_id,
               u.first_name,
               u.last_name,
               ua.last_activity_at
        from users u
        left join user_activity ua on u.id = ua.user_id
        where u.is_inactivated = false
          and u.is_anonymized = false
          and (
              ua.last_activity_at < now() - make_interval(days => :threshold_days)
              or ua.last_activity_at is null
          )
          and not exists (
              select 1 from oauth2_clients oc
              where oc.service_user_id = u.id and oc.client_type = 'b2b'
          )
        """,
        {"threshold_days": threshold_days},
    )
