"""User account database operations."""

from typing import Any

from ._core import TenantArg, execute, fetchall, fetchone


def get_user_by_id(tenant_id: TenantArg, user_id: str) -> dict | None:
    """
    Get a user by ID.

    Returns:
        User record with id, tenant_id, first_name, last_name, role, created_at,
        last_login, mfa_enabled, mfa_method, tz, locale
    """
    return fetchone(
        tenant_id,
        """
        select id, tenant_id, first_name, last_name, role, created_at, last_login,
               mfa_enabled, mfa_method, tz, locale
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


def count_users(tenant_id: TenantArg, search: str | None = None) -> int:
    """
    Count users, optionally filtered by search term.

    Args:
        tenant_id: Tenant ID
        search: Search term to filter by (searches first_name, last_name, email)

    Returns:
        Total count of matching users
    """
    where_clause = ""
    params: dict[str, Any] = {}

    if search:
        where_clause = """
            where u.first_name ilike :search
               or u.last_name ilike :search
               or ue.email ilike :search
        """
        params["search"] = f"%{search}%"

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
) -> list[dict]:
    """
    List users with pagination, sorting, and search.

    Args:
        tenant_id: Tenant ID
        search: Search term to filter by (searches first_name, last_name, email)
        sort_field: Field to sort by (name, email, role, last_login, created_at)
        sort_order: Sort order (asc or desc)
        page: Page number (1-indexed)
        page_size: Number of results per page
        collation: Optional collation for text sorting (e.g., "sv-SE-x-icu")

    Returns:
        List of user dicts with id, first_name, last_name, role, created_at,
        last_login, and email
    """
    # Build WHERE clause
    where_clause = ""
    params: dict[str, str | int] = {}

    if search:
        where_clause = """
            where u.first_name ilike :search
               or u.last_name ilike :search
               or ue.email ilike :search
        """
        params["search"] = f"%{search}%"

    # Build ORDER BY clause
    collate_clause = f' COLLATE "{collation}"' if collation else ""
    sort_field_map = {
        "name": f"u.last_name{collate_clause} {{order}}, u.first_name{collate_clause} {{order}}",
        "email": f"ue.email{collate_clause} {{order}}",
        "role": "u.role {order}",  # ENUM type - cannot use COLLATE
        "last_login": "u.last_login {order}",
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
               ue.email
        from users u
        left join user_emails ue on u.id = ue.user_id and ue.is_primary = true
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
