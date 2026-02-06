"""Utility functions for users service.

These are low-level utility functions without authorization.
Callers must have already verified permissions.
"""

import database


def check_collation_exists(tenant_id: str, collation: str) -> bool:
    """
    Check if a database collation exists.

    This is a utility function without authorization - used for
    determining locale-aware sorting support.

    Args:
        tenant_id: Tenant ID
        collation: Collation name (e.g., "sv-SE-x-icu")

    Returns:
        True if collation exists in the database, False otherwise
    """
    return database.users.check_collation_exists(tenant_id, collation)


def count_users(
    tenant_id: str,
    search: str | None = None,
    roles: list[str] | None = None,
    statuses: list[str] | None = None,
) -> int:
    """
    Count users in a tenant, optionally filtered by search term, roles, and statuses.

    This is a utility function without authorization.

    Args:
        tenant_id: Tenant ID
        search: Optional search term
        roles: Optional list of roles to filter by (member, admin, super_admin)
        statuses: Optional list of statuses to filter by (active, inactivated, anonymized)

    Returns:
        Total count of matching users
    """
    return database.users.count_users(tenant_id, search, roles, statuses)


def list_users_raw(
    tenant_id: str,
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
    List users with pagination - returns raw dicts for HTML templates.

    This is a utility function without authorization - caller must
    have already verified admin access.

    Args:
        tenant_id: Tenant ID
        search: Optional search term
        sort_field: Field to sort by (name, email, role, status, last_login, created_at)
        sort_order: Sort order (asc or desc)
        page: Page number (1-indexed)
        page_size: Results per page
        collation: Optional collation for locale-aware sorting
        roles: Optional list of roles to filter by (member, admin, super_admin)
        statuses: Optional list of statuses to filter by (active, inactivated, anonymized)

    Returns:
        List of user dicts
    """
    return database.users.list_users(
        tenant_id=tenant_id,
        search=search,
        sort_field=sort_field,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
        collation=collation,
        roles=roles,
        statuses=statuses,
    )


def email_exists(tenant_id: str, email: str) -> bool:
    """
    Check if an email address already exists in the tenant.

    This is a utility function without authorization.

    Args:
        tenant_id: Tenant ID
        email: Email address to check

    Returns:
        True if email exists, False otherwise
    """
    return database.user_emails.email_exists(tenant_id, email)


def get_tenant_name(tenant_id: str) -> str:
    """
    Get the display name for a tenant.

    This is a utility function without authorization.

    Args:
        tenant_id: Tenant ID

    Returns:
        Tenant name or "Loom" as default
    """
    tenant_info = database.tenants.get_tenant_by_id(tenant_id)
    return tenant_info.get("name", "Loom") if tenant_info else "Loom"


def create_user_raw(
    tenant_id: str,
    first_name: str,
    last_name: str,
    email: str,
    role: str,
) -> dict | None:
    """
    Create a user record without email setup.

    This is a low-level utility function without authorization.
    Caller must have already verified permissions.

    Args:
        tenant_id: Tenant ID
        first_name: User's first name
        last_name: User's last name
        email: User's email (for the user record)
        role: User role

    Returns:
        Dict with user_id if successful, None otherwise
    """
    return database.users.create_user(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        first_name=first_name,
        last_name=last_name,
        email=email,
        role=role,
    )


def add_verified_email_with_nonce(
    tenant_id: str,
    user_id: str,
    email: str,
    is_primary: bool = True,
) -> dict | None:
    """
    Add a verified email address to a user.

    This is a low-level utility function without authorization.
    Caller must have already verified permissions.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        email: Email address
        is_primary: Whether to set as primary

    Returns:
        Dict with email id if successful, None otherwise
    """
    result = database.user_emails.add_verified_email(
        tenant_id=tenant_id,
        tenant_id_value=tenant_id,
        user_id=user_id,
        email=email,
        is_primary=is_primary,
    )
    if result and is_primary:
        database.user_emails.set_primary_email(tenant_id, result["id"])
    return result


def add_unverified_email_with_nonce(
    tenant_id: str,
    user_id: str,
    email: str,
    is_primary: bool = True,
) -> dict | None:
    """
    Add an unverified email address to a user.

    This is a low-level utility function without authorization.
    Caller must have already verified permissions.

    Args:
        tenant_id: Tenant ID
        user_id: User ID
        email: Email address
        is_primary: Whether to set as primary

    Returns:
        Dict with email id and verify_nonce if successful, None otherwise
    """
    result = database.user_emails.add_email(
        tenant_id=tenant_id,
        user_id=user_id,
        email=email,
        tenant_id_value=tenant_id,
    )
    if result and is_primary:
        database.user_emails.set_primary_email(tenant_id, result["id"])
    return result


def get_available_roles() -> list[str]:
    """
    Get list of available user roles.

    Returns:
        List of role names: member, admin, super_admin
    """
    return ["member", "admin", "super_admin"]


def get_admin_emails(tenant_id: str) -> list[str]:
    """
    Get email addresses of all active admins and super_admins.

    This is a utility function without authorization - used for
    sending admin notifications.

    Args:
        tenant_id: Tenant ID

    Returns:
        List of admin email addresses
    """
    return database.users.get_admin_emails(tenant_id)


def get_user_id_by_email(tenant_id: str, email: str) -> str | None:
    """
    Look up a user ID by email address.

    This is a utility function without authorization - used for
    security logging of failed login attempts.

    Args:
        tenant_id: Tenant ID
        email: Email address to look up

    Returns:
        User ID if found, None otherwise
    """
    result = database.users.get_user_by_email(tenant_id, email)
    return str(result["user_id"]) if result else None


def get_user_by_id_raw(tenant_id: str, user_id: str) -> dict | None:
    """
    Get a user by ID (raw dict).

    This is a utility function without authorization - used for
    authentication flows where the user isn't fully logged in yet.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID

    Returns:
        User dict or None if not found
    """
    return database.users.get_user_by_id(tenant_id, user_id)


def update_password(tenant_id: str, user_id: str, password_hash: str) -> None:
    """
    Update a user's password hash.

    This is a utility function without authorization - called after
    validation in set_password route.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID
        password_hash: Hashed password to store
    """
    database.users.update_password(tenant_id, user_id, password_hash)


def update_last_login(tenant_id: str, user_id: str) -> None:
    """
    Update user's last login timestamp.

    This is a utility function without authorization - called after
    successful MFA verification.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID
    """
    database.users.update_last_login(tenant_id, user_id)


def update_timezone_and_last_login(tenant_id: str, user_id: str, timezone: str) -> None:
    """
    Update user's timezone and last login timestamp.

    This is a utility function without authorization - called after
    successful MFA verification when timezone changed.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID
        timezone: Timezone string (e.g., "America/New_York")
    """
    database.users.update_timezone_and_last_login(tenant_id, user_id, timezone)


def update_locale_and_last_login(tenant_id: str, user_id: str, locale: str) -> None:
    """
    Update user's locale and last login timestamp.

    This is a utility function without authorization - called after
    successful MFA verification when locale changed.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID
        locale: Locale string (e.g., "en-US")
    """
    database.users.update_locale_and_last_login(tenant_id, user_id, locale)


def update_timezone_locale_and_last_login(
    tenant_id: str, user_id: str, timezone: str, locale: str
) -> None:
    """
    Update user's timezone, locale, and last login timestamp.

    This is a utility function without authorization - called after
    successful MFA verification when both changed.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID
        timezone: Timezone string (e.g., "America/New_York")
        locale: Locale string (e.g., "en-US")
    """
    database.users.update_timezone_locale_and_last_login(tenant_id, user_id, timezone, locale)
