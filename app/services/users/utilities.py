"""Utility functions for users service.

These are low-level utility functions without authorization.
Callers must have already verified permissions.
"""

from datetime import date

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
    auth_methods: list[str] | None = None,
    domain: str | None = None,
    group_id: str | None = None,
    has_secondary_email: bool | str | None = None,
    activity_start: date | None = None,
    activity_end: date | None = None,
    role_negate: bool = False,
    status_negate: bool = False,
    auth_method_negate: bool = False,
    domain_negate: bool = False,
    group_negate: bool = False,
    group_include_children: bool = True,
) -> int:
    """
    Count users in a tenant, optionally filtered.

    This is a utility function without authorization.
    """
    return database.users.count_users(
        tenant_id,
        search,
        roles,
        statuses,
        auth_methods,
        domain=domain,
        group_id=group_id,
        has_secondary_email=has_secondary_email,
        activity_start=activity_start,
        activity_end=activity_end,
        role_negate=role_negate,
        status_negate=status_negate,
        auth_method_negate=auth_method_negate,
        domain_negate=domain_negate,
        group_negate=group_negate,
        group_include_children=group_include_children,
    )


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
    auth_methods: list[str] | None = None,
    domain: str | None = None,
    group_id: str | None = None,
    has_secondary_email: bool | str | None = None,
    activity_start: date | None = None,
    activity_end: date | None = None,
    role_negate: bool = False,
    status_negate: bool = False,
    auth_method_negate: bool = False,
    domain_negate: bool = False,
    group_negate: bool = False,
    group_include_children: bool = True,
) -> list[dict]:
    """
    List users with pagination - returns raw dicts for HTML templates.

    This is a utility function without authorization - caller must
    have already verified admin access.
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
        auth_methods=auth_methods,
        domain=domain,
        group_id=group_id,
        has_secondary_email=has_secondary_email,
        activity_start=activity_start,
        activity_end=activity_end,
        role_negate=role_negate,
        status_negate=status_negate,
        auth_method_negate=auth_method_negate,
        domain_negate=domain_negate,
        group_negate=group_negate,
        group_include_children=group_include_children,
    )


def get_auth_method_options(tenant_id: str) -> list[dict]:
    """
    Get available auth method filter options.

    Builds options from static categories plus any configured SAML IdPs.
    This avoids a heavy GROUP BY query across all users.

    Args:
        tenant_id: Tenant ID

    Returns:
        List of dicts with auth_method_key and auth_method_label
    """
    options: list[dict] = [
        {"auth_method_key": "password_email", "auth_method_label": "Password + Email"},
        {"auth_method_key": "password_totp", "auth_method_label": "Password + TOTP"},
        {"auth_method_key": "passkey", "auth_method_label": "Passkey"},
        {"auth_method_key": "multiple", "auth_method_label": "Multiple methods"},
    ]

    idps = database.saml.list_identity_providers(tenant_id)
    for idp in idps:
        idp_id = str(idp["id"])
        name = idp["name"]
        options.append({"auth_method_key": f"idp:{idp_id}", "auth_method_label": name})
        if idp.get("require_platform_mfa"):
            options.append(
                {"auth_method_key": f"idp:{idp_id}_totp", "auth_method_label": f"{name} + TOTP"}
            )

    options.append({"auth_method_key": "unverified", "auth_method_label": "Unverified"})

    return options


def get_domain_filter_options(tenant_id: str) -> list[dict]:
    """Get all observed email domains for filtering.

    Returns all distinct domains from user emails, with a flag indicating
    whether each domain is a privileged domain.

    Args:
        tenant_id: Tenant ID

    Returns:
        List of dicts with domain (str) and privileged (bool), sorted alphabetically.
    """
    privileged = {d["domain"] for d in database.settings.list_privileged_domains(tenant_id)}
    all_domains = database.user_emails.list_distinct_domains(tenant_id)
    return [{"domain": d["domain"], "privileged": d["domain"] in privileged} for d in all_domains]


def get_secondary_email_domain_options(tenant_id: str) -> list[str]:
    """Get distinct domains used in secondary (non-primary) emails.

    Args:
        tenant_id: Tenant ID

    Returns:
        Sorted list of domain strings.
    """
    rows = database.user_emails.list_secondary_email_domains(tenant_id)
    return [r["domain"] for r in rows]


def get_group_filter_options(tenant_id: str) -> list[dict]:
    """Get available groups for filtering.

    Returns list of dicts with id and name, sorted by name.

    Args:
        tenant_id: Tenant ID

    Returns:
        List of dicts with id and name keys
    """
    groups = database.groups.list_groups(
        tenant_id, sort_field="name", sort_order="asc", page_size=10000
    )
    return [{"id": str(g["id"]), "name": g["name"], "group_type": g["group_type"]} for g in groups]


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


def update_password(
    tenant_id: str,
    user_id: str,
    password_hash: str,
    hibp_prefix: str | None = None,
    hibp_check_hmac: str | None = None,
    policy_length_at_set: int | None = None,
    policy_score_at_set: int | None = None,
) -> None:
    """
    Update a user's password hash.

    This is a utility function without authorization - called after
    validation in set_password route.

    Args:
        tenant_id: Tenant ID
        user_id: User UUID
        password_hash: Hashed password to store
        hibp_prefix: First 5 hex chars of SHA-1 for HIBP monitoring
        hibp_check_hmac: HMAC of full SHA-1 for breach verification
        policy_length_at_set: Minimum password length policy when set
        policy_score_at_set: Minimum zxcvbn score policy when set
    """
    database.users.update_password(
        tenant_id,
        user_id,
        password_hash,
        hibp_prefix=hibp_prefix,
        hibp_check_hmac=hibp_check_hmac,
        policy_length_at_set=policy_length_at_set,
        policy_score_at_set=policy_score_at_set,
    )


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
