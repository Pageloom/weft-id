"""User profile and preferences database operations."""

from database._core import TenantArg, execute


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


def update_user_theme(tenant_id: TenantArg, user_id: str, theme: str) -> int:
    """Update user's theme preference."""
    return execute(
        tenant_id,
        "update users set theme = :theme where id = :user_id",
        {"theme": theme, "user_id": user_id},
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
