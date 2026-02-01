"""User login and activity tracking database operations."""

from database._core import TenantArg, execute


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
