"""Datetime formatting utilities with timezone and locale support."""

from datetime import datetime
from zoneinfo import ZoneInfo


def format_datetime(dt: datetime, timezone: str | None = None, locale: str = "en_US") -> str:
    """
    Format a datetime object to a localized string with timezone conversion.

    Args:
        dt: datetime object (should be timezone-aware, typically UTC from database)
        timezone: IANA timezone string (e.g., 'America/New_York', 'Europe/London')
                 If None, uses UTC
        locale: locale string (e.g., 'en_US', 'sv_SE') - currently unused, reserved for future

    Returns:
        Formatted datetime string with seconds precision (no microseconds)
    """
    if dt is None:
        return ""

    # Ensure datetime is timezone-aware (assume UTC if naive)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))

    # Convert to user's timezone if provided
    if timezone:
        try:
            user_tz = ZoneInfo(timezone)
            dt = dt.astimezone(user_tz)
        except Exception:
            # If timezone is invalid, fall back to UTC
            pass

    # Format with seconds precision (no microseconds)
    # Using ISO-like format: YYYY-MM-DD HH:MM:SS
    # For future locale support, this can be replaced with locale-specific formatting
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def create_datetime_formatter(user_timezone: str | None = None, user_locale: str = "en_US"):
    """
    Create a datetime formatter function with bound timezone and locale.

    This is useful for passing to templates so they can format datetimes consistently.

    Args:
        user_timezone: IANA timezone string for the user
        user_locale: locale string for the user

    Returns:
        A function that takes a datetime and returns a formatted string
    """

    def formatter(dt: datetime) -> str:
        return format_datetime(dt, user_timezone, user_locale)

    return formatter
