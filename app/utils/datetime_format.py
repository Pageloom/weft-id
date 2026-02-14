"""Datetime formatting utilities with timezone and locale support."""

from datetime import date, datetime
from zoneinfo import ZoneInfo

from babel.dates import format_datetime as babel_format_datetime


def format_datetime(dt: datetime, timezone: str | None = None, locale: str = "en_US") -> str:
    """
    Format a datetime object to a localized string with timezone conversion.

    Args:
        dt: datetime object (should be timezone-aware, typically UTC from database)
        timezone: IANA timezone string (e.g., 'America/New_York', 'Europe/Stockholm')
                 If None, uses UTC
        locale: locale string (e.g., 'en_US', 'sv_SE', 'en_SE')

    Returns:
        Formatted datetime string according to locale conventions
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

    # Format using babel for locale-aware formatting
    # 'medium' format includes date and time with seconds
    try:
        return babel_format_datetime(dt, format="medium", locale=locale)
    except Exception:
        # Fallback to ISO format if locale is invalid
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


def format_relative_date(
    dt: datetime | None,
    timezone: str | None = None,
    locale: str = "en_US",
    reference: date | None = None,
) -> tuple[str, str]:
    """
    Format a datetime as a relative date string with an exact tooltip.

    Args:
        dt: datetime object (should be timezone-aware, typically UTC from database)
        timezone: IANA timezone string for the user (for converting both dt and reference)
        locale: locale string for exact date formatting
        reference: reference date for "today" (defaults to today in user's timezone).
                   Useful for testing.

    Returns:
        Tuple of (relative_text, exact_text) where exact_text is the full formatted date
    """
    if dt is None:
        return ("Never", "")

    exact_text = format_datetime(dt, timezone, locale)

    # Convert dt to the user's timezone for date comparison
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))

    if timezone:
        try:
            user_tz = ZoneInfo(timezone)
            dt_local = dt.astimezone(user_tz)
        except Exception:
            dt_local = dt
    else:
        dt_local = dt

    dt_date = dt_local.date()

    if reference is None:
        # Get "today" in the user's timezone
        if timezone:
            try:
                user_tz = ZoneInfo(timezone)
                reference = datetime.now(tz=user_tz).date()
            except Exception:
                reference = datetime.now(tz=ZoneInfo("UTC")).date()
        else:
            reference = datetime.now(tz=ZoneInfo("UTC")).date()

    days_ago = (reference - dt_date).days

    if days_ago < 0:
        days_ahead = -days_ago
        if days_ahead == 1:
            relative_text = "Tomorrow"
        elif days_ahead < 14:
            relative_text = f"in {days_ahead} days"
        elif days_ahead < 60:
            weeks = days_ahead // 7
            relative_text = f"in {weeks} week{'s' if weeks != 1 else ''}"
        elif days_ahead < 365:
            months = days_ahead // 30
            relative_text = f"in {months} month{'s' if months != 1 else ''}"
        else:
            years = days_ahead // 365
            relative_text = f"in {years} year{'s' if years != 1 else ''}"
    elif days_ago == 0:
        relative_text = "Today"
    elif days_ago == 1:
        relative_text = "Yesterday"
    elif days_ago < 14:
        relative_text = f"{days_ago} days ago"
    elif days_ago < 60:
        weeks = days_ago // 7
        relative_text = f"{weeks} week{'s' if weeks != 1 else ''} ago"
    elif days_ago < 365:
        months = days_ago // 30
        relative_text = f"{months} month{'s' if months != 1 else ''} ago"
    else:
        years = days_ago // 365
        relative_text = f"{years} year{'s' if years != 1 else ''} ago"

    return (relative_text, exact_text)


def create_relative_date_formatter(user_timezone: str | None = None, user_locale: str = "en_US"):
    """
    Create a relative date formatter function with bound timezone and locale.

    Args:
        user_timezone: IANA timezone string for the user
        user_locale: locale string for the user

    Returns:
        A function that takes a datetime and returns (relative_text, exact_text)
    """

    def formatter(dt: datetime | None) -> tuple[str, str]:
        return format_relative_date(dt, user_timezone, user_locale)

    return formatter
