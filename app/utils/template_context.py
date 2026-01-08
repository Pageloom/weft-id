"""Template context helpers for adding common data to templates."""

from dependencies import get_current_user
from fastapi import Request
from middleware.csrf import get_csrf_token
from pages import get_navigation_context
from utils.datetime_format import create_datetime_formatter


def get_template_context(request: Request, tenant_id: str, **kwargs):
    """Get common template context including user and navigation."""
    user = get_current_user(request, tenant_id)

    # Get the current path from the request
    current_path = request.url.path

    # Get navigation context
    nav_context = {}
    if user:
        nav_context = get_navigation_context(current_path, user.get("role"))

    # Create datetime formatter with user's timezone and locale
    user_timezone = user.get("tz") if user else None
    user_locale = user.get("locale", "en_US") if user else "en_US"
    fmt_datetime = create_datetime_formatter(user_timezone, user_locale)

    # Create CSRF token getter that captures the request
    def csrf_token() -> str:
        """Get the CSRF token for this request."""
        return get_csrf_token(request)

    context = {
        "request": request,
        "user": user,
        "nav_items": nav_context.get("top_level_items", []),  # Keep for backward compatibility
        "nav": nav_context,  # Full navigation context
        "fmt_datetime": fmt_datetime,  # Datetime formatter function
        "csrf_token": csrf_token,  # CSRF token getter function
        **kwargs,
    }

    return context
