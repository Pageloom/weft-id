"""Template context helpers for adding common data to templates."""

from fastapi import Request

from pages import get_navigation_context
from utils.auth import get_current_user


def get_template_context(request: Request, tenant_id: str, **kwargs):
    """Get common template context including user and navigation."""
    user = get_current_user(request, tenant_id)

    # Get the current path from the request
    current_path = request.url.path

    # Get navigation context
    nav_context = {}
    if user:
        nav_context = get_navigation_context(current_path, user.get('role'))

    context = {
        'request': request,
        'user': user,
        'nav_items': nav_context.get('top_level_items', []),  # Keep for backward compatibility
        'nav': nav_context,  # Full navigation context
        **kwargs
    }

    return context
