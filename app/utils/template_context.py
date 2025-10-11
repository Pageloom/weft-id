"""Template context helpers for adding common data to templates."""

from fastapi import Request

from pages import get_nav_items
from utils.auth import get_current_user


def get_template_context(request: Request, tenant_id: str, **kwargs):
    """Get common template context including user and navigation."""
    user = get_current_user(request, tenant_id)

    context = {
        'request': request,
        'user': user,
        'nav_items': [],
        **kwargs
    }

    if user:
        # Get navigation items based on user's role
        context['nav_items'] = get_nav_items(user.get('role'))

    return context
