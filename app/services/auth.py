"""Authorization helpers for service layer.

This module provides centralized authorization checks for service functions.
All service modules should import from here rather than defining their own
authorization helpers.

Usage:
    from services.auth import require_admin, require_super_admin

    def some_admin_function(requesting_user: RequestingUser) -> ...:
        require_admin(requesting_user)
        # ... rest of function
"""

import logging

from services.exceptions import ForbiddenError
from services.types import RequestingUser

logger = logging.getLogger(__name__)


def require_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not admin or super_admin."""
    if user["role"] not in ("admin", "super_admin"):
        logger.warning(
            "Authorization denied: user %s (role=%s, tenant=%s) requires admin",
            user["id"],
            user["role"],
            user["tenant_id"],
        )
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )


def require_super_admin(user: RequestingUser) -> None:
    """Raise ForbiddenError if user is not super_admin."""
    if user["role"] != "super_admin":
        logger.warning(
            "Authorization denied: user %s (role=%s, tenant=%s) requires super_admin",
            user["id"],
            user["role"],
            user["tenant_id"],
        )
        raise ForbiddenError(
            message="Super admin access required",
            code="super_admin_required",
            required_role="super_admin",
        )
