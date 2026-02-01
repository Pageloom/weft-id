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

from services.event_log import log_event
from services.exceptions import ForbiddenError
from services.types import RequestingUser


def require_admin(
    user: RequestingUser,
    *,
    log_failure: bool = False,
    service_name: str | None = None,
) -> None:
    """
    Raise ForbiddenError if user is not admin or super_admin.

    Args:
        user: The requesting user to check
        log_failure: If True, log an authorization_denied event before raising
        service_name: Optional service name for logging context
    """
    if user["role"] not in ("admin", "super_admin"):
        if log_failure:
            log_event(
                tenant_id=user["tenant_id"],
                actor_user_id=user["id"],
                artifact_type="user",
                artifact_id=user["id"],
                event_type="authorization_denied",
                metadata={
                    "required_role": "admin",
                    "actual_role": user["role"],
                    "service": service_name or "unknown",
                },
            )
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )


def require_super_admin(
    user: RequestingUser,
    *,
    log_failure: bool = False,
    service_name: str | None = None,
) -> None:
    """
    Raise ForbiddenError if user is not super_admin.

    Args:
        user: The requesting user to check
        log_failure: If True, log an authorization_denied event before raising
        service_name: Optional service name for logging context
    """
    if user["role"] != "super_admin":
        if log_failure:
            log_event(
                tenant_id=user["tenant_id"],
                actor_user_id=user["id"],
                artifact_type="user",
                artifact_id=user["id"],
                event_type="authorization_denied",
                metadata={
                    "required_role": "super_admin",
                    "actual_role": user["role"],
                    "service": service_name or "unknown",
                },
            )
        raise ForbiddenError(
            message="Super admin access required",
            code="super_admin_required",
            required_role="super_admin",
        )
