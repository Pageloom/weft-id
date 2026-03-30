"""Validation helpers for users service.

These private helpers enforce business rules for user operations.
"""

import logging

import database
from services.exceptions import ForbiddenError, ValidationError
from services.types import RequestingUser

logger = logging.getLogger(__name__)


def _validate_role_change(
    tenant_id: str,
    user: dict,
    new_role: str | None,
    requesting_user: RequestingUser,
) -> None:
    """Validate role change restrictions on user update.

    Checks that only super_admin can change to/from admin/super_admin,
    and prevents demoting the last super_admin.
    """
    if new_role is None:
        return

    current_role = user["role"]

    # Only super_admin can change to/from super_admin or admin
    if (new_role in ("admin", "super_admin") or current_role == "super_admin") and requesting_user[
        "role"
    ] != "super_admin":
        logger.warning(
            "Authorization denied: user %s (role=%s) attempted role change %s -> %s on user %s",
            requesting_user["id"],
            requesting_user["role"],
            current_role,
            new_role,
            user["id"],
        )
        raise ForbiddenError(
            message="Only super_admin can change admin or super_admin roles",
            code="super_admin_role_change_denied",
            required_role="super_admin",
        )

    # Prevent demoting the last super_admin
    if current_role == "super_admin" and new_role != "super_admin":
        super_admin_count = database.users.count_active_super_admins(tenant_id)
        if super_admin_count <= 1:
            raise ValidationError(
                message="Cannot demote the last super_admin",
                code="last_super_admin",
            )
