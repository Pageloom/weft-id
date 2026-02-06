"""Validation helpers for users service.

These private helpers enforce business rules for user operations.
"""

import database
from services.event_log import log_event
from services.exceptions import ForbiddenError, ValidationError
from services.types import RequestingUser


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
        log_event(
            tenant_id=tenant_id,
            actor_user_id=requesting_user["id"],
            artifact_type="user",
            artifact_id=str(user["id"]),
            event_type="authorization_denied",
            metadata={
                "required_role": "super_admin",
                "actual_role": requesting_user["role"],
                "action": "role_change",
                "target_user_id": str(user["id"]),
                "current_role": current_role,
                "attempted_role": new_role,
            },
        )
        raise ForbiddenError(
            message="Only super_admin can change admin or super_admin roles",
            code="super_admin_role_change_denied",
            required_role="super_admin",
        )

    # Prevent demoting the last super_admin
    if current_role == "super_admin" and new_role != "super_admin":
        super_admins = database.users.list_users(
            tenant_id=tenant_id,
            search=None,
            sort_field="created_at",
            sort_order="asc",
            page=1,
            page_size=100,
        )
        super_admin_count = sum(1 for u in super_admins if u["role"] == "super_admin")
        if super_admin_count <= 1:
            raise ValidationError(
                message="Cannot demote the last super_admin",
                code="last_super_admin",
            )
