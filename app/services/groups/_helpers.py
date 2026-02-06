"""Validation guards for groups service.

These private helpers enforce business rules for group operations.
"""

from services.exceptions import ForbiddenError


def _is_idp_group(group: dict) -> bool:
    """Check if a group is managed by an IdP (read-only)."""
    return group.get("group_type") == "idp"


def _require_not_idp_group(group: dict, operation: str) -> None:
    """Raise ForbiddenError if trying to modify an IdP-managed group."""
    if _is_idp_group(group):
        raise ForbiddenError(
            message=f"Cannot {operation}: this group is managed by an identity provider",
            code="idp_group_readonly",
        )
