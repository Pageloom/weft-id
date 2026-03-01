"""Validation guards for groups service.

These private helpers enforce business rules for group operations.
"""

import database
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


def _is_idp_umbrella_group(tenant_id: str, group: dict) -> bool:
    """Check if a group is the umbrella (base) group for its IdP.

    The umbrella group has the same name as the IdP and serves as the root
    of the IdP group hierarchy.
    """
    if not _is_idp_group(group):
        return False
    idp_id = group.get("idp_id")
    if not idp_id:
        return False
    base_group_id = database.groups.get_idp_base_group_id(tenant_id, idp_id)
    return base_group_id is not None and str(group.get("id")) == base_group_id


def _is_idp_managed_relationship(tenant_id: str, parent: dict, child: dict) -> bool:
    """Check if a parent-child relationship is managed by the IdP system.

    Returns True when parent is the umbrella group for an IdP and child is
    an IdP group of the same IdP. These relationships are created automatically
    during authentication and should not be removed manually.
    """
    if not _is_idp_group(parent) or not _is_idp_group(child):
        return False
    parent_idp_id = parent.get("idp_id")
    child_idp_id = child.get("idp_id")
    if not parent_idp_id or parent_idp_id != child_idp_id:
        return False
    return _is_idp_umbrella_group(tenant_id, parent)
