"""Group service layer.

This package provides business logic for group management:
- Group CRUD operations
- User membership management
- Hierarchical relationships with cycle detection
- IdP group synchronization

All functions:
- Receive a RequestingUser for authorization
- Return Pydantic models from app/schemas/groups.py
- Raise ServiceError subclasses on failures
- Log events after successful writes
- Track activity for reads

This module re-exports all public functions for backwards compatibility.
Existing code using `from services import groups` will continue to work.
"""

# Re-export converters for backwards compatibility
# Some tests directly import these
from services.groups._converters import (
    _row_to_detail,
    _row_to_member,
    _row_to_relationship,
    _row_to_summary,
)

# Re-export helpers for backwards compatibility
from services.groups._helpers import (
    _is_idp_group,
    _require_not_idp_group,
)

# Re-export from crud module
from services.groups.crud import (
    create_group,
    delete_group,
    get_group,
    list_groups,
    update_group,
)

# Re-export from hierarchy module
from services.groups.hierarchy import (
    add_child,
    list_children,
    list_parents,
    remove_child,
)

# Re-export from idp module
from services.groups.idp import (
    _apply_membership_additions,
    _apply_membership_removals,
    create_idp_base_group,
    get_or_create_idp_group,
    invalidate_idp_groups,
    list_groups_for_idp,
    sync_user_idp_groups,
)

# Re-export from membership module
from services.groups.membership import (
    add_member,
    list_members,
    remove_member,
)

# Re-export from selection module
from services.groups.selection import (
    list_available_children,
    list_available_parents,
    list_available_users_for_group,
)

# Re-export from utilities module
from services.groups.utilities import (
    get_user_group_ids,
)

__all__ = [
    # CRUD
    "create_group",
    "delete_group",
    "get_group",
    "list_groups",
    "update_group",
    # Membership
    "add_member",
    "list_members",
    "remove_member",
    # Hierarchy
    "add_child",
    "list_children",
    "list_parents",
    "remove_child",
    # Selection
    "list_available_children",
    "list_available_parents",
    "list_available_users_for_group",
    # Utilities
    "get_user_group_ids",
    # IdP
    "create_idp_base_group",
    "get_or_create_idp_group",
    "invalidate_idp_groups",
    "list_groups_for_idp",
    "sync_user_idp_groups",
    # Private (for backwards compatibility)
    "_apply_membership_additions",
    "_apply_membership_removals",
    "_is_idp_group",
    "_require_not_idp_group",
    "_row_to_detail",
    "_row_to_member",
    "_row_to_relationship",
    "_row_to_summary",
]
