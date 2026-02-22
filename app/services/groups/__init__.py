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
    _row_to_member_detail,
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
    get_group_graph_data,
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
    ensure_user_in_base_group,
    ensure_users_in_base_group,
    get_or_create_idp_group,
    invalidate_idp_groups,
    list_groups_for_idp,
    move_users_between_idps,
    remove_user_from_all_idp_groups,
    remove_user_from_base_group,
    sync_user_idp_groups,
)

# Re-export from layout module
from services.groups.layout import get_graph_layout as get_graph_layout_for_user
from services.groups.layout import save_graph_layout

# Re-export from membership module
from services.groups.membership import (
    add_member,
    bulk_add_members,
    bulk_add_user_to_groups,
    bulk_remove_members,
    get_direct_memberships,
    get_effective_members,
    get_effective_memberships,
    get_my_groups,
    list_members,
    list_members_filtered,
    remove_member,
)

# Re-export from selection module
from services.groups.selection import (
    list_available_children,
    list_available_groups_for_user,
    list_available_parents,
    list_available_users_for_group,
    list_available_users_paginated,
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
    "get_group_graph_data",
    "list_groups",
    "update_group",
    # Membership
    "add_member",
    "bulk_add_members",
    "bulk_add_user_to_groups",
    "bulk_remove_members",
    "get_direct_memberships",
    "get_effective_members",
    "get_effective_memberships",
    "get_my_groups",
    "list_members",
    "list_members_filtered",
    "remove_member",
    # Hierarchy
    "add_child",
    "list_children",
    "list_parents",
    "remove_child",
    # Selection
    "list_available_children",
    "list_available_groups_for_user",
    "list_available_parents",
    "list_available_users_for_group",
    "list_available_users_paginated",
    # Layout
    "get_graph_layout_for_user",
    "save_graph_layout",
    # Utilities
    "get_user_group_ids",
    # IdP
    "create_idp_base_group",
    "ensure_user_in_base_group",
    "ensure_users_in_base_group",
    "get_or_create_idp_group",
    "invalidate_idp_groups",
    "list_groups_for_idp",
    "move_users_between_idps",
    "remove_user_from_all_idp_groups",
    "remove_user_from_base_group",
    "sync_user_idp_groups",
    # Private (for backwards compatibility)
    "_apply_membership_additions",
    "_apply_membership_removals",
    "_is_idp_group",
    "_require_not_idp_group",
    "_row_to_detail",
    "_row_to_member",
    "_row_to_member_detail",
    "_row_to_relationship",
    "_row_to_summary",
]
