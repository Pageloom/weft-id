"""Group database operations with transactional lineage maintenance."""

from database.groups.core import (
    create_group,
    delete_group,
    get_group_by_id,
    get_group_by_name,
    get_weftid_group_by_name,
    update_group,
)
from database.groups.effective import (
    count_effective_members,
    get_effective_members,
    get_effective_memberships,
    get_user_groups_with_context,
)
from database.groups.idp import (
    bulk_add_user_to_groups,
    bulk_remove_user_from_groups,
    create_idp_group,
    get_group_by_idp_and_name,
    get_groups_by_idp,
    get_idp_base_group_id,
    get_user_idp_group_ids,
    invalidate_groups_by_idp,
)
from database.groups.lineage import (
    get_group_ancestors,
    get_group_descendants,
    is_ancestor_of,
)
from database.groups.listing import count_groups, list_groups
from database.groups.memberships import (
    add_group_member,
    bulk_add_group_members,
    count_group_members,
    get_group_members,
    get_user_groups,
    is_group_member,
    remove_group_member,
)
from database.groups.relationships import (
    add_group_relationship,
    get_group_children,
    get_group_parents,
    relationship_exists,
    remove_group_relationship,
    would_create_cycle,
)
from database.groups.selection import (
    get_groups_for_child_select,
    get_groups_for_parent_select,
    get_groups_for_user_select,
)

__all__ = [
    # core
    "get_group_by_id",
    "get_group_by_name",
    "get_weftid_group_by_name",
    "create_group",
    "update_group",
    "delete_group",
    # listing
    "count_groups",
    "list_groups",
    # memberships
    "get_group_members",
    "count_group_members",
    "is_group_member",
    "add_group_member",
    "bulk_add_group_members",
    "remove_group_member",
    "get_user_groups",
    # effective membership
    "get_user_groups_with_context",
    "get_effective_memberships",
    "get_effective_members",
    "count_effective_members",
    # relationships
    "would_create_cycle",
    "relationship_exists",
    "add_group_relationship",
    "remove_group_relationship",
    "get_group_parents",
    "get_group_children",
    # lineage
    "get_group_ancestors",
    "get_group_descendants",
    "is_ancestor_of",
    # selection
    "get_groups_for_user_select",
    "get_groups_for_parent_select",
    "get_groups_for_child_select",
    # idp
    "get_idp_base_group_id",
    "get_groups_by_idp",
    "get_group_by_idp_and_name",
    "create_idp_group",
    "invalidate_groups_by_idp",
    "get_user_idp_group_ids",
    "bulk_add_user_to_groups",
    "bulk_remove_user_from_groups",
]
