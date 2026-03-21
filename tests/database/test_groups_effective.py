"""Tests for database.groups.effective module.

Integration tests for trunk group names and access-relevant group names
queries using the group_lineage closure table.
"""

from uuid import uuid4

import database

# =============================================================================
# Helpers
# =============================================================================


def _create_group(tenant_id, name, **kwargs):
    """Create a group and return a dict with id and name."""
    result = database.groups.create_group(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        **kwargs,
    )
    # create_group only returns {"id": ...}, so attach the name for convenience
    result["name"] = name
    return result


def _add_member(tenant_id, group_id, user_id):
    """Add a user to a group."""
    return database.groups.add_group_member(tenant_id, str(tenant_id), group_id, str(user_id))


def _add_relationship(tenant_id, parent_id, child_id):
    """Create a parent-child relationship between groups."""
    return database.groups.add_group_relationship(
        tenant_id, str(tenant_id), str(parent_id), str(child_id)
    )


def _create_sp(tenant_id, user_id, name="Test SP"):
    """Create a service provider."""
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )


def _assign_sp_to_group(tenant_id, sp_id, group_id, user_id):
    """Create an SP-group assignment."""
    return database.sp_group_assignments.create_assignment(
        tenant_id, str(tenant_id), sp_id, group_id, str(user_id)
    )


# =============================================================================
# get_effective_group_names
# =============================================================================


def test_get_effective_group_names_direct(test_tenant, test_user):
    """Direct membership returns that group name."""
    group = _create_group(test_tenant["id"], f"Direct-{uuid4().hex[:8]}")
    _add_member(test_tenant["id"], group["id"], test_user["id"])

    names = database.groups.get_effective_group_names(test_tenant["id"], str(test_user["id"]))

    assert group["name"] in names


def test_get_effective_group_names_inherited(test_tenant, test_user):
    """Membership in child also includes ancestor group names."""
    parent = _create_group(test_tenant["id"], f"Parent-{uuid4().hex[:8]}")
    child = _create_group(test_tenant["id"], f"Child-{uuid4().hex[:8]}")
    _add_relationship(test_tenant["id"], parent["id"], child["id"])
    _add_member(test_tenant["id"], child["id"], test_user["id"])

    names = database.groups.get_effective_group_names(test_tenant["id"], str(test_user["id"]))

    assert parent["name"] in names
    assert child["name"] in names


# =============================================================================
# get_trunk_group_names
# =============================================================================


def test_get_trunk_group_names_single_root(test_tenant, test_user):
    """User in a leaf group: trunk is the root of the chain."""
    root = _create_group(test_tenant["id"], f"Root-{uuid4().hex[:8]}")
    mid = _create_group(test_tenant["id"], f"Mid-{uuid4().hex[:8]}")
    leaf = _create_group(test_tenant["id"], f"Leaf-{uuid4().hex[:8]}")
    _add_relationship(test_tenant["id"], root["id"], mid["id"])
    _add_relationship(test_tenant["id"], mid["id"], leaf["id"])
    _add_member(test_tenant["id"], leaf["id"], test_user["id"])

    trunk = database.groups.get_trunk_group_names(test_tenant["id"], str(test_user["id"]))

    # The root is the topmost group in the user's effective set
    assert root["name"] in trunk
    # Mid and leaf are not trunk (they have ancestors in the effective set)
    assert mid["name"] not in trunk
    assert leaf["name"] not in trunk


def test_get_trunk_group_names_multiple_branches(test_tenant, test_user):
    """User in two separate hierarchies returns both roots as trunk."""
    root_a = _create_group(test_tenant["id"], f"RootA-{uuid4().hex[:8]}")
    leaf_a = _create_group(test_tenant["id"], f"LeafA-{uuid4().hex[:8]}")
    _add_relationship(test_tenant["id"], root_a["id"], leaf_a["id"])

    root_b = _create_group(test_tenant["id"], f"RootB-{uuid4().hex[:8]}")
    leaf_b = _create_group(test_tenant["id"], f"LeafB-{uuid4().hex[:8]}")
    _add_relationship(test_tenant["id"], root_b["id"], leaf_b["id"])

    _add_member(test_tenant["id"], leaf_a["id"], test_user["id"])
    _add_member(test_tenant["id"], leaf_b["id"], test_user["id"])

    trunk = database.groups.get_trunk_group_names(test_tenant["id"], str(test_user["id"]))

    assert root_a["name"] in trunk
    assert root_b["name"] in trunk
    assert leaf_a["name"] not in trunk
    assert leaf_b["name"] not in trunk


def test_get_trunk_group_names_flat_group(test_tenant, test_user):
    """User in a group with no parents: that group itself is trunk."""
    standalone = _create_group(test_tenant["id"], f"Standalone-{uuid4().hex[:8]}")
    _add_member(test_tenant["id"], standalone["id"], test_user["id"])

    trunk = database.groups.get_trunk_group_names(test_tenant["id"], str(test_user["id"]))

    assert standalone["name"] in trunk


def test_get_trunk_group_names_no_memberships(test_tenant, test_user):
    """User with no group memberships returns empty list."""
    trunk = database.groups.get_trunk_group_names(test_tenant["id"], str(test_user["id"]))

    assert trunk == []


# =============================================================================
# get_access_relevant_group_names
# =============================================================================


def test_get_access_relevant_group_names_direct_match(test_tenant, test_user):
    """User in a group directly assigned to SP returns that group name."""
    sp = _create_sp(test_tenant["id"], test_user["id"], f"SP-{uuid4().hex[:8]}")
    group = _create_group(test_tenant["id"], f"Access-{uuid4().hex[:8]}")
    _add_member(test_tenant["id"], group["id"], test_user["id"])
    _assign_sp_to_group(test_tenant["id"], sp["id"], group["id"], test_user["id"])

    names = database.groups.get_access_relevant_group_names(
        test_tenant["id"], str(test_user["id"]), str(sp["id"])
    )

    assert group["name"] in names


def test_get_access_relevant_group_names_child_of_assigned(test_tenant, test_user):
    """User in child of assigned group returns both child and parent."""
    sp = _create_sp(test_tenant["id"], test_user["id"], f"SP-{uuid4().hex[:8]}")
    parent = _create_group(test_tenant["id"], f"AssignedParent-{uuid4().hex[:8]}")
    child = _create_group(test_tenant["id"], f"ChildOfAssigned-{uuid4().hex[:8]}")
    _add_relationship(test_tenant["id"], parent["id"], child["id"])
    _add_member(test_tenant["id"], child["id"], test_user["id"])
    _assign_sp_to_group(test_tenant["id"], sp["id"], parent["id"], test_user["id"])

    names = database.groups.get_access_relevant_group_names(
        test_tenant["id"], str(test_user["id"]), str(sp["id"])
    )

    # Both the assigned parent and the user's child group are access-relevant
    assert parent["name"] in names
    assert child["name"] in names


def test_get_access_relevant_group_names_no_match(test_tenant, test_user):
    """User with groups not assigned to SP returns empty list."""
    sp = _create_sp(test_tenant["id"], test_user["id"], f"SP-{uuid4().hex[:8]}")
    group = _create_group(test_tenant["id"], f"Unrelated-{uuid4().hex[:8]}")
    _add_member(test_tenant["id"], group["id"], test_user["id"])
    # No sp_group_assignment for this group

    names = database.groups.get_access_relevant_group_names(
        test_tenant["id"], str(test_user["id"]), str(sp["id"])
    )

    assert names == []


def test_get_access_relevant_group_names_no_memberships(test_tenant, test_user):
    """User with no group memberships returns empty list."""
    sp = _create_sp(test_tenant["id"], test_user["id"], f"SP-{uuid4().hex[:8]}")

    names = database.groups.get_access_relevant_group_names(
        test_tenant["id"], str(test_user["id"]), str(sp["id"])
    )

    assert names == []


def test_get_access_relevant_group_names_multiple_assigned(test_tenant, test_user):
    """User in multiple groups, some assigned to SP, returns only relevant ones."""
    sp = _create_sp(test_tenant["id"], test_user["id"], f"SP-{uuid4().hex[:8]}")
    relevant = _create_group(test_tenant["id"], f"Relevant-{uuid4().hex[:8]}")
    irrelevant = _create_group(test_tenant["id"], f"Irrelevant-{uuid4().hex[:8]}")
    _add_member(test_tenant["id"], relevant["id"], test_user["id"])
    _add_member(test_tenant["id"], irrelevant["id"], test_user["id"])
    _assign_sp_to_group(test_tenant["id"], sp["id"], relevant["id"], test_user["id"])

    names = database.groups.get_access_relevant_group_names(
        test_tenant["id"], str(test_user["id"]), str(sp["id"])
    )

    assert relevant["name"] in names
    assert irrelevant["name"] not in names
