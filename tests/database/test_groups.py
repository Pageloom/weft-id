"""Tests for database.groups module.

These are integration tests that use a real database connection.
"""


def test_create_group(test_tenant):
    """Test creating a group."""
    import database

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Engineering Team",
        description="The engineering team",
    )

    assert result is not None
    assert "id" in result

    # Verify group was created
    group = database.groups.get_group_by_id(test_tenant["id"], result["id"])
    assert group is not None
    assert group["name"] == "Engineering Team"
    assert group["description"] == "The engineering team"
    assert group["group_type"] == "weftid"
    assert group["is_valid"] is True


def test_create_group_creates_self_lineage(test_tenant):
    """Test that creating a group also creates self-referential lineage entry."""
    import database

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Self Lineage Test",
    )

    # Check lineage table has self-reference
    lineage = database.fetchone(
        test_tenant["id"],
        """
        select * from group_lineage
        where ancestor_id = :group_id and descendant_id = :group_id
        """,
        {"group_id": result["id"]},
    )

    assert lineage is not None
    assert lineage["depth"] == 0


def test_get_group_by_id(test_tenant):
    """Test retrieving a group by ID."""
    import database

    # Create a group first
    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test Group",
    )

    group = database.groups.get_group_by_id(test_tenant["id"], result["id"])

    assert group is not None
    assert group["id"] == result["id"]
    assert group["name"] == "Test Group"
    assert group["member_count"] == 0
    assert group["parent_count"] == 0
    assert group["child_count"] == 0


def test_get_group_by_id_not_found(test_tenant):
    """Test retrieving a non-existent group returns None."""
    from uuid import uuid4

    import database

    group = database.groups.get_group_by_id(test_tenant["id"], str(uuid4()))

    assert group is None


def test_get_group_by_name(test_tenant):
    """Test retrieving a group by name."""
    import database

    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Named Group",
    )

    group = database.groups.get_group_by_name(test_tenant["id"], "Named Group")

    assert group is not None
    assert group["name"] == "Named Group"


def test_get_group_by_name_not_found(test_tenant):
    """Test retrieving a non-existent group by name returns None."""
    import database

    group = database.groups.get_group_by_name(test_tenant["id"], "Nonexistent")

    assert group is None


def test_list_groups(test_tenant):
    """Test listing groups."""
    import database

    # Create some groups
    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Group A",
    )
    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Group B",
    )

    groups = database.groups.list_groups(test_tenant["id"])

    assert len(groups) >= 2
    names = [g["name"] for g in groups]
    assert "Group A" in names
    assert "Group B" in names


def test_list_groups_with_search(test_tenant):
    """Test listing groups with search filter."""
    import database

    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Engineering",
        description="Tech team",
    )
    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Marketing",
        description="Marketing team",
    )

    # Search by name
    groups = database.groups.list_groups(test_tenant["id"], search="Engineer")
    assert len(groups) >= 1
    assert any(g["name"] == "Engineering" for g in groups)

    # Search by description
    groups = database.groups.list_groups(test_tenant["id"], search="Marketing")
    assert len(groups) >= 1


def test_count_groups(test_tenant):
    """Test counting groups."""
    import database

    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Count Test A",
    )
    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Count Test B",
    )

    count = database.groups.count_groups(test_tenant["id"])

    assert count >= 2


def test_update_group(test_tenant):
    """Test updating a group."""
    import database

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Original Name",
        description="Original description",
    )

    # Update the group
    rows = database.groups.update_group(
        tenant_id=test_tenant["id"],
        group_id=result["id"],
        name="Updated Name",
        description="Updated description",
    )

    assert rows > 0

    # Verify the update
    group = database.groups.get_group_by_id(test_tenant["id"], result["id"])
    assert group["name"] == "Updated Name"
    assert group["description"] == "Updated description"


def test_delete_group(test_tenant):
    """Test deleting a group."""
    import database

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="To Delete",
    )

    # Delete the group
    rows = database.groups.delete_group(test_tenant["id"], result["id"])
    assert rows == 1

    # Verify it's gone
    group = database.groups.get_group_by_id(test_tenant["id"], result["id"])
    assert group is None


# =============================================================================
# Membership Tests
# =============================================================================


def test_add_group_member(test_tenant, test_user):
    """Test adding a user to a group."""
    import database

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Membership Test",
    )

    membership = database.groups.add_group_member(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        group_id=result["id"],
        user_id=str(test_user["id"]),
    )

    assert membership is not None
    assert "id" in membership


def test_is_group_member(test_tenant, test_user):
    """Test checking group membership."""
    import database

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Membership Check",
    )

    # Not a member yet
    assert not database.groups.is_group_member(
        test_tenant["id"], result["id"], str(test_user["id"])
    )

    # Add as member
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), result["id"], str(test_user["id"])
    )

    # Now is a member
    assert database.groups.is_group_member(test_tenant["id"], result["id"], str(test_user["id"]))


def test_remove_group_member(test_tenant, test_user):
    """Test removing a user from a group."""
    import database

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Remove Member Test",
    )

    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), result["id"], str(test_user["id"])
    )

    # Remove member
    rows = database.groups.remove_group_member(
        test_tenant["id"], result["id"], str(test_user["id"])
    )

    assert rows == 1
    assert not database.groups.is_group_member(
        test_tenant["id"], result["id"], str(test_user["id"])
    )


def test_get_group_members(test_tenant, test_user, test_admin_user):
    """Test getting group members."""
    import database

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Members List Test",
    )

    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), result["id"], str(test_user["id"])
    )
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), result["id"], str(test_admin_user["id"])
    )

    members = database.groups.get_group_members(test_tenant["id"], result["id"])

    assert len(members) == 2
    user_ids = [str(m["user_id"]) for m in members]
    assert str(test_user["id"]) in user_ids
    assert str(test_admin_user["id"]) in user_ids


def test_count_group_members(test_tenant, test_user):
    """Test counting group members."""
    import database

    result = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Count Members Test",
    )

    assert database.groups.count_group_members(test_tenant["id"], result["id"]) == 0

    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), result["id"], str(test_user["id"])
    )

    assert database.groups.count_group_members(test_tenant["id"], result["id"]) == 1


def test_get_user_groups(test_tenant, test_user):
    """Test getting groups a user belongs to."""
    import database

    group1 = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="User Group 1",
    )
    group2 = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="User Group 2",
    )

    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), group1["id"], str(test_user["id"])
    )
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), group2["id"], str(test_user["id"])
    )

    groups = database.groups.get_user_groups(test_tenant["id"], str(test_user["id"]))

    assert len(groups) == 2
    names = [g["name"] for g in groups]
    assert "User Group 1" in names
    assert "User Group 2" in names


# =============================================================================
# Relationship Tests (with lineage)
# =============================================================================


def test_add_group_relationship(test_tenant):
    """Test adding a parent-child relationship."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Parent Group",
    )
    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Child Group",
    )

    result = database.groups.add_group_relationship(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        parent_group_id=parent["id"],
        child_group_id=child["id"],
    )

    assert result is not None
    assert "id" in result


def test_add_group_relationship_creates_lineage(test_tenant):
    """Test that adding a relationship updates the lineage table."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Lineage Parent",
    )
    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Lineage Child",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], child["id"]
    )

    # Verify lineage entry was created
    lineage = database.fetchone(
        test_tenant["id"],
        """
        select * from group_lineage
        where ancestor_id = :parent_id and descendant_id = :child_id
        """,
        {"parent_id": parent["id"], "child_id": child["id"]},
    )

    assert lineage is not None
    assert lineage["depth"] == 1


def test_transitive_lineage(test_tenant):
    """Test that transitive relationships are captured in lineage."""
    import database

    # Create A -> B -> C hierarchy
    group_a = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Group A",
    )
    group_b = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Group B",
    )
    group_c = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Group C",
    )

    # A -> B
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_a["id"], group_b["id"]
    )
    # B -> C
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_b["id"], group_c["id"]
    )

    # Verify A -> C transitive relationship exists with depth 2
    lineage = database.fetchone(
        test_tenant["id"],
        """
        select * from group_lineage
        where ancestor_id = :a_id and descendant_id = :c_id
        """,
        {"a_id": group_a["id"], "c_id": group_c["id"]},
    )

    assert lineage is not None
    assert lineage["depth"] == 2


def test_would_create_cycle(test_tenant):
    """Test cycle detection."""
    import database

    # Create A -> B -> C hierarchy
    group_a = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Cycle A",
    )
    group_b = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Cycle B",
    )
    group_c = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Cycle C",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_a["id"], group_b["id"]
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_b["id"], group_c["id"]
    )

    # C -> A would create a cycle
    assert database.groups.would_create_cycle(test_tenant["id"], group_c["id"], group_a["id"])

    # A -> D (new group) would not create a cycle
    group_d = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Cycle D",
    )
    assert not database.groups.would_create_cycle(test_tenant["id"], group_a["id"], group_d["id"])


def test_relationship_exists(test_tenant):
    """Test checking if a direct relationship exists."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Exists Parent",
    )
    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Exists Child",
    )

    assert not database.groups.relationship_exists(test_tenant["id"], parent["id"], child["id"])

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], child["id"]
    )

    assert database.groups.relationship_exists(test_tenant["id"], parent["id"], child["id"])


def test_remove_group_relationship(test_tenant):
    """Test removing a parent-child relationship."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Remove Parent",
    )
    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Remove Child",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], child["id"]
    )

    rows = database.groups.remove_group_relationship(test_tenant["id"], parent["id"], child["id"])

    assert rows == 1
    assert not database.groups.relationship_exists(test_tenant["id"], parent["id"], child["id"])


def test_get_group_parents(test_tenant):
    """Test getting parent groups."""
    import database

    parent1 = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Multi Parent 1",
    )
    parent2 = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Multi Parent 2",
    )
    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Multi Child",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent1["id"], child["id"]
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent2["id"], child["id"]
    )

    parents = database.groups.get_group_parents(test_tenant["id"], child["id"])

    assert len(parents) == 2
    names = [p["name"] for p in parents]
    assert "Multi Parent 1" in names
    assert "Multi Parent 2" in names


def test_get_group_children(test_tenant):
    """Test getting child groups."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Parent With Children",
    )
    child1 = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Child 1",
    )
    child2 = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Child 2",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], child1["id"]
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], child2["id"]
    )

    children = database.groups.get_group_children(test_tenant["id"], parent["id"])

    assert len(children) == 2
    names = [c["name"] for c in children]
    assert "Child 1" in names
    assert "Child 2" in names


def test_get_group_ancestors(test_tenant):
    """Test getting all ancestors via lineage table."""
    import database

    # Create A -> B -> C hierarchy
    group_a = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Ancestor A",
    )
    group_b = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Ancestor B",
    )
    group_c = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Ancestor C",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_a["id"], group_b["id"]
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_b["id"], group_c["id"]
    )

    ancestors = database.groups.get_group_ancestors(test_tenant["id"], group_c["id"])

    assert len(ancestors) == 2
    names = [a["name"] for a in ancestors]
    assert "Ancestor A" in names
    assert "Ancestor B" in names
    # Should be ordered by depth (B first, then A)
    assert ancestors[0]["depth"] == 1
    assert ancestors[1]["depth"] == 2


def test_get_group_descendants(test_tenant):
    """Test getting all descendants via lineage table."""
    import database

    # Create A -> B -> C hierarchy
    group_a = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Desc A",
    )
    group_b = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Desc B",
    )
    group_c = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Desc C",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_a["id"], group_b["id"]
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_b["id"], group_c["id"]
    )

    descendants = database.groups.get_group_descendants(test_tenant["id"], group_a["id"])

    assert len(descendants) == 2
    names = [d["name"] for d in descendants]
    assert "Desc B" in names
    assert "Desc C" in names


def test_is_ancestor_of(test_tenant):
    """Test checking ancestor relationship via lineage table."""
    import database

    group_a = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Is Ancestor A",
    )
    group_b = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Is Ancestor B",
    )
    group_c = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Is Ancestor C",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_a["id"], group_b["id"]
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_b["id"], group_c["id"]
    )

    # A is ancestor of B and C
    assert database.groups.is_ancestor_of(test_tenant["id"], group_a["id"], group_b["id"])
    assert database.groups.is_ancestor_of(test_tenant["id"], group_a["id"], group_c["id"])

    # B is ancestor of C but not A
    assert database.groups.is_ancestor_of(test_tenant["id"], group_b["id"], group_c["id"])
    assert not database.groups.is_ancestor_of(test_tenant["id"], group_b["id"], group_a["id"])

    # C is not ancestor of anything
    assert not database.groups.is_ancestor_of(test_tenant["id"], group_c["id"], group_a["id"])


def test_dag_allows_multiple_parents(test_tenant):
    """Test that DAG model allows groups to have multiple parents."""
    import database

    # Diamond: A and B both parents of C
    #     A     B
    #      \   /
    #        C
    group_a = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="DAG A",
    )
    group_b = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="DAG B",
    )
    group_c = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="DAG C",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_a["id"], group_c["id"]
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_b["id"], group_c["id"]
    )

    parents = database.groups.get_group_parents(test_tenant["id"], group_c["id"])
    assert len(parents) == 2


def test_dag_allows_shared_descendants(test_tenant):
    """Test that A and B can both be parents of C, and A can become parent of B."""
    import database

    # This is allowed in a DAG:
    #     A
    #    / \
    #   B   |
    #    \ /
    #     C
    group_a = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Shared A",
    )
    group_b = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Shared B",
    )
    group_c = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Shared C",
    )

    # A -> C, B -> C
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_a["id"], group_c["id"]
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_b["id"], group_c["id"]
    )

    # A -> B is allowed (B already has C as child)
    assert not database.groups.would_create_cycle(test_tenant["id"], group_a["id"], group_b["id"])

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), group_a["id"], group_b["id"]
    )

    # Verify the structure
    children_of_a = database.groups.get_group_children(test_tenant["id"], group_a["id"])
    assert len(children_of_a) == 2  # B and C


# =============================================================================
# Bulk Operations Tests
# =============================================================================


def test_get_groups_for_child_select(test_tenant):
    """Test getting groups that can be children of a given group."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Select Parent",
    )
    existing_child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Existing Child",
    )
    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Potential Child",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], existing_child["id"]
    )

    available = database.groups.get_groups_for_child_select(test_tenant["id"], parent["id"])

    names = [g["name"] for g in available]
    # Should not include parent itself or existing child
    assert "Select Parent" not in names
    assert "Existing Child" not in names
    # Should include potential child
    assert "Potential Child" in names


def test_get_groups_for_parent_select(test_tenant):
    """Test getting groups that can be parents of a given group."""
    import database

    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Select Child",
    )
    existing_parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Existing Parent",
    )
    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Potential Parent",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), existing_parent["id"], child["id"]
    )

    available = database.groups.get_groups_for_parent_select(test_tenant["id"], child["id"])

    names = [g["name"] for g in available]
    # Should not include child itself or existing parent
    assert "Select Child" not in names
    assert "Existing Parent" not in names
    # Should include potential parent
    assert "Potential Parent" in names


# =============================================================================
# Effective Membership Tests
# =============================================================================


def test_get_user_groups_with_context_no_parents(test_tenant, test_user):
    """Test getting user groups with context when groups have no parents."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Context Test Group",
    )

    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), group["id"], str(test_user["id"])
    )

    groups = database.groups.get_user_groups_with_context(test_tenant["id"], str(test_user["id"]))

    assert len(groups) == 1
    assert groups[0]["name"] == "Context Test Group"
    assert groups[0]["parent_names"] is None


def test_get_user_groups_with_context_with_parents(test_tenant, test_user):
    """Test getting user groups with context shows parent names."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Parent Context",
    )
    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Child Context",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], child["id"]
    )
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), child["id"], str(test_user["id"])
    )

    groups = database.groups.get_user_groups_with_context(test_tenant["id"], str(test_user["id"]))

    assert len(groups) == 1
    assert groups[0]["name"] == "Child Context"
    assert groups[0]["parent_names"] == "Parent Context"


def test_get_effective_memberships_direct_and_inherited(test_tenant, test_user):
    """Test effective memberships include both direct and ancestor groups."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Effective Parent",
    )
    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Effective Child",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], child["id"]
    )

    # User is a direct member of child only
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), child["id"], str(test_user["id"])
    )

    memberships = database.groups.get_effective_memberships(test_tenant["id"], str(test_user["id"]))

    names = {m["name"] for m in memberships}
    assert "Effective Child" in names
    assert "Effective Parent" in names

    # Check is_direct flags
    for m in memberships:
        if m["name"] == "Effective Child":
            assert m["is_direct"] is True
        elif m["name"] == "Effective Parent":
            assert m["is_direct"] is False


def test_get_effective_members_direct_and_inherited(test_tenant, test_user, test_admin_user):
    """Test effective members include direct and inherited via descendants."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="EM Parent",
    )
    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="EM Child",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], child["id"]
    )

    # test_user in parent (direct), test_admin_user in child (inherited for parent)
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], str(test_user["id"])
    )
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), child["id"], str(test_admin_user["id"])
    )

    members = database.groups.get_effective_members(test_tenant["id"], parent["id"])

    user_ids = {str(m["user_id"]) for m in members}
    assert str(test_user["id"]) in user_ids
    assert str(test_admin_user["id"]) in user_ids

    # Check is_direct flags
    for m in members:
        if str(m["user_id"]) == str(test_user["id"]):
            assert m["is_direct"] is True
        elif str(m["user_id"]) == str(test_admin_user["id"]):
            assert m["is_direct"] is False


def test_count_effective_members(test_tenant, test_user, test_admin_user):
    """Test counting effective members."""
    import database

    parent = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Count EM Parent",
    )
    child = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Count EM Child",
    )

    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], child["id"]
    )

    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), parent["id"], str(test_user["id"])
    )
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), child["id"], str(test_admin_user["id"])
    )

    count = database.groups.count_effective_members(test_tenant["id"], parent["id"])

    assert count == 2


def test_bulk_add_group_members(test_tenant, test_user, test_admin_user):
    """Test bulk adding members to a group."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Bulk Add Test",
    )

    count = database.groups.bulk_add_group_members(
        test_tenant["id"],
        str(test_tenant["id"]),
        group["id"],
        [str(test_user["id"]), str(test_admin_user["id"])],
    )

    assert count == 2
    assert database.groups.count_group_members(test_tenant["id"], group["id"]) == 2


def test_bulk_add_group_members_duplicates(test_tenant, test_user):
    """Test bulk adding members skips duplicates."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Bulk Dup Test",
    )

    # Add user first
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), group["id"], str(test_user["id"])
    )

    # Try to bulk add the same user
    count = database.groups.bulk_add_group_members(
        test_tenant["id"],
        str(test_tenant["id"]),
        group["id"],
        [str(test_user["id"])],
    )

    assert count == 0
    assert database.groups.count_group_members(test_tenant["id"], group["id"]) == 1


def test_bulk_add_group_members_empty_list(test_tenant):
    """Test bulk adding with empty list returns 0."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Bulk Empty Test",
    )

    count = database.groups.bulk_add_group_members(
        test_tenant["id"],
        str(test_tenant["id"]),
        group["id"],
        [],
    )

    assert count == 0


# =============================================================================
# Search, Filter, and Bulk Remove Tests
# (search_group_members, count_group_members_filtered, search_available_users,
#  count_available_users, bulk_remove_group_members)
# =============================================================================

# Pre-computed argon2 hash reused for quick user creation in search tests
_SEARCH_TEST_PW = (
    "$argon2id$v=19$m=65536,t=3,p=4$WIhSoX0J3BrSyeyhzWPUdA$"
    "XhgXtxJyazeshxAIXw91bA0OXmrY/p0MydMEKzoZPP8"
)


def _make_search_user(
    tenant_id,
    first_name,
    last_name,
    role="member",
    is_inactivated=False,
    is_anonymized=False,
):
    """Create a user with a primary verified email for search/filter tests."""
    from uuid import uuid4

    import database

    suffix = str(uuid4())[:8]
    email = f"{first_name.lower()}-{suffix}@example.com"

    user = database.fetchone(
        tenant_id,
        """
        INSERT INTO users (
            tenant_id, password_hash, first_name, last_name, role,
            is_inactivated, is_anonymized
        ) VALUES (
            :tenant_id, :password_hash, :first_name, :last_name, :role,
            :is_inactivated, :is_anonymized
        ) RETURNING id, first_name, last_name, role
        """,
        {
            "tenant_id": tenant_id,
            "password_hash": _SEARCH_TEST_PW,
            "first_name": first_name,
            "last_name": last_name,
            "role": role,
            "is_inactivated": is_inactivated,
            "is_anonymized": is_anonymized,
        },
    )

    database.execute(
        tenant_id,
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": tenant_id, "user_id": user["id"], "email": email},
    )

    user["email"] = email
    return user


# -- search_group_members -----------------------------------------------------


def test_search_group_members_no_filters(test_tenant):
    """Test search_group_members returns members with extended info."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Search Members Test",
    )

    alice = _make_search_user(test_tenant["id"], "Alice", "Anderson")
    bob = _make_search_user(test_tenant["id"], "Bob", "Brown", role="admin")

    for u in [alice, bob]:
        database.groups.add_group_member(
            test_tenant["id"], str(test_tenant["id"]), group["id"], str(u["id"])
        )

    results = database.groups.search_group_members(test_tenant["id"], group["id"])

    assert len(results) == 2
    for r in results:
        assert "role" in r
        assert "is_inactivated" in r
        assert "is_anonymized" in r
        assert "email" in r
        assert "last_activity_at" in r


def test_search_group_members_text_search(test_tenant):
    """Test tokenized text search: AND across tokens, OR within a token."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Text Search Test",
    )

    alice = _make_search_user(test_tenant["id"], "Alice", "Anderson")
    bob = _make_search_user(test_tenant["id"], "Bob", "Brown")

    for u in [alice, bob]:
        database.groups.add_group_member(
            test_tenant["id"], str(test_tenant["id"]), group["id"], str(u["id"])
        )

    # Single token matches first name
    results = database.groups.search_group_members(test_tenant["id"], group["id"], search="Alice")
    assert len(results) == 1
    assert str(results[0]["user_id"]) == str(alice["id"])

    # Single token matches last name
    results = database.groups.search_group_members(test_tenant["id"], group["id"], search="Brown")
    assert len(results) == 1
    assert str(results[0]["user_id"]) == str(bob["id"])

    # Multi-token AND: both tokens must match one user
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], search="Alice Anderson"
    )
    assert len(results) == 1
    assert str(results[0]["user_id"]) == str(alice["id"])

    # Multi-token AND: mismatched tokens find nobody
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], search="Alice Brown"
    )
    assert len(results) == 0


def test_search_group_members_role_filter(test_tenant):
    """Test filtering group members by role."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Role Filter Test",
    )

    member = _make_search_user(test_tenant["id"], "Regular", "Member")
    admin = _make_search_user(test_tenant["id"], "Admin", "Usr", role="admin")
    sa = _make_search_user(test_tenant["id"], "Super", "Adm", role="super_admin")

    for u in [member, admin, sa]:
        database.groups.add_group_member(
            test_tenant["id"], str(test_tenant["id"]), group["id"], str(u["id"])
        )

    # Single role filter
    results = database.groups.search_group_members(test_tenant["id"], group["id"], roles=["admin"])
    assert len(results) == 1
    assert str(results[0]["user_id"]) == str(admin["id"])

    # Multiple roles
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], roles=["member", "super_admin"]
    )
    assert len(results) == 2
    ids = {str(r["user_id"]) for r in results}
    assert str(member["id"]) in ids
    assert str(sa["id"]) in ids

    # Invalid roles are silently ignored, no filter applied
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], roles=["nonexistent"]
    )
    assert len(results) == 3


def test_search_group_members_status_filter(test_tenant):
    """Test filtering group members by status (active/inactivated/anonymized)."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Status Filter Test",
    )

    active = _make_search_user(test_tenant["id"], "Active", "User")
    inactivated = _make_search_user(test_tenant["id"], "Inactive", "User", is_inactivated=True)
    anonymized = _make_search_user(
        test_tenant["id"], "Anon", "User", is_inactivated=True, is_anonymized=True
    )

    for u in [active, inactivated, anonymized]:
        database.groups.add_group_member(
            test_tenant["id"], str(test_tenant["id"]), group["id"], str(u["id"])
        )

    # Active only
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], statuses=["active"]
    )
    assert len(results) == 1
    assert str(results[0]["user_id"]) == str(active["id"])

    # Inactivated only
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], statuses=["inactivated"]
    )
    assert len(results) == 1
    assert str(results[0]["user_id"]) == str(inactivated["id"])

    # Anonymized only
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], statuses=["anonymized"]
    )
    assert len(results) == 1
    assert str(results[0]["user_id"]) == str(anonymized["id"])

    # Combined statuses
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], statuses=["active", "inactivated"]
    )
    assert len(results) == 2


def test_search_group_members_sorting_and_pagination(test_tenant):
    """Test sort fields and pagination."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Sort Pagination Test",
    )

    alice = _make_search_user(test_tenant["id"], "Alice", "Zulu")
    bob = _make_search_user(test_tenant["id"], "Bob", "Adams")
    carol = _make_search_user(test_tenant["id"], "Carol", "Middle")

    for u in [alice, bob, carol]:
        database.groups.add_group_member(
            test_tenant["id"], str(test_tenant["id"]), group["id"], str(u["id"])
        )

    # Sort by name ascending (last_name first)
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], sort_field="name", sort_order="asc"
    )
    assert results[0]["last_name"] == "Adams"
    assert results[1]["last_name"] == "Middle"
    assert results[2]["last_name"] == "Zulu"

    # Sort by name descending
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], sort_field="name", sort_order="desc"
    )
    assert results[0]["last_name"] == "Zulu"
    assert results[2]["last_name"] == "Adams"

    # Pagination: page_size=2
    page1 = database.groups.search_group_members(
        test_tenant["id"],
        group["id"],
        sort_field="name",
        sort_order="asc",
        page=1,
        page_size=2,
    )
    page2 = database.groups.search_group_members(
        test_tenant["id"],
        group["id"],
        sort_field="name",
        sort_order="asc",
        page=2,
        page_size=2,
    )
    assert len(page1) == 2
    assert len(page2) == 1
    all_ids = {str(r["user_id"]) for r in page1 + page2}
    assert len(all_ids) == 3

    # Invalid sort field falls back to created_at (no crash)
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], sort_field="bogus"
    )
    assert len(results) == 3

    # Invalid sort order falls back to desc (no crash)
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], sort_order="bogus"
    )
    assert len(results) == 3

    # last_activity_at sort with no activity records (NULL, no crash)
    results = database.groups.search_group_members(
        test_tenant["id"], group["id"], sort_field="last_activity_at"
    )
    assert len(results) == 3


# -- count_group_members_filtered ----------------------------------------------


def test_count_group_members_filtered_no_filters(test_tenant):
    """Test basic count with no filters."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Count No Filter Test",
    )

    alice = _make_search_user(test_tenant["id"], "Alice", "Count")
    bob = _make_search_user(test_tenant["id"], "Bob", "Count")

    for u in [alice, bob]:
        database.groups.add_group_member(
            test_tenant["id"], str(test_tenant["id"]), group["id"], str(u["id"])
        )

    count = database.groups.count_group_members_filtered(test_tenant["id"], group["id"])
    assert count == 2


def test_count_group_members_filtered_with_filters(test_tenant):
    """Test count with search, role, and status filters."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Count Filters Test",
    )

    alice = _make_search_user(test_tenant["id"], "Alice", "Smith")
    bob = _make_search_user(test_tenant["id"], "Bob", "Smith", role="admin")
    carol = _make_search_user(test_tenant["id"], "Carol", "Jones", is_inactivated=True)

    for u in [alice, bob, carol]:
        database.groups.add_group_member(
            test_tenant["id"], str(test_tenant["id"]), group["id"], str(u["id"])
        )

    # Search filter
    assert (
        database.groups.count_group_members_filtered(test_tenant["id"], group["id"], search="Smith")
        == 2
    )

    # Role filter
    assert (
        database.groups.count_group_members_filtered(
            test_tenant["id"], group["id"], roles=["admin"]
        )
        == 1
    )

    # Status filter
    assert (
        database.groups.count_group_members_filtered(
            test_tenant["id"], group["id"], statuses=["inactivated"]
        )
        == 1
    )

    # Combined: active Smiths who are members
    assert (
        database.groups.count_group_members_filtered(
            test_tenant["id"],
            group["id"],
            search="Smith",
            roles=["member"],
            statuses=["active"],
        )
        == 1
    )


def test_count_group_members_filtered_matches_search(test_tenant):
    """Test that count equals the number of search results."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Count Match Test",
    )

    users = [
        _make_search_user(test_tenant["id"], "Alice", "Smith"),
        _make_search_user(test_tenant["id"], "Bob", "Smith", role="admin"),
        _make_search_user(test_tenant["id"], "Carol", "Jones", is_inactivated=True),
    ]
    for u in users:
        database.groups.add_group_member(
            test_tenant["id"], str(test_tenant["id"]), group["id"], str(u["id"])
        )

    kwargs = {"search": "Smith", "roles": ["member"]}
    results = database.groups.search_group_members(test_tenant["id"], group["id"], **kwargs)
    count = database.groups.count_group_members_filtered(test_tenant["id"], group["id"], **kwargs)
    assert count == len(results)
    assert count == 1


# -- search_available_users ----------------------------------------------------


def test_search_available_users_excludes_members(test_tenant):
    """Test that users already in the group are excluded."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Available Exclude Test",
    )

    member = _make_search_user(test_tenant["id"], "Member", "User")
    nonmember = _make_search_user(test_tenant["id"], "Available", "User")

    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), group["id"], str(member["id"])
    )

    results = database.groups.search_available_users(test_tenant["id"], group["id"])

    result_ids = {str(r["id"]) for r in results}
    assert str(member["id"]) not in result_ids
    assert str(nonmember["id"]) in result_ids


def test_search_available_users_excludes_service_accounts(test_tenant):
    """Test that OAuth2 B2B service account users are excluded."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Service Acct Test",
    )

    regular = _make_search_user(test_tenant["id"], "Regular", "User")

    # Create a B2B client which auto-creates a service user
    b2b = database.oauth2.create_b2b_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Test B2B",
        role="admin",
        created_by=str(regular["id"]),
    )

    results = database.groups.search_available_users(test_tenant["id"], group["id"])

    result_ids = {str(r["id"]) for r in results}
    assert str(regular["id"]) in result_ids
    assert str(b2b["service_user_id"]) not in result_ids


def test_search_available_users_with_filters(test_tenant):
    """Test search, role, and status filters for available users."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Available Filter Test",
    )

    alice = _make_search_user(test_tenant["id"], "Alice", "Wonderland")
    bob = _make_search_user(test_tenant["id"], "Bob", "Builder", role="admin")
    carol = _make_search_user(test_tenant["id"], "Carol", "Inactive", is_inactivated=True)

    # Text search
    results = database.groups.search_available_users(test_tenant["id"], group["id"], search="Alice")
    result_ids = {str(r["id"]) for r in results}
    assert str(alice["id"]) in result_ids
    assert str(bob["id"]) not in result_ids

    # Role filter
    results = database.groups.search_available_users(
        test_tenant["id"], group["id"], roles=["admin"]
    )
    result_ids = {str(r["id"]) for r in results}
    assert str(bob["id"]) in result_ids
    assert str(alice["id"]) not in result_ids

    # Status filter
    results = database.groups.search_available_users(
        test_tenant["id"], group["id"], statuses=["inactivated"]
    )
    result_ids = {str(r["id"]) for r in results}
    assert str(carol["id"]) in result_ids
    assert str(alice["id"]) not in result_ids


def test_search_available_users_sorting_and_pagination(test_tenant):
    """Test sorting and pagination for available users."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Available Sort Page Test",
    )

    _make_search_user(test_tenant["id"], "Alice", "Zulu")
    _make_search_user(test_tenant["id"], "Bob", "Adams")
    _make_search_user(test_tenant["id"], "Carol", "Middle")

    # Default sort is name asc
    results = database.groups.search_available_users(test_tenant["id"], group["id"])
    assert results[0]["last_name"] == "Adams"
    assert results[1]["last_name"] == "Middle"
    assert results[2]["last_name"] == "Zulu"

    # Pagination
    page1 = database.groups.search_available_users(
        test_tenant["id"], group["id"], page=1, page_size=2
    )
    page2 = database.groups.search_available_users(
        test_tenant["id"], group["id"], page=2, page_size=2
    )
    assert len(page1) == 2
    assert len(page2) == 1
    all_ids = {str(r["id"]) for r in page1 + page2}
    assert len(all_ids) == 3

    # Invalid sort field falls back to name (no crash)
    results = database.groups.search_available_users(
        test_tenant["id"], group["id"], sort_field="bogus"
    )
    assert len(results) == 3


# -- count_available_users -----------------------------------------------------


def test_count_available_users_matches_search(test_tenant):
    """Test that count matches search results with same filters."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Count Available Test",
    )

    alice = _make_search_user(test_tenant["id"], "Alice", "Smith")
    _make_search_user(test_tenant["id"], "Bob", "Smith", role="admin")

    # Add Alice to the group so only Bob is available
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), group["id"], str(alice["id"])
    )

    # No filters
    count = database.groups.count_available_users(test_tenant["id"], group["id"])
    results = database.groups.search_available_users(test_tenant["id"], group["id"], page_size=1000)
    assert count == len(results)
    assert count == 1  # Only Bob

    # With filters
    count = database.groups.count_available_users(test_tenant["id"], group["id"], roles=["admin"])
    results = database.groups.search_available_users(
        test_tenant["id"], group["id"], roles=["admin"], page_size=1000
    )
    assert count == len(results)
    assert count == 1

    count = database.groups.count_available_users(
        test_tenant["id"], group["id"], search="Nonexistent"
    )
    assert count == 0


# -- bulk_remove_group_members -------------------------------------------------


def test_bulk_remove_group_members(test_tenant):
    """Test removing multiple members atomically."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Bulk Remove Test",
    )

    alice = _make_search_user(test_tenant["id"], "Alice", "Remove")
    bob = _make_search_user(test_tenant["id"], "Bob", "Remove")
    carol = _make_search_user(test_tenant["id"], "Carol", "Keep")

    for u in [alice, bob, carol]:
        database.groups.add_group_member(
            test_tenant["id"], str(test_tenant["id"]), group["id"], str(u["id"])
        )

    assert database.groups.count_group_members(test_tenant["id"], group["id"]) == 3

    removed = database.groups.bulk_remove_group_members(
        test_tenant["id"],
        group["id"],
        [str(alice["id"]), str(bob["id"])],
    )

    assert removed == 2
    assert database.groups.count_group_members(test_tenant["id"], group["id"]) == 1
    assert not database.groups.is_group_member(test_tenant["id"], group["id"], str(alice["id"]))
    assert not database.groups.is_group_member(test_tenant["id"], group["id"], str(bob["id"]))
    assert database.groups.is_group_member(test_tenant["id"], group["id"], str(carol["id"]))


def test_bulk_remove_group_members_empty_list(test_tenant):
    """Test bulk remove with empty list returns 0."""
    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Bulk Remove Empty Test",
    )

    removed = database.groups.bulk_remove_group_members(test_tenant["id"], group["id"], [])
    assert removed == 0


def test_bulk_remove_group_members_nonexistent_users(test_tenant):
    """Test bulk remove with nonexistent user IDs returns 0."""
    from uuid import uuid4

    import database

    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Bulk Remove Nonexistent Test",
    )

    removed = database.groups.bulk_remove_group_members(
        test_tenant["id"],
        group["id"],
        [str(uuid4()), str(uuid4())],
    )
    assert removed == 0


# =============================================================================
# get_groups_for_user_select (groups/selection.py)
# =============================================================================


def test_get_groups_for_user_select_excludes_member_groups(test_tenant, test_user):
    """Test that groups the user belongs to are excluded from the select list."""
    import database

    group_a = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Select Group A",
    )
    group_b = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Select Group B",
    )

    # Add user to group_a only
    database.groups.add_group_member(
        test_tenant["id"],
        str(test_tenant["id"]),
        group_a["id"],
        str(test_user["id"]),
    )

    results = database.groups.get_groups_for_user_select(
        test_tenant["id"], exclude_user_id=str(test_user["id"])
    )

    result_ids = [str(r["id"]) for r in results]
    assert str(group_a["id"]) not in result_ids  # user is a member - excluded
    assert str(group_b["id"]) in result_ids  # user is not a member - included


def test_get_groups_for_user_select_without_exclude_returns_all(test_tenant):
    """Test that omitting exclude_user_id returns all valid groups."""
    import database

    group_a = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="All Groups A",
    )
    group_b = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="All Groups B",
    )

    results = database.groups.get_groups_for_user_select(test_tenant["id"])

    result_ids = [str(r["id"]) for r in results]
    assert str(group_a["id"]) in result_ids
    assert str(group_b["id"]) in result_ids


def test_get_groups_for_user_select_returns_ordered_by_name(test_tenant):
    """Test that results are ordered by group name."""
    import database

    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Zeta Group",
    )
    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Alpha Group",
    )

    results = database.groups.get_groups_for_user_select(test_tenant["id"])

    names = [r["name"] for r in results]
    assert names == sorted(names)
