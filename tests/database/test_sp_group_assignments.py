"""Tests for database.sp_group_assignments module.

These are integration tests that use a real database connection.
"""

from uuid import uuid4

import database


def _create_sp(tenant_id, user_id, name="Test SP", **kwargs):
    """Helper to create a service provider with sensible defaults."""
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
        **kwargs,
    )


def _create_group(tenant_id, name="Test Group", **kwargs):
    """Helper to create a group with sensible defaults."""
    return database.groups.create_group(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        **kwargs,
    )


# -- create_assignment ---------------------------------------------------------


def test_create_assignment(test_tenant, test_user):
    """Test creating a single SP-group assignment."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Assign SP")
    group = _create_group(tid, name="Assign Group")

    result = database.sp_group_assignments.create_assignment(
        tid, str(tid), sp["id"], group["id"], str(uid)
    )

    assert result is not None
    assert result["sp_id"] == sp["id"]
    assert result["group_id"] == group["id"]
    assert str(result["assigned_by"]) == str(uid)
    assert result["assigned_at"] is not None
    assert result["id"] is not None


def test_create_assignment_duplicate(test_tenant, test_user):
    """Test that creating the same assignment twice raises an integrity error."""
    import psycopg.errors

    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Dup SP")
    group = _create_group(tid, name="Dup Group")

    database.sp_group_assignments.create_assignment(tid, str(tid), sp["id"], group["id"], str(uid))

    # Second insert with same (sp_id, group_id) should fail due to unique constraint
    try:
        database.sp_group_assignments.create_assignment(
            tid, str(tid), sp["id"], group["id"], str(uid)
        )
        # If no exception, the DB allowed a duplicate somehow
        assert False, "Expected UniqueViolation for duplicate assignment"
    except psycopg.errors.UniqueViolation:
        pass  # Expected: unique constraint violation

    # Verify only one assignment exists
    assignments = database.sp_group_assignments.list_assignments_for_sp(tid, sp["id"])
    assert len(assignments) == 1


# -- list_assignments_for_sp ---------------------------------------------------


def test_list_assignments_for_sp(test_tenant, test_user):
    """Test listing group assignments for a service provider."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="List SP")
    group_a = _create_group(tid, name="Alpha Group")
    group_b = _create_group(tid, name="Beta Group")

    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp["id"], group_a["id"], str(uid)
    )
    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp["id"], group_b["id"], str(uid)
    )

    assignments = database.sp_group_assignments.list_assignments_for_sp(tid, sp["id"])

    assert len(assignments) == 2
    assert assignments[0]["group_name"] == "Alpha Group"
    assert assignments[1]["group_name"] == "Beta Group"
    # Verify joined fields are present
    assert "group_description" in assignments[0]
    assert "group_type" in assignments[0]


def test_list_assignments_for_sp_empty(test_tenant, test_user):
    """Test listing assignments for an SP with no assignments returns []."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Empty SP")

    assignments = database.sp_group_assignments.list_assignments_for_sp(tid, sp["id"])

    assert assignments == []


# -- list_assignments_for_group ------------------------------------------------


def test_list_assignments_for_group(test_tenant, test_user):
    """Test listing SP assignments for a group."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    group = _create_group(tid, name="Multi SP Group")
    sp_a = _create_sp(tid, uid, name="Alpha SP")
    sp_b = _create_sp(tid, uid, name="Beta SP")

    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp_a["id"], group["id"], str(uid)
    )
    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp_b["id"], group["id"], str(uid)
    )

    assignments = database.sp_group_assignments.list_assignments_for_group(tid, group["id"])

    assert len(assignments) == 2
    assert assignments[0]["sp_name"] == "Alpha SP"
    assert assignments[1]["sp_name"] == "Beta SP"
    # Verify joined fields are present
    assert "sp_entity_id" in assignments[0]
    assert "sp_description" in assignments[0]


def test_list_assignments_for_group_empty(test_tenant):
    """Test listing assignments for a group with no assignments returns []."""
    tid = test_tenant["id"]
    group = _create_group(tid, name="Lonely Group")

    assignments = database.sp_group_assignments.list_assignments_for_group(tid, group["id"])

    assert assignments == []


# -- delete_assignment ---------------------------------------------------------


def test_delete_assignment(test_tenant, test_user):
    """Test deleting an assignment."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Delete SP")
    group = _create_group(tid, name="Delete Group")

    database.sp_group_assignments.create_assignment(tid, str(tid), sp["id"], group["id"], str(uid))

    rows = database.sp_group_assignments.delete_assignment(tid, sp["id"], group["id"])

    assert rows == 1
    assert database.sp_group_assignments.list_assignments_for_sp(tid, sp["id"]) == []


def test_delete_assignment_not_found(test_tenant):
    """Test deleting a nonexistent assignment returns 0."""
    tid = test_tenant["id"]

    rows = database.sp_group_assignments.delete_assignment(tid, str(uuid4()), str(uuid4()))

    assert rows == 0


# -- bulk_create_assignments ---------------------------------------------------


def test_bulk_create_assignments(test_tenant, test_user):
    """Test bulk creating assignments."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Bulk SP")
    groups = [_create_group(tid, name=f"Bulk Group {i}") for i in range(3)]
    group_ids = [g["id"] for g in groups]

    created = database.sp_group_assignments.bulk_create_assignments(
        tid, str(tid), sp["id"], group_ids, str(uid)
    )

    assert created == 3
    assignments = database.sp_group_assignments.list_assignments_for_sp(tid, sp["id"])
    assert len(assignments) == 3


def test_bulk_create_assignments_empty_list(test_tenant, test_user):
    """Test bulk creating with empty group_ids returns 0 immediately."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Empty Bulk SP")

    created = database.sp_group_assignments.bulk_create_assignments(
        tid, str(tid), sp["id"], [], str(uid)
    )

    assert created == 0


def test_bulk_create_assignments_with_duplicates(test_tenant, test_user):
    """Test bulk create skips duplicates via ON CONFLICT DO NOTHING."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Dedup SP")
    existing_group = _create_group(tid, name="Existing Group")
    new_group = _create_group(tid, name="New Group")

    # Create one assignment first
    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp["id"], existing_group["id"], str(uid)
    )

    # Bulk create including the existing one plus a new one
    created = database.sp_group_assignments.bulk_create_assignments(
        tid, str(tid), sp["id"], [existing_group["id"], new_group["id"]], str(uid)
    )

    assert created == 1  # Only the new one was inserted
    assignments = database.sp_group_assignments.list_assignments_for_sp(tid, sp["id"])
    assert len(assignments) == 2


# -- user_can_access_sp --------------------------------------------------------


def test_user_can_access_sp_direct(test_tenant, test_user):
    """Test user has access when in a directly assigned group."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Direct Access SP")
    group = _create_group(tid, name="Direct Group")

    database.sp_group_assignments.create_assignment(tid, str(tid), sp["id"], group["id"], str(uid))
    database.groups.add_group_member(tid, str(tid), group["id"], str(uid))

    assert database.sp_group_assignments.user_can_access_sp(tid, str(uid), sp["id"]) is True


def test_user_can_access_sp_inherited(test_tenant, test_user):
    """Test user has access via inherited group assignment (parent assigned, user in child)."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Inherited Access SP")
    parent = _create_group(tid, name="Parent Group")
    child = _create_group(tid, name="Child Group")

    # Build hierarchy: parent -> child
    database.groups.add_group_relationship(tid, str(tid), parent["id"], child["id"])

    # Assign SP to parent group
    database.sp_group_assignments.create_assignment(tid, str(tid), sp["id"], parent["id"], str(uid))

    # Add user to child group (should inherit access via lineage)
    database.groups.add_group_member(tid, str(tid), child["id"], str(uid))

    assert database.sp_group_assignments.user_can_access_sp(tid, str(uid), sp["id"]) is True


def test_user_can_access_sp_no_access(test_tenant, test_user):
    """Test user has no access when not in any assigned group."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="No Access SP")
    group = _create_group(tid, name="Exclusive Group")

    # Assign group to SP but don't add user to group
    database.sp_group_assignments.create_assignment(tid, str(tid), sp["id"], group["id"], str(uid))

    assert database.sp_group_assignments.user_can_access_sp(tid, str(uid), sp["id"]) is False


def test_user_can_access_sp_no_assignment(test_tenant, test_user):
    """Test user has no access when in a group that isn't assigned to the SP."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Unassigned SP")
    group = _create_group(tid, name="Unassigned Group")

    # Add user to group but don't assign group to SP
    database.groups.add_group_member(tid, str(tid), group["id"], str(uid))

    assert database.sp_group_assignments.user_can_access_sp(tid, str(uid), sp["id"]) is False


# -- get_accessible_sps_for_user -----------------------------------------------


def test_get_accessible_sps_for_user(test_tenant, test_user):
    """Test getting accessible SPs including direct and inherited access."""
    tid = test_tenant["id"]
    uid = test_user["id"]

    # SP1: direct access via group membership
    sp1 = _create_sp(tid, uid, name="Alpha Accessible SP", trust_established=True)
    direct_group = _create_group(tid, name="Direct Group")
    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp1["id"], direct_group["id"], str(uid)
    )
    database.groups.add_group_member(tid, str(tid), direct_group["id"], str(uid))

    # SP2: inherited access via parent-child hierarchy
    sp2 = _create_sp(tid, uid, name="Beta Inherited SP", trust_established=True)
    parent = _create_group(tid, name="Parent Group")
    child = _create_group(tid, name="Child Group")
    database.groups.add_group_relationship(tid, str(tid), parent["id"], child["id"])
    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp2["id"], parent["id"], str(uid)
    )
    database.groups.add_group_member(tid, str(tid), child["id"], str(uid))

    sps = database.sp_group_assignments.get_accessible_sps_for_user(tid, str(uid))

    names = [sp["name"] for sp in sps]
    assert "Alpha Accessible SP" in names
    assert "Beta Inherited SP" in names
    # Ordered by name
    assert names == sorted(names)


def test_get_accessible_sps_for_user_excludes_disabled(test_tenant, test_user):
    """Test that disabled SPs are excluded even if group is assigned."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Disabled SP", trust_established=True)
    group = _create_group(tid, name="Disabled Test Group")

    database.sp_group_assignments.create_assignment(tid, str(tid), sp["id"], group["id"], str(uid))
    database.groups.add_group_member(tid, str(tid), group["id"], str(uid))

    # Disable the SP
    database.service_providers.set_service_provider_enabled(tid, sp["id"], enabled=False)

    sps = database.sp_group_assignments.get_accessible_sps_for_user(tid, str(uid))

    sp_ids = [s["id"] for s in sps]
    assert sp["id"] not in sp_ids


def test_get_accessible_sps_for_user_excludes_untrusted(test_tenant, test_user):
    """Test that untrusted SPs are excluded even if group is assigned."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    # trust_established defaults to False
    sp = _create_sp(tid, uid, name="Untrusted SP")
    group = _create_group(tid, name="Untrusted Test Group")

    database.sp_group_assignments.create_assignment(tid, str(tid), sp["id"], group["id"], str(uid))
    database.groups.add_group_member(tid, str(tid), group["id"], str(uid))

    sps = database.sp_group_assignments.get_accessible_sps_for_user(tid, str(uid))

    sp_ids = [s["id"] for s in sps]
    assert sp["id"] not in sp_ids


def test_get_accessible_sps_for_user_empty(test_tenant, test_user):
    """Test that user with no group memberships gets no accessible SPs."""
    tid = test_tenant["id"]
    uid = test_user["id"]

    sps = database.sp_group_assignments.get_accessible_sps_for_user(tid, str(uid))

    assert sps == []


# -- count_assignments_for_sp --------------------------------------------------


def test_count_assignments_for_sp(test_tenant, test_user):
    """Test counting group assignments for a single SP."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Count SP")
    group_a = _create_group(tid, name="Count Group A")
    group_b = _create_group(tid, name="Count Group B")

    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp["id"], group_a["id"], str(uid)
    )
    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp["id"], group_b["id"], str(uid)
    )

    assert database.sp_group_assignments.count_assignments_for_sp(tid, sp["id"]) == 2


def test_count_assignments_for_sp_none(test_tenant, test_user):
    """Test counting assignments for an SP with none returns 0."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp = _create_sp(tid, uid, name="Zero Count SP")

    assert database.sp_group_assignments.count_assignments_for_sp(tid, sp["id"]) == 0


# -- count_assignments_for_sps ------------------------------------------------


def test_count_assignments_for_sps(test_tenant, test_user):
    """Test counting assignments across multiple SPs."""
    tid = test_tenant["id"]
    uid = test_user["id"]
    sp1 = _create_sp(tid, uid, name="Multi Count SP1")
    sp2 = _create_sp(tid, uid, name="Multi Count SP2")
    group_a = _create_group(tid, name="Multi Count Group A")
    group_b = _create_group(tid, name="Multi Count Group B")

    # SP1 gets 2 assignments, SP2 gets 1
    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp1["id"], group_a["id"], str(uid)
    )
    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp1["id"], group_b["id"], str(uid)
    )
    database.sp_group_assignments.create_assignment(
        tid, str(tid), sp2["id"], group_a["id"], str(uid)
    )

    counts = database.sp_group_assignments.count_assignments_for_sps(tid)

    assert counts[str(sp1["id"])] == 2
    assert counts[str(sp2["id"])] == 1


def test_count_assignments_for_sps_empty(test_tenant):
    """Test counting assignments when none exist returns empty dict."""
    tid = test_tenant["id"]

    counts = database.sp_group_assignments.count_assignments_for_sps(tid)

    assert counts == {}
