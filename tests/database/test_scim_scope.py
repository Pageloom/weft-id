"""Tests for `database.scim_scope` query helpers.

Real-schema integration tests. Each test builds up a lineage shape, sets
`scim_enabled = true` on the relevant SPs via raw SQL (the migration adds
the column but `create_service_provider` doesn't expose it yet), then
asserts the queries pick the right rows.
"""

from __future__ import annotations

from uuid import uuid4

import database


def _create_sp(tenant_id, user_id, name="Scope SP", scim_enabled=True, membership_mode="effective"):
    sp = database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )
    database.execute(
        tenant_id,
        """
        update service_providers
        set scim_enabled = :enabled,
            scim_membership_mode = :mode
        where id = :sp_id
        """,
        {"enabled": scim_enabled, "mode": membership_mode, "sp_id": sp["id"]},
    )
    return sp


def _create_group(tenant_id, name="Group"):
    return database.groups.create_group(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=f"{name}-{uuid4().hex[:8]}",
    )


def _create_user(tenant_id, email_suffix=None):
    suffix = email_suffix or uuid4().hex[:8]
    from tests.conftest import TEST_PASSWORD_HASH

    user = database.fetchone(
        tenant_id,
        """
        INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
        VALUES (:tenant_id, :ph, 'Test', 'User', 'member')
        RETURNING id
        """,
        {"tenant_id": str(tenant_id), "ph": TEST_PASSWORD_HASH},
    )
    database.execute(
        tenant_id,
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {
            "tenant_id": str(tenant_id),
            "user_id": user["id"],
            "email": f"u-{suffix}@example.com",
        },
    )
    return user


def _assign(tenant_id, sp_id, group_id, user_id):
    database.sp_group_assignments.create_assignment(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        sp_id=str(sp_id),
        group_id=str(group_id),
        assigned_by=str(user_id),
    )


# ---------------------------------------------------------------------------
# scim_sps_granting_user
# ---------------------------------------------------------------------------


def test_scim_sps_granting_user_returns_direct_grant(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    group = _create_group(test_tenant["id"])
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), str(group["id"]), str(test_user["id"])
    )
    _assign(test_tenant["id"], sp["id"], group["id"], test_user["id"])

    rows = database.scim_scope.scim_sps_granting_user(test_tenant["id"], str(test_user["id"]))
    assert [str(r["id"]) for r in rows] == [str(sp["id"])]


def test_scim_sps_granting_user_returns_via_ancestor(test_tenant, test_user):
    """User is in child group; SP grants the parent group. The closure
    table should resolve the inheritance."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    parent = _create_group(test_tenant["id"], "parent")
    child = _create_group(test_tenant["id"], "child")
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), str(parent["id"]), str(child["id"])
    )
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), str(child["id"]), str(test_user["id"])
    )
    _assign(test_tenant["id"], sp["id"], parent["id"], test_user["id"])

    rows = database.scim_scope.scim_sps_granting_user(test_tenant["id"], str(test_user["id"]))
    assert [str(r["id"]) for r in rows] == [str(sp["id"])]


def test_scim_sps_granting_user_excludes_scim_disabled_sp(test_tenant, test_user):
    sp_off = _create_sp(test_tenant["id"], test_user["id"], name="off", scim_enabled=False)
    group = _create_group(test_tenant["id"])
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), str(group["id"]), str(test_user["id"])
    )
    _assign(test_tenant["id"], sp_off["id"], group["id"], test_user["id"])

    rows = database.scim_scope.scim_sps_granting_user(test_tenant["id"], str(test_user["id"]))
    assert rows == []


def test_scim_sps_granting_user_empty_when_no_grants(test_tenant, test_user):
    rows = database.scim_scope.scim_sps_granting_user(test_tenant["id"], str(test_user["id"]))
    assert rows == []


def test_scim_sps_granting_user_returns_membership_mode(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"], membership_mode="direct")
    group = _create_group(test_tenant["id"])
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), str(group["id"]), str(test_user["id"])
    )
    _assign(test_tenant["id"], sp["id"], group["id"], test_user["id"])

    rows = database.scim_scope.scim_sps_granting_user(test_tenant["id"], str(test_user["id"]))
    assert rows[0]["scim_membership_mode"] == "direct"


def test_scim_sps_granting_user_includes_available_to_all_sp(test_tenant, test_user):
    """SPs flagged `available_to_all=true` are tenant-wide grants and MUST
    surface in SCIM scope even when there is no explicit `sp_group_assignments`
    row. Otherwise SCIM-enabled tenant-wide SPs (Slack, Notion, company
    wiki) would silently never receive provisioning or deprovisioning.

    Locks in the rule: SCIM scope = (group-grant trail) OR (available_to_all).
    """
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)
    database.execute(
        test_tenant["id"],
        "update service_providers set available_to_all = true where id = :sp_id",
        {"sp_id": sp["id"]},
    )
    # No sp_group_assignments row. available_to_all alone must be enough.
    rows = database.scim_scope.scim_sps_granting_user(test_tenant["id"], str(test_user["id"]))
    assert [str(r["id"]) for r in rows] == [str(sp["id"])]


def test_scim_sps_granting_user_walks_three_level_lineage(test_tenant, test_user):
    """Closure-table walk across a 3-level chain: grandparent -> parent ->
    child, user in the leaf, SP grants the grandparent. The user must still
    surface.
    """
    sp = _create_sp(test_tenant["id"], test_user["id"])
    grandparent = _create_group(test_tenant["id"], "gp")
    parent = _create_group(test_tenant["id"], "p")
    child = _create_group(test_tenant["id"], "c")
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), str(grandparent["id"]), str(parent["id"])
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), str(parent["id"]), str(child["id"])
    )
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), str(child["id"]), str(test_user["id"])
    )
    _assign(test_tenant["id"], sp["id"], grandparent["id"], test_user["id"])

    rows = database.scim_scope.scim_sps_granting_user(test_tenant["id"], str(test_user["id"]))
    assert [str(r["id"]) for r in rows] == [str(sp["id"])]


def test_scim_sps_granting_via_group_three_levels_deep(test_tenant, test_user):
    """Membership-change scope walk across 3 levels: SP grants the
    grandparent group; querying for the leaf must return the SP. This is the
    "ancestor at any depth" guarantee for `enqueue_membership_change`.
    """
    sp = _create_sp(test_tenant["id"], test_user["id"])
    grandparent = _create_group(test_tenant["id"], "gp")
    parent = _create_group(test_tenant["id"], "p")
    child = _create_group(test_tenant["id"], "c")
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), str(grandparent["id"]), str(parent["id"])
    )
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), str(parent["id"]), str(child["id"])
    )
    _assign(test_tenant["id"], sp["id"], grandparent["id"], test_user["id"])

    rows = database.scim_scope.scim_sps_granting_via_group(test_tenant["id"], str(child["id"]))
    assert [str(r["id"]) for r in rows] == [str(sp["id"])]


# ---------------------------------------------------------------------------
# scim_sps_granting_via_group
# ---------------------------------------------------------------------------


def test_scim_sps_granting_via_group_direct_match(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    group = _create_group(test_tenant["id"])
    _assign(test_tenant["id"], sp["id"], group["id"], test_user["id"])

    rows = database.scim_scope.scim_sps_granting_via_group(test_tenant["id"], str(group["id"]))
    assert [str(r["id"]) for r in rows] == [str(sp["id"])]


def test_scim_sps_granting_via_group_walks_to_ancestor(test_tenant, test_user):
    """SP grants the parent; we ask about the child. The query should
    walk up the ancestor chain via group_lineage."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    parent = _create_group(test_tenant["id"], "parent")
    child = _create_group(test_tenant["id"], "child")
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), str(parent["id"]), str(child["id"])
    )
    _assign(test_tenant["id"], sp["id"], parent["id"], test_user["id"])

    rows = database.scim_scope.scim_sps_granting_via_group(test_tenant["id"], str(child["id"]))
    assert [str(r["id"]) for r in rows] == [str(sp["id"])]


def test_scim_sps_granting_via_group_excludes_scim_disabled(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=False)
    group = _create_group(test_tenant["id"])
    _assign(test_tenant["id"], sp["id"], group["id"], test_user["id"])

    rows = database.scim_scope.scim_sps_granting_via_group(test_tenant["id"], str(group["id"]))
    assert rows == []


# ---------------------------------------------------------------------------
# transitive_user_ids_for_group
# ---------------------------------------------------------------------------


def test_transitive_user_ids_for_group_direct_members(test_tenant, test_user):
    group = _create_group(test_tenant["id"])
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), str(group["id"]), str(test_user["id"])
    )

    user_ids = database.scim_scope.transitive_user_ids_for_group(
        test_tenant["id"], str(group["id"])
    )
    assert user_ids == [str(test_user["id"])]


def test_transitive_user_ids_for_group_includes_descendants(test_tenant, test_user):
    """Members of a descendant group must surface for the ancestor's id."""
    other = _create_user(test_tenant["id"])
    parent = _create_group(test_tenant["id"], "parent")
    child = _create_group(test_tenant["id"], "child")
    database.groups.add_group_relationship(
        test_tenant["id"], str(test_tenant["id"]), str(parent["id"]), str(child["id"])
    )
    # test_user directly in parent, other in child
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), str(parent["id"]), str(test_user["id"])
    )
    database.groups.add_group_member(
        test_tenant["id"], str(test_tenant["id"]), str(child["id"]), str(other["id"])
    )

    user_ids = set(
        database.scim_scope.transitive_user_ids_for_group(test_tenant["id"], str(parent["id"]))
    )
    assert user_ids == {str(test_user["id"]), str(other["id"])}


def test_transitive_user_ids_for_group_empty_when_no_members(test_tenant, test_user):
    group = _create_group(test_tenant["id"])
    user_ids = database.scim_scope.transitive_user_ids_for_group(
        test_tenant["id"], str(group["id"])
    )
    assert user_ids == []


# ---------------------------------------------------------------------------
# is_scim_enabled_sp
# ---------------------------------------------------------------------------


def test_is_scim_enabled_sp_true(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)
    assert database.scim_scope.is_scim_enabled_sp(test_tenant["id"], str(sp["id"])) is True


def test_is_scim_enabled_sp_false_when_disabled(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=False)
    assert database.scim_scope.is_scim_enabled_sp(test_tenant["id"], str(sp["id"])) is False


def test_is_scim_enabled_sp_false_when_missing(test_tenant):
    assert database.scim_scope.is_scim_enabled_sp(test_tenant["id"], str(uuid4())) is False
