"""Database tests for inbound SCIM read helpers.

Covers `database.users.{count,list,get}_users_for_idp` and the
equivalent `database.groups.{count,list,get,list_group_members}_*`
helpers introduced in iteration 2.

The key invariants we exercise are:
- IdP scoping: users / groups belonging to a different IdP (or to no
  IdP at all) must not leak into the response.
- `eq` filter behaviour: filtering by userName, externalId, or
  displayName returns only matching rows.
- Pagination is 1-indexed at the API and 0-indexed in SQL -- both
  sides of the boundary must round-trip cleanly.
- Group member projection has the columns the SCIM payload builder
  needs (id, first_name, last_name, email).
"""

from __future__ import annotations

from uuid import uuid4

import database

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _create_idp(tenant_id, user_id, *, name="Test IdP"):
    return database.saml.create_identity_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(user_id),
    )


def _create_user(tenant_id, *, email, first="Test", last="User", idp_id=None):
    user = database.fetchone(
        tenant_id,
        """
        insert into users (tenant_id, first_name, last_name, role, saml_idp_id)
        values (:tenant_id, :first, :last, 'member', :idp_id)
        returning id, first_name, last_name
        """,
        {"tenant_id": str(tenant_id), "first": first, "last": last, "idp_id": idp_id},
    )
    database.execute(
        tenant_id,
        """
        insert into user_emails (tenant_id, user_id, email, is_primary, verified_at)
        values (:tenant_id, :user_id, :email, true, now())
        """,
        {"tenant_id": str(tenant_id), "user_id": user["id"], "email": email},
    )
    user["email"] = email
    return user


def _create_idp_group(tenant_id, idp, *, name):
    return database.groups.create_idp_group(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        idp_id=str(idp["id"]),
        name=name,
    )


# ---------------------------------------------------------------------------
# users.scim_reads
# ---------------------------------------------------------------------------


def test_list_users_for_idp_returns_only_users_bound_to_that_idp(test_tenant, test_user):
    idp_a = _create_idp(test_tenant["id"], test_user["id"], name="IdP A")
    idp_b = _create_idp(test_tenant["id"], test_user["id"], name="IdP B")
    u_a = _create_user(test_tenant["id"], email="a@x.test", idp_id=str(idp_a["id"]))
    u_b = _create_user(test_tenant["id"], email="b@x.test", idp_id=str(idp_b["id"]))
    _create_user(test_tenant["id"], email="orphan@x.test", idp_id=None)

    rows_a = database.users.list_users_for_idp(test_tenant["id"], str(idp_a["id"]))
    ids_a = {str(r["id"]) for r in rows_a}
    assert str(u_a["id"]) in ids_a
    assert str(u_b["id"]) not in ids_a


def test_count_users_for_idp_matches_list(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    for i in range(3):
        _create_user(test_tenant["id"], email=f"user{i}@x.test", idp_id=str(idp["id"]))

    rows = database.users.list_users_for_idp(test_tenant["id"], str(idp["id"]))
    count = database.users.count_users_for_idp(test_tenant["id"], str(idp["id"]))
    assert count == len(rows) == 3


def test_list_users_for_idp_user_name_filter(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    _create_user(test_tenant["id"], email="alice@x.test", idp_id=str(idp["id"]))
    target = _create_user(test_tenant["id"], email="bob@x.test", idp_id=str(idp["id"]))

    rows = database.users.list_users_for_idp(
        test_tenant["id"], str(idp["id"]), user_name="bob@x.test"
    )
    assert [str(r["id"]) for r in rows] == [str(target["id"])]


def test_list_users_for_idp_external_id_filter_against_user_id(test_tenant, test_user):
    """Iteration 2: externalId maps to the WeftID user id (no upstream id store yet)."""
    idp = _create_idp(test_tenant["id"], test_user["id"])
    target = _create_user(test_tenant["id"], email="ext@x.test", idp_id=str(idp["id"]))
    _create_user(test_tenant["id"], email="other@x.test", idp_id=str(idp["id"]))

    rows = database.users.list_users_for_idp(
        test_tenant["id"], str(idp["id"]), external_id=str(target["id"])
    )
    assert [str(r["id"]) for r in rows] == [str(target["id"])]


def test_list_users_for_idp_pagination_is_one_indexed(test_tenant, test_user):
    """SCIM `startIndex` is 1-indexed; the DB layer accepts it directly."""
    idp = _create_idp(test_tenant["id"], test_user["id"])
    users = []
    for i in range(5):
        users.append(
            _create_user(test_tenant["id"], email=f"user{i}@x.test", idp_id=str(idp["id"]))
        )

    page1 = database.users.list_users_for_idp(
        test_tenant["id"], str(idp["id"]), start_index=1, count=2
    )
    page2 = database.users.list_users_for_idp(
        test_tenant["id"], str(idp["id"]), start_index=3, count=2
    )
    page3 = database.users.list_users_for_idp(
        test_tenant["id"], str(idp["id"]), start_index=5, count=2
    )

    assert len(page1) == 2
    assert len(page2) == 2
    assert len(page3) == 1
    # No overlap across pages (sort is by created_at then id).
    ids = [str(r["id"]) for r in page1 + page2 + page3]
    assert len(set(ids)) == 5


def test_get_user_for_idp_returns_none_for_cross_idp_lookup(test_tenant, test_user):
    """A user belonging to IdP B is invisible to a /Users/{id} call scoped to IdP A."""
    idp_a = _create_idp(test_tenant["id"], test_user["id"], name="IdP A")
    idp_b = _create_idp(test_tenant["id"], test_user["id"], name="IdP B")
    u_b = _create_user(test_tenant["id"], email="b@x.test", idp_id=str(idp_b["id"]))

    found_in_b = database.users.get_user_for_idp(
        test_tenant["id"], str(idp_b["id"]), str(u_b["id"])
    )
    not_found_in_a = database.users.get_user_for_idp(
        test_tenant["id"], str(idp_a["id"]), str(u_b["id"])
    )
    assert found_in_b is not None
    assert not_found_in_a is None


# ---------------------------------------------------------------------------
# groups.scim_reads
# ---------------------------------------------------------------------------


def test_list_groups_for_idp_only_returns_idp_groups(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    idp_grp = _create_idp_group(test_tenant["id"], idp, name="Engineers")
    # Create a 'weftid' (manually-managed) group: must NOT appear.
    database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Manual Group",
        created_by=str(test_user["id"]),
    )

    rows = database.groups.list_groups_for_idp(test_tenant["id"], str(idp["id"]))
    assert [str(r["id"]) for r in rows] == [str(idp_grp["id"])]


def test_list_groups_for_idp_display_name_filter(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    _create_idp_group(test_tenant["id"], idp, name="Engineers")
    target = _create_idp_group(test_tenant["id"], idp, name="Marketing")

    rows = database.groups.list_groups_for_idp(
        test_tenant["id"], str(idp["id"]), display_name="Marketing"
    )
    assert [str(r["id"]) for r in rows] == [str(target["id"])]


def test_list_groups_for_idp_excludes_invalid_groups(test_tenant, test_user):
    """Soft-deleted (is_valid=false) IdP groups are excluded."""
    idp = _create_idp(test_tenant["id"], test_user["id"])
    keep = _create_idp_group(test_tenant["id"], idp, name="Keep")
    invalid = _create_idp_group(test_tenant["id"], idp, name="Invalid")
    database.execute(
        test_tenant["id"],
        "update groups set is_valid = false where id = :id",
        {"id": invalid["id"]},
    )

    rows = database.groups.list_groups_for_idp(test_tenant["id"], str(idp["id"]))
    assert [str(r["id"]) for r in rows] == [str(keep["id"])]


def test_get_group_for_idp_returns_none_for_other_idp(test_tenant, test_user):
    idp_a = _create_idp(test_tenant["id"], test_user["id"], name="A")
    idp_b = _create_idp(test_tenant["id"], test_user["id"], name="B")
    grp_b = _create_idp_group(test_tenant["id"], idp_b, name="X")

    in_b = database.groups.get_group_for_idp(test_tenant["id"], str(idp_b["id"]), str(grp_b["id"]))
    in_a = database.groups.get_group_for_idp(test_tenant["id"], str(idp_a["id"]), str(grp_b["id"]))
    assert in_b is not None
    assert in_a is None


def test_list_group_members_for_scim_returns_display_columns(test_tenant, test_user):
    """Members come back with the columns the SCIM payload builder needs."""
    idp = _create_idp(test_tenant["id"], test_user["id"])
    grp = _create_idp_group(test_tenant["id"], idp, name="Engineers")
    u1 = _create_user(
        test_tenant["id"], email="zara@x.test", first="Zara", last="Z", idp_id=str(idp["id"])
    )
    u2 = _create_user(
        test_tenant["id"], email="amy@x.test", first="Amy", last="A", idp_id=str(idp["id"])
    )
    database.groups.add_group_member(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        group_id=str(grp["id"]),
        user_id=str(u1["id"]),
    )
    database.groups.add_group_member(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        group_id=str(grp["id"]),
        user_id=str(u2["id"]),
    )

    rows = database.groups.list_group_members_for_scim(test_tenant["id"], str(grp["id"]))
    ids = [str(r["id"]) for r in rows]
    # Ordering is by last_name asc, first_name asc -> Amy A first.
    assert ids == [str(u2["id"]), str(u1["id"])]
    assert rows[0]["email"] == "amy@x.test"
    assert rows[0]["first_name"] == "Amy"


def test_count_groups_for_idp_with_filter(test_tenant, test_user):
    idp = _create_idp(test_tenant["id"], test_user["id"])
    _create_idp_group(test_tenant["id"], idp, name="A")
    _create_idp_group(test_tenant["id"], idp, name="B")

    assert database.groups.count_groups_for_idp(test_tenant["id"], str(idp["id"])) == 2
    assert (
        database.groups.count_groups_for_idp(test_tenant["id"], str(idp["id"]), display_name="A")
        == 1
    )
