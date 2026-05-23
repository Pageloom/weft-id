"""Tests for database.scim_remote_ids module."""

from uuid import uuid4

import database

from tests.conftest import TEST_PASSWORD_HASH


def _create_extra_tenant_and_user() -> tuple[dict, dict]:
    """Spin up a second tenant + user for cross-tenant isolation tests.

    Conftest's `test_tenant` / `test_user` fixtures only give us one of each;
    this helper creates a peer pair so the same database session can confirm
    RLS keeps mappings apart. The tenant cascade-deletes on its own when
    nothing references it, so test teardown is implicit.
    """
    unique = str(uuid4())[:8]
    tenant = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id, subdomain, name",
        {"s": f"peer-{unique}", "n": f"Peer Tenant {unique}"},
    )
    assert tenant is not None
    user = database.fetchone(
        tenant["id"],
        """
        INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
        VALUES (:tid, :pw, 'Peer', 'User', 'member')
        RETURNING id
        """,
        {"tid": tenant["id"], "pw": TEST_PASSWORD_HASH},
    )
    assert user is not None
    return tenant, user


def _create_sp(tenant_id, user_id, name="SCIM Remote ID SP"):
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )


# -- get_one / upsert ----------------------------------------------------------


def test_get_one_returns_none_when_no_mapping(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    out = database.scim_remote_ids.get_one(test_tenant["id"], str(sp["id"]), "user", str(uuid4()))
    assert out is None


def test_upsert_inserts_first_then_updates(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    weftid_id = str(uuid4())

    row1, inserted1 = database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="user",
        weftid_id=weftid_id,
        remote_id="remote-A",
    )
    assert inserted1 is True
    assert str(row1["weftid_id"]) == weftid_id
    assert row1["remote_id"] == "remote-A"

    row2, inserted2 = database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="user",
        weftid_id=weftid_id,
        remote_id="remote-B",
    )
    assert inserted2 is False
    assert str(row2["id"]) == str(row1["id"])
    assert row2["remote_id"] == "remote-B"
    assert row2["updated_at"] >= row1["updated_at"]


def test_get_one_returns_inserted_mapping(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    weftid_id = str(uuid4())
    database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="group",
        weftid_id=weftid_id,
        remote_id="group-42",
    )

    out = database.scim_remote_ids.get_one(test_tenant["id"], str(sp["id"]), "group", weftid_id)
    assert out is not None
    assert out["remote_id"] == "group-42"
    assert out["resource_type"] == "group"


# -- unique constraint --------------------------------------------------------


def test_unique_per_sp_resource_weftid(test_tenant, test_user):
    """Different SP, different resource_type, or different weftid_id => new row."""
    sp_a = _create_sp(test_tenant["id"], test_user["id"], name="SP A")
    sp_b = _create_sp(test_tenant["id"], test_user["id"], name="SP B")
    weftid_id = str(uuid4())

    a_user, _ = database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp_a["id"]),
        resource_type="user",
        weftid_id=weftid_id,
        remote_id="remote-A-user",
    )
    b_user, _ = database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp_b["id"]),
        resource_type="user",
        weftid_id=weftid_id,
        remote_id="remote-B-user",
    )
    a_group, _ = database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp_a["id"]),
        resource_type="group",
        weftid_id=weftid_id,
        remote_id="remote-A-group",
    )

    ids = {str(a_user["id"]), str(b_user["id"]), str(a_group["id"])}
    assert len(ids) == 3


# -- delete --------------------------------------------------------------------


def test_delete_removes_mapping(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    weftid_id = str(uuid4())
    database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="user",
        weftid_id=weftid_id,
        remote_id="rid-1",
    )

    affected = database.scim_remote_ids.delete(test_tenant["id"], str(sp["id"]), "user", weftid_id)
    assert affected == 1
    assert (
        database.scim_remote_ids.get_one(test_tenant["id"], str(sp["id"]), "user", weftid_id)
        is None
    )


def test_delete_missing_is_noop(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    affected = database.scim_remote_ids.delete(
        test_tenant["id"], str(sp["id"]), "user", str(uuid4())
    )
    assert affected == 0


# -- get_for_users (batch) -----------------------------------------------------


def test_get_for_users_returns_only_matching_user_mappings(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    u1, u2, u3 = str(uuid4()), str(uuid4()), str(uuid4())

    database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="user",
        weftid_id=u1,
        remote_id="r1",
    )
    database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="user",
        weftid_id=u2,
        remote_id="r2",
    )
    # Same weftid_id but as a group: must NOT appear in the user batch.
    database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="group",
        weftid_id=u3,
        remote_id="g-noise",
    )

    out = database.scim_remote_ids.get_for_users(test_tenant["id"], str(sp["id"]), [u1, u2, u3])
    assert out == {u1: "r1", u2: "r2"}


def test_get_for_users_empty_input_no_db_round_trip(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    assert database.scim_remote_ids.get_for_users(test_tenant["id"], str(sp["id"]), []) == {}


# -- cascade on SP delete ------------------------------------------------------


def test_cascade_on_sp_delete(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"], name="SP to delete")
    weftid_id = str(uuid4())
    database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="user",
        weftid_id=weftid_id,
        remote_id="rid",
    )

    database.service_providers.delete_service_provider(test_tenant["id"], str(sp["id"]))

    assert (
        database.scim_remote_ids.get_one(test_tenant["id"], str(sp["id"]), "user", weftid_id)
        is None
    )


# -- tenant isolation ----------------------------------------------------------


def test_mapping_isolated_across_tenants(test_tenant, test_user):
    other_tenant, other_user = _create_extra_tenant_and_user()
    sp_self = _create_sp(test_tenant["id"], test_user["id"], name="Self SP")
    sp_other = _create_sp(other_tenant["id"], other_user["id"], name="Other SP")
    weftid_id = str(uuid4())

    database.scim_remote_ids.upsert(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp_self["id"]),
        resource_type="user",
        weftid_id=weftid_id,
        remote_id="mine",
    )
    database.scim_remote_ids.upsert(
        tenant_id=other_tenant["id"],
        tenant_id_value=str(other_tenant["id"]),
        sp_id=str(sp_other["id"]),
        resource_type="user",
        weftid_id=weftid_id,
        remote_id="yours",
    )

    # From test_tenant's session, the other tenant's mapping is invisible
    assert (
        database.scim_remote_ids.get_one(test_tenant["id"], str(sp_other["id"]), "user", weftid_id)
        is None
    )
    # And own mapping is visible
    own = database.scim_remote_ids.get_one(test_tenant["id"], str(sp_self["id"]), "user", weftid_id)
    assert own is not None and own["remote_id"] == "mine"
