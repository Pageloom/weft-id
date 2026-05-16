"""Integration test: `enqueue_grant_fan_out` against a real lineage shape.

Builds an ancestor chain `parent -> middle -> leaf` with N users
distributed across the chain, then asserts that assigning the parent
group to a SCIM-enabled SP results in queue rows for every transitive
member plus the parent group itself.
"""

from __future__ import annotations

from uuid import uuid4

import database
from services.scim import dispatch


def _create_sp(tenant_id, user_id, name="Fanout SP", scim_enabled=True):
    sp = database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )
    database.execute(
        tenant_id,
        "update service_providers set scim_enabled = :enabled where id = :sp_id",
        {"enabled": scim_enabled, "sp_id": sp["id"]},
    )
    return sp


def _create_group(tenant_id, name):
    return database.groups.create_group(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=f"{name}-{uuid4().hex[:8]}",
    )


def _create_user(tenant_id):
    from tests.conftest import TEST_PASSWORD_HASH

    user = database.fetchone(
        tenant_id,
        """
        INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
        VALUES (:tenant_id, :ph, 'F', 'U', 'member') RETURNING id
        """,
        {"tenant_id": str(tenant_id), "ph": TEST_PASSWORD_HASH},
    )
    suffix = uuid4().hex[:8]
    database.execute(
        tenant_id,
        """
        INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
        VALUES (:tenant_id, :user_id, :email, true, now())
        """,
        {
            "tenant_id": str(tenant_id),
            "user_id": user["id"],
            "email": f"fan-{suffix}@example.com",
        },
    )
    return user


def test_enqueue_grant_fan_out_walks_full_chain(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])

    # parent -> middle -> leaf
    parent = _create_group(test_tenant["id"], "parent")
    middle = _create_group(test_tenant["id"], "middle")
    leaf = _create_group(test_tenant["id"], "leaf")
    database.groups.add_group_relationship(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(parent["id"]),
        str(middle["id"]),
    )
    database.groups.add_group_relationship(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(middle["id"]),
        str(leaf["id"]),
    )

    # Three users, one per level.
    u_parent = _create_user(test_tenant["id"])
    u_middle = _create_user(test_tenant["id"])
    u_leaf = _create_user(test_tenant["id"])
    database.groups.add_group_member(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(parent["id"]),
        str(u_parent["id"]),
    )
    database.groups.add_group_member(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(middle["id"]),
        str(u_middle["id"]),
    )
    database.groups.add_group_member(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(leaf["id"]),
        str(u_leaf["id"]),
    )

    # Fire the trigger as if "sp_group_assigned" landed on (sp, parent).
    dispatch.enqueue_grant_fan_out(
        str(test_tenant["id"]),
        str(sp["id"]),
        {"group_id": str(parent["id"])},
    )

    # Assert: 3 user rows + 1 group row in scim_push_queue.
    rows = database.fetchall(
        test_tenant["id"],
        """
        select resource_type, resource_id from scim_push_queue
        where sp_id = :sp_id
        order by resource_type, resource_id
        """,
        {"sp_id": str(sp["id"])},
    )
    users = sorted(str(r["resource_id"]) for r in rows if r["resource_type"] == "user")
    groups = [str(r["resource_id"]) for r in rows if r["resource_type"] == "group"]
    assert users == sorted([str(u_parent["id"]), str(u_middle["id"]), str(u_leaf["id"])])
    assert groups == [str(parent["id"])]


def test_enqueue_grant_fan_out_noop_for_non_scim_sp(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=False)
    group = _create_group(test_tenant["id"], "g")
    database.groups.add_group_member(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(group["id"]),
        str(test_user["id"]),
    )

    dispatch.enqueue_grant_fan_out(
        str(test_tenant["id"]),
        str(sp["id"]),
        {"group_id": str(group["id"])},
    )

    count = database.fetchone(
        test_tenant["id"],
        "select count(*) as c from scim_push_queue where sp_id = :sp_id",
        {"sp_id": str(sp["id"])},
    )
    assert count["c"] == 0
