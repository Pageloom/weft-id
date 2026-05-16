"""Integration test: hard delete must enqueue SCIM deprovisioning rows.

`group_memberships.user_id` has `ON DELETE CASCADE`, so by the time the
`enqueue_user_self` trigger fires after the `user_deleted` event, the
user has zero memberships and an unaided scope query resolves zero SPs.
The fix is to pre-resolve the SP scope in `delete_user` before the
deletion, then stash the list on the event metadata. This test exercises
the full path: service call -> cascade delete -> event log -> dispatch ->
queue rows.
"""

from __future__ import annotations

from uuid import uuid4

import database
from services import users as users_service
from services.types import RequestingUser


def _create_sp(tenant_id, user_id, name="HardDelete SP", scim_enabled=True):
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


def _create_member_user(tenant_id):
    from tests.conftest import TEST_PASSWORD_HASH

    suffix = uuid4().hex[:8]
    user = database.fetchone(
        tenant_id,
        """
        INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
        VALUES (:tenant_id, :ph, 'Doomed', 'User', 'member') RETURNING id
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
            "email": f"doomed-{suffix}@example.com",
        },
    )
    return user


def test_hard_delete_user_enqueues_scim_deprovisioning(test_tenant, test_admin_user):
    """End-to-end: deleting a user that has access to a SCIM SP via a
    group grant must produce a `("user", user_id, sp_id)` queue row even
    though the FK cascade clears `group_memberships` first.
    """
    tenant_id = test_tenant["id"]

    sp = _create_sp(tenant_id, test_admin_user["id"])
    group = _create_group(tenant_id, "engineering")
    doomed = _create_member_user(tenant_id)

    database.groups.add_group_member(tenant_id, str(tenant_id), str(group["id"]), str(doomed["id"]))
    database.sp_group_assignments.create_assignment(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        sp_id=str(sp["id"]),
        group_id=str(group["id"]),
        assigned_by=str(test_admin_user["id"]),
    )

    # Sanity: scope resolves the SP before deletion.
    pre_scope = database.scim_scope.scim_sps_granting_user(tenant_id, str(doomed["id"]))
    assert [str(r["id"]) for r in pre_scope] == [str(sp["id"])]

    requesting_user = RequestingUser(
        id=str(test_admin_user["id"]),
        tenant_id=str(tenant_id),
        role="admin",
    )

    users_service.delete_user(requesting_user, str(doomed["id"]))

    # The user row is gone (cascade removed memberships).
    assert database.users.get_user_by_id(tenant_id, str(doomed["id"])) is None

    # And the SCIM dispatch produced a queue row pointing at the SP.
    rows = database.fetchall(
        tenant_id,
        """
        select resource_type, resource_id, sp_id
        from scim_push_queue
        where tenant_id = :tenant_id and resource_id = :user_id
        """,
        {"tenant_id": str(tenant_id), "user_id": str(doomed["id"])},
    )
    sp_ids = {str(r["sp_id"]) for r in rows if r["resource_type"] == "user"}
    assert str(sp["id"]) in sp_ids, (
        f"Expected a deprovisioning queue row for SP {sp['id']}, got {rows!r}"
    )
