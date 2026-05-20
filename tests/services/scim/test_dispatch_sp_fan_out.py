"""Tests for the `enqueue_sp_tenant_fan_out` dispatch trigger.

Covers the iteration 5 acceptance criterion: when an admin flips
`available_to_all` on a SCIM-enabled SP, every tenant user is enqueued.
The trigger is event-log driven via the `sp_access_mode_updated` event
type registered in `EVENT_TYPE_SCIM_TRIGGERS`.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import database
from constants.event_types import EVENT_TYPE_SCIM_TRIGGERS
from services.scim import dispatch as scim_dispatch


def _create_sp(tenant_id, user_id, scim_enabled=True):
    sp = database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=f"SP-{uuid4().hex[:8]}",
        created_by=str(user_id),
    )
    database.execute(
        tenant_id,
        "update service_providers set scim_enabled = :enabled where id = :sp_id",
        {"enabled": scim_enabled, "sp_id": sp["id"]},
    )
    return sp


def _create_user(tenant_id):
    from tests.conftest import TEST_PASSWORD_HASH

    user = database.fetchone(
        tenant_id,
        """
        INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
        VALUES (:tenant_id, :ph, 'F', 'L', 'member')
        RETURNING id
        """,
        {"tenant_id": str(tenant_id), "ph": TEST_PASSWORD_HASH},
    )
    return user


def test_event_type_registered():
    """`sp_access_mode_updated` must be tagged with the fan-out trigger."""
    assert EVENT_TYPE_SCIM_TRIGGERS["sp_access_mode_updated"] == "enqueue_sp_tenant_fan_out"


def test_fan_out_enqueues_every_tenant_user_on_false_to_true(test_tenant, test_user):
    """false -> true: every tenant user gets a queue row for that SP."""
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)
    user_b = _create_user(test_tenant["id"])
    user_c = _create_user(test_tenant["id"])

    scim_dispatch.enqueue_sp_tenant_fan_out(
        str(test_tenant["id"]),
        str(sp["id"]),
        {"available_to_all": True, "previous_available_to_all": False},
    )

    rows = database.fetchall(
        test_tenant["id"],
        """
        select resource_id from scim_push_queue
        where sp_id = :sp_id and resource_type = 'user'
        """,
        {"sp_id": str(sp["id"])},
    )
    enqueued = {str(r["resource_id"]) for r in rows}
    assert str(test_user["id"]) in enqueued
    assert str(user_b["id"]) in enqueued
    assert str(user_c["id"]) in enqueued


def test_fan_out_enqueues_every_tenant_user_on_true_to_false(test_tenant, test_user):
    """true -> false: same fan-out so the worker can re-evaluate scope per user."""
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)
    user_b = _create_user(test_tenant["id"])

    scim_dispatch.enqueue_sp_tenant_fan_out(
        str(test_tenant["id"]),
        str(sp["id"]),
        {"available_to_all": False, "previous_available_to_all": True},
    )

    rows = database.fetchall(
        test_tenant["id"],
        """
        select resource_id from scim_push_queue
        where sp_id = :sp_id and resource_type = 'user'
        """,
        {"sp_id": str(sp["id"])},
    )
    enqueued = {str(r["resource_id"]) for r in rows}
    assert str(test_user["id"]) in enqueued
    assert str(user_b["id"]) in enqueued


def test_fan_out_skips_when_value_unchanged(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)

    scim_dispatch.enqueue_sp_tenant_fan_out(
        str(test_tenant["id"]),
        str(sp["id"]),
        {"available_to_all": True, "previous_available_to_all": True},
    )

    rows = database.fetchall(
        test_tenant["id"],
        "select 1 from scim_push_queue where sp_id = :sp_id",
        {"sp_id": str(sp["id"])},
    )
    assert rows == []


def test_fan_out_skips_when_scim_not_enabled(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=False)

    scim_dispatch.enqueue_sp_tenant_fan_out(
        str(test_tenant["id"]),
        str(sp["id"]),
        {"available_to_all": True, "previous_available_to_all": False},
    )

    rows = database.fetchall(
        test_tenant["id"],
        "select 1 from scim_push_queue where sp_id = :sp_id",
        {"sp_id": str(sp["id"])},
    )
    assert rows == []


def test_fan_out_skips_when_metadata_missing(test_tenant, test_user):
    """Missing `available_to_all` means we cannot tell what changed."""
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)

    scim_dispatch.enqueue_sp_tenant_fan_out(
        str(test_tenant["id"]),
        str(sp["id"]),
        {},
    )

    rows = database.fetchall(
        test_tenant["id"],
        "select 1 from scim_push_queue where sp_id = :sp_id",
        {"sp_id": str(sp["id"])},
    )
    assert rows == []


def test_fan_out_swallows_user_lookup_failure(test_tenant, test_user):
    """Best-effort: a database failure inside the trigger must not raise."""
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)

    with patch(
        "database.scim_scope.tenant_user_ids",
        side_effect=RuntimeError("boom"),
    ):
        scim_dispatch.enqueue_sp_tenant_fan_out(
            str(test_tenant["id"]),
            str(sp["id"]),
            {"available_to_all": True, "previous_available_to_all": False},
        )

    rows = database.fetchall(
        test_tenant["id"],
        "select 1 from scim_push_queue where sp_id = :sp_id",
        {"sp_id": str(sp["id"])},
    )
    assert rows == []


def test_event_log_dispatches_through_log_event(test_tenant, test_user):
    """Wire test: writing the event via log_event() triggers the fan-out."""
    from services.event_log import log_event

    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)

    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="service_provider",
        artifact_id=str(sp["id"]),
        event_type="sp_access_mode_updated",
        metadata={"available_to_all": True, "previous_available_to_all": False},
    )

    rows = database.fetchall(
        test_tenant["id"],
        """
        select resource_id from scim_push_queue
        where sp_id = :sp_id and resource_type = 'user'
        """,
        {"sp_id": str(sp["id"])},
    )
    assert str(test_user["id"]) in {str(r["resource_id"]) for r in rows}
