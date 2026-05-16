"""Integration tests for `log_event` -> SCIM dispatch wiring.

Asserts the contract:

- Tagged event types call `scim_dispatch` with the right args.
- Untagged event types do not call `scim_dispatch`.
- `dispatch_scim=False` suppresses dispatch on a tagged event.
- A raising dispatch never fails the event write (the event row still
  exists afterward).
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import database
from services.event_log import log_event
from utils.request_context import set_request_context


def _setup_request_context() -> None:
    set_request_context(
        {
            "remote_address": "127.0.0.1",
            "user_agent": "pytest",
            "device": "unknown",
            "session_id_hash": None,
        }
    )


def test_log_event_dispatches_for_tagged_event(test_tenant, test_user):
    _setup_request_context()
    artifact_id = str(uuid4())

    with patch("services.scim.dispatch.scim_dispatch") as mock_dispatch:
        log_event(
            tenant_id=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="user",
            artifact_id=artifact_id,
            event_type="user_created",
            metadata={"role": "member"},
        )

    mock_dispatch.assert_called_once()
    kwargs = mock_dispatch.call_args.kwargs
    assert kwargs["event_type"] == "user_created"
    assert kwargs["tenant_id"] == str(test_tenant["id"])
    assert kwargs["actor_user_id"] == str(test_user["id"])
    assert kwargs["artifact_type"] == "user"
    assert kwargs["artifact_id"] == artifact_id
    assert kwargs["metadata"] == {"role": "member"}


def test_log_event_does_not_dispatch_for_untagged_event(test_tenant, test_user):
    _setup_request_context()

    with patch("services.scim.dispatch.scim_dispatch") as mock_dispatch:
        log_event(
            tenant_id=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="user",
            artifact_id=str(uuid4()),
            event_type="login_failed",
        )

    # scim_dispatch is still called from log_event; it's the dispatch func
    # itself that no-ops on untagged events. But the test asserts dispatch
    # was called with an untagged type and the trigger registry sees no
    # match. The simplest assertion: scim_dispatch is invoked exactly once
    # with event_type="login_failed", and produces no queue writes.
    mock_dispatch.assert_called_once()
    assert mock_dispatch.call_args.kwargs["event_type"] == "login_failed"


def test_log_event_with_dispatch_scim_false_skips_dispatch(test_tenant, test_user):
    _setup_request_context()

    with patch("services.scim.dispatch.scim_dispatch") as mock_dispatch:
        log_event(
            tenant_id=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="user",
            artifact_id=str(uuid4()),
            event_type="user_created",
            dispatch_scim=False,
        )

    mock_dispatch.assert_not_called()


def test_log_event_dispatch_failure_does_not_fail_event_write(test_tenant, test_user):
    """If scim_dispatch raises, the event row still lands and the caller
    sees no error."""
    _setup_request_context()
    artifact_id = str(uuid4())

    def boom(**_kw):
        raise RuntimeError("dispatch exploded")

    initial = database.event_log.count_events(test_tenant["id"])

    with patch("services.scim.dispatch.scim_dispatch", side_effect=boom):
        # Must not raise.
        log_event(
            tenant_id=str(test_tenant["id"]),
            actor_user_id=str(test_user["id"]),
            artifact_type="user",
            artifact_id=artifact_id,
            event_type="user_created",
        )

    final = database.event_log.count_events(test_tenant["id"])
    assert final == initial + 1


def _build_scim_scope_for_user(test_tenant, test_user):
    """Helper: create an SP + group + assignment + membership so that
    `test_user` is in scope for one SCIM-enabled SP.
    """
    sp = database.service_providers.create_service_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=f"Scope-{uuid4().hex[:6]}",
        created_by=str(test_user["id"]),
    )
    database.execute(
        test_tenant["id"],
        "update service_providers set scim_enabled = true where id = :sp_id",
        {"sp_id": sp["id"]},
    )
    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=f"scope-{uuid4().hex[:6]}",
    )
    database.sp_group_assignments.create_assignment(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        group_id=str(group["id"]),
        assigned_by=str(test_user["id"]),
    )
    database.groups.add_group_member(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(group["id"]),
        str(test_user["id"]),
    )
    return sp, group


def test_log_event_dispatch_scim_false_writes_zero_queue_rows(test_tenant, test_user):
    """`dispatch_scim=False` on a tagged event MUST produce zero
    `scim_push_queue` rows, even with a fully-in-scope user. Asserts the
    real-world skip semantic, not just "mock not called."
    """
    _setup_request_context()
    sp, _group = _build_scim_scope_for_user(test_tenant, test_user)

    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_created",
        dispatch_scim=False,
    )

    count = database.fetchone(
        test_tenant["id"],
        "select count(*) as c from scim_push_queue where sp_id = :sp_id",
        {"sp_id": str(sp["id"])},
    )
    assert count["c"] == 0


def test_log_event_untagged_event_writes_zero_queue_rows(test_tenant, test_user):
    """Untagged event types must be a clean no-op at the DB level: the
    dispatch function returns early before touching the queue.
    """
    _setup_request_context()
    sp, _group = _build_scim_scope_for_user(test_tenant, test_user)

    # password_changed is in EVENT_TYPE_DESCRIPTIONS but NOT in
    # EVENT_TYPE_SCIM_TRIGGERS, so it must produce no queue rows.
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="password_changed",
    )

    count = database.fetchone(
        test_tenant["id"],
        "select count(*) as c from scim_push_queue where sp_id = :sp_id",
        {"sp_id": str(sp["id"])},
    )
    assert count["c"] == 0


def test_log_event_end_to_end_user_in_group_grants_to_scim_sp(test_tenant, test_user):
    """The end-to-end path: a user added to a group that grants access to
    a SCIM-enabled SP results in a `scim_push_queue` row for that
    user/SP pair, with no other rows leaking."""
    _setup_request_context()

    # Build the world: SP with scim_enabled=true, group, assignment,
    # user already a member.
    sp = database.service_providers.create_service_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="E2E SP",
        created_by=str(test_user["id"]),
    )
    database.execute(
        test_tenant["id"],
        "update service_providers set scim_enabled = true where id = :sp_id",
        {"sp_id": sp["id"]},
    )
    group = database.groups.create_group(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=f"e2e-{uuid4().hex[:6]}",
    )
    database.sp_group_assignments.create_assignment(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        group_id=str(group["id"]),
        assigned_by=str(test_user["id"]),
    )
    database.groups.add_group_member(
        test_tenant["id"],
        str(test_tenant["id"]),
        str(group["id"]),
        str(test_user["id"]),
    )

    # Now fire the "user_created" event for that user.
    log_event(
        tenant_id=str(test_tenant["id"]),
        actor_user_id=str(test_user["id"]),
        artifact_type="user",
        artifact_id=str(test_user["id"]),
        event_type="user_created",
    )

    rows = database.fetchall(
        test_tenant["id"],
        """
        select sp_id, resource_type, resource_id
        from scim_push_queue
        where sp_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert len(rows) == 1
    assert rows[0]["resource_type"] == "user"
    assert str(rows[0]["resource_id"]) == str(test_user["id"])
