"""End-to-end-ish integration test for the SCIM push worker.

Real Postgres, real RLS-scoped session. The transport-level HTTP client is
the only external boundary we mock -- the test asserts the SP would have
received the right request and that the queue/sync-log mutations land as
expected.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import database
from database._core import execute
from services.scim import client as scim_client
from services.scim import worker as scim_worker


def _create_scim_enabled_sp(tenant_id, user_id, *, available_to_all=True):
    sp = database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name="Integration SP",
        created_by=str(user_id),
    )
    execute(
        tenant_id,
        """
        update service_providers
        set scim_enabled = true,
            scim_target_url = 'https://scim.example.com/scim/v2',
            scim_kind = 'generic',
            scim_membership_mode = 'effective',
            scim_log_retention = '3',
            available_to_all = :ata
        where id = :id
        """,
        {"id": sp["id"], "ata": available_to_all},
    )
    return sp


def test_worker_drains_queue_writes_sync_log_on_success(test_tenant, test_user):
    sp = _create_scim_enabled_sp(test_tenant["id"], test_user["id"])

    # Enqueue a push for the existing test_user.
    database.scim_push_queue.upsert_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(test_user["id"]),
    )
    pending_before = database.scim_push_queue.count_pending_for_sp(test_tenant["id"], sp["id"])
    assert pending_before["pending"] == 1

    success = scim_client.PushResult(
        status="success", http_status=201, reason=None, scim_id="ext-1"
    )
    with patch("services.scim.worker.scim_client.push_user", return_value=success) as push_mock:
        result = scim_worker.process_pending_pushes(
            str(test_tenant["id"]),
            token_resolver=lambda _t, _s: "test-token",
        )

    assert result["succeeded"] == 1
    push_mock.assert_called_once()
    # The SP target dict is passed in; assert it carries the URL.
    sent_sp = push_mock.call_args.args[0]
    assert sent_sp["scim_target_url"] == "https://scim.example.com/scim/v2"
    sent_resource = push_mock.call_args.args[1]
    assert sent_resource["userName"] == test_user["email"]

    # Queue drained, sync-log row in done state.
    pending_after = database.scim_push_queue.count_pending_for_sp(test_tenant["id"], sp["id"])
    assert pending_after["pending"] == 0
    log_rows = database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"])
    assert len(log_rows) == 1
    assert log_rows[0]["status"] == "done"
    assert log_rows[0]["completed_at"] is not None


def test_worker_dead_letters_after_repeated_retryable_failures(test_tenant, test_user):
    sp = _create_scim_enabled_sp(test_tenant["id"], test_user["id"])
    database.scim_push_queue.upsert_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(test_user["id"]),
    )

    retryable = scim_client.PushResult(
        status="retryable", http_status=503, reason="service down", scim_id=None
    )
    with patch("services.scim.worker.scim_client.push_user", return_value=retryable):
        # 5 consecutive worker passes, each one returning a retryable failure.
        # The 5th must dead-letter the entry.
        for run in range(5):
            # Simulate scheduler clearing next_attempt_at so each run picks it up.
            execute(
                test_tenant["id"],
                "update scim_push_queue set next_attempt_at = null where sp_id = :sp_id",
                {"sp_id": sp["id"]},
            )
            scim_worker.process_pending_pushes(
                str(test_tenant["id"]),
                token_resolver=lambda _t, _s: "test-token",
            )

    counts = database.scim_push_queue.count_pending_for_sp(test_tenant["id"], sp["id"])
    assert counts["pending"] == 0
    assert counts["dead_lettered"] == 1
    log_rows = database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"])
    statuses = [r["status"] for r in log_rows]
    assert statuses[0] == "dead_letter"
    # 5 attempts -> 5 sync-log rows total.
    assert len(log_rows) == 5


def test_worker_skips_entry_when_sp_disabled_mid_flight(test_tenant, test_user):
    sp = _create_scim_enabled_sp(test_tenant["id"], test_user["id"])
    database.scim_push_queue.upsert_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(test_user["id"]),
    )
    # Admin disables SCIM on the SP before the worker runs.
    execute(
        test_tenant["id"],
        "update service_providers set scim_enabled = false where id = :id",
        {"id": sp["id"]},
    )

    result = scim_worker.process_pending_pushes(
        str(test_tenant["id"]),
        token_resolver=lambda _t, _s: "test-token",
    )
    assert result["skipped"] == 1
    counts = database.scim_push_queue.count_pending_for_sp(test_tenant["id"], sp["id"])
    assert counts["pending"] == 0
    log_rows = database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"])
    assert len(log_rows) == 1
    assert log_rows[0]["status"] == "dead_letter"


def test_cleanup_job_deletes_log_rows_past_retention(test_tenant, test_user):
    """Per-SP retention sweep removes only completed-and-old rows."""
    from datetime import UTC, datetime, timedelta

    from jobs.cleanup_scim_sync_log import cleanup_scim_sync_log

    sp = _create_scim_enabled_sp(test_tenant["id"], test_user["id"])
    # Override retention to "3" months (the default).
    execute(
        test_tenant["id"],
        "update service_providers set scim_log_retention = '3' where id = :id",
        {"id": sp["id"]},
    )

    # Insert an old completed row and a recent completed row.
    old_completed = datetime.now(UTC) - timedelta(days=200)
    recent = database.scim_sync_log.create_entry(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="user",
        resource_id=str(uuid4()),
        status="done",
        attempt=1,
        started_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    old = database.scim_sync_log.create_entry(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=str(sp["id"]),
        resource_type="user",
        resource_id=str(uuid4()),
        status="done",
        attempt=1,
        started_at=old_completed,
    )
    # Mark both completed; backdate the "old" one's completed_at via SQL.
    database.scim_sync_log.update_status(
        test_tenant["id"], str(recent["id"]), "done", completed=True
    )
    database.scim_sync_log.update_status(test_tenant["id"], str(old["id"]), "done", completed=True)
    execute(
        test_tenant["id"],
        "update scim_sync_log set completed_at = :ts where id = :id",
        {"ts": old_completed, "id": str(old["id"])},
    )

    result = cleanup_scim_sync_log()
    assert result["rows_deleted"] >= 1

    remaining_ids = {
        str(r["id"])
        for r in database.scim_sync_log.list_recent_for_sp(
            test_tenant["id"], str(sp["id"]), limit=10
        )
    }
    assert str(recent["id"]) in remaining_ids
    assert str(old["id"]) not in remaining_ids
