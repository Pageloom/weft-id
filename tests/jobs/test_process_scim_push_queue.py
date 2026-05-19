"""Tests for the `process_scim_push_queue` periodic job."""

from __future__ import annotations

from unittest.mock import patch

from jobs.process_scim_push_queue import process_scim_push_queue


def test_returns_empty_summary_when_no_tenants_have_ready_entries() -> None:
    with (
        patch("jobs.process_scim_push_queue.database") as db,
        patch("jobs.process_scim_push_queue.scim_worker") as worker_mod,
    ):
        db.scim_push_queue.list_tenants_with_ready_entries.return_value = []
        result = process_scim_push_queue()

    assert result["tenants_processed"] == 0
    assert result["entries_processed"] == 0
    assert result["details"] == []
    worker_mod.process_pending_pushes.assert_not_called()


def test_calls_worker_for_each_tenant_in_session() -> None:
    with (
        patch("jobs.process_scim_push_queue.database") as db,
        patch("jobs.process_scim_push_queue.scim_worker") as worker_mod,
        patch("jobs.process_scim_push_queue.session") as session_mock,
    ):
        db.scim_push_queue.list_tenants_with_ready_entries.return_value = [
            "tenant-a",
            "tenant-b",
        ]
        worker_mod.process_pending_pushes.side_effect = [
            {
                "entries_processed": 3,
                "succeeded": 2,
                "retried": 1,
                "dead_lettered": 0,
                "skipped": 0,
            },
            {
                "entries_processed": 5,
                "succeeded": 4,
                "retried": 0,
                "dead_lettered": 1,
                "skipped": 0,
            },
        ]
        result = process_scim_push_queue()

    assert result["tenants_processed"] == 2
    assert result["entries_processed"] == 8
    assert result["succeeded"] == 6
    assert result["retried"] == 1
    assert result["dead_lettered"] == 1
    assert worker_mod.process_pending_pushes.call_count == 2
    assert session_mock.call_count == 2
    # Tenants are recorded in details.
    tenant_ids = [d["tenant_id"] for d in result["details"]]
    assert tenant_ids == ["tenant-a", "tenant-b"]


def test_tenant_failure_does_not_block_other_tenants() -> None:
    with (
        patch("jobs.process_scim_push_queue.database") as db,
        patch("jobs.process_scim_push_queue.scim_worker") as worker_mod,
        patch("jobs.process_scim_push_queue.session"),
    ):
        db.scim_push_queue.list_tenants_with_ready_entries.return_value = [
            "bad-tenant",
            "good-tenant",
        ]
        worker_mod.process_pending_pushes.side_effect = [
            RuntimeError("DB blew up"),
            {
                "entries_processed": 1,
                "succeeded": 1,
                "retried": 0,
                "dead_lettered": 0,
                "skipped": 0,
            },
        ]
        result = process_scim_push_queue()

    assert result["tenants_processed"] == 2
    assert result["entries_processed"] == 1
    assert any("error" in d for d in result["details"])
    assert any(d.get("tenant_id") == "good-tenant" for d in result["details"])
