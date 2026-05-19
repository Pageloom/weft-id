"""Tests for `services.scim.worker.process_pending_pushes`.

The worker is exercised end-to-end with mocks at the database and HTTP-
client boundaries so each test can drive a specific path (success,
retryable failure with backoff, permanent failure with dead-letter,
no-longer-in-scope -> DELETE, missing SP, missing credential) without
spinning real Postgres or HTTPX.

The `database` module is replaced wholesale for each test via `patch`,
mirroring the pattern used by the other SCIM service tests.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from services.scim import client as scim_client
from services.scim import worker


def _entry(
    sp_id: str = "sp-1",
    resource_type: str = "user",
    resource_id: str = "user-1",
    attempts: int = 0,
    entry_id: str | None = None,
) -> dict:
    return {
        "id": entry_id or str(uuid4()),
        "sp_id": sp_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "attempts": attempts,
        "next_attempt_at": None,
        "last_error": None,
        "dead_letter_at": None,
    }


def _sp(
    sp_id: str = "sp-1",
    scim_enabled: bool = True,
    target_url: str = "https://scim.example.com/scim/v2",
    kind: str = "generic",
    membership_mode: str = "effective",
) -> dict:
    return {
        "id": sp_id,
        "name": "Test SP",
        "scim_enabled": scim_enabled,
        "scim_target_url": target_url,
        "scim_kind": kind,
        "scim_membership_mode": membership_mode,
        "scim_log_retention": "3",
        "available_to_all": False,
    }


@pytest.fixture
def fake_now() -> datetime:
    return datetime(2026, 5, 17, 12, 0, tzinfo=UTC)


def _build_db_mock(
    *,
    queue_entries: list[dict],
    sp: dict | None,
    user_with_email: dict | None = None,
    user_full: dict | None = None,
    scope_sps: list[dict] | None = None,
    group_row: dict | None = None,
    group_members: list[list[dict]] | None = None,
    new_log_id: str = "log-1",
) -> MagicMock:
    db = MagicMock()
    db.scim_push_queue.list_ready_entries.return_value = queue_entries
    db.service_providers.get_scim_target.return_value = sp
    db.user_emails.get_user_with_primary_email.return_value = user_with_email
    db.users.get_user_by_id.return_value = user_full
    db.scim_scope.scim_sps_granting_user.return_value = scope_sps or []
    db.groups.get_group_by_id.return_value = group_row
    db.groups.get_effective_members.side_effect = group_members or [[], []]
    db.scim_sync_log.create_entry.return_value = {"id": new_log_id}
    return db


# ---------------------------------------------------------------------------
# Empty / skipped paths
# ---------------------------------------------------------------------------


def test_returns_empty_summary_when_no_ready_entries(fake_now: datetime) -> None:
    db = _build_db_mock(queue_entries=[], sp=None)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
    ):
        result = worker.process_pending_pushes("tenant-1", now=fake_now)
    assert result == {
        "entries_processed": 0,
        "succeeded": 0,
        "retried": 0,
        "dead_lettered": 0,
        "skipped": 0,
    }
    db.service_providers.get_scim_target.assert_not_called()


def test_drops_entries_when_sp_no_longer_exists(fake_now: datetime) -> None:
    entry = _entry()
    db = _build_db_mock(queue_entries=[entry], sp=None)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["skipped"] == 1
    assert result["entries_processed"] == 1
    db.scim_push_queue.delete_entry.assert_called_once_with("tenant-1", entry["id"])
    # A sync-log row was written and dead-lettered for visibility.
    db.scim_sync_log.create_entry.assert_called_once()
    db.scim_sync_log.update_status.assert_called_once()
    assert db.scim_sync_log.update_status.call_args.kwargs["status"] == "dead_letter"


def test_drops_entries_when_sp_has_scim_disabled(fake_now: datetime) -> None:
    entry = _entry()
    sp = _sp(scim_enabled=False)
    db = _build_db_mock(queue_entries=[entry], sp=sp)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["skipped"] == 1
    db.scim_push_queue.delete_entry.assert_called_once_with("tenant-1", entry["id"])


def test_drops_entries_when_sp_has_no_target_url(fake_now: datetime) -> None:
    entry = _entry()
    sp = _sp()
    sp["scim_target_url"] = None
    db = _build_db_mock(queue_entries=[entry], sp=sp)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["skipped"] == 1


# ---------------------------------------------------------------------------
# Missing credential
# ---------------------------------------------------------------------------


def test_dead_letters_when_token_resolver_returns_none(fake_now: datetime) -> None:
    entry = _entry()
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1", "first_name": "Test"},
        scope_sps=[{"id": "sp-1", "scim_membership_mode": "effective"}],
    )
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
    ):
        result = worker.process_pending_pushes(
            "tenant-1",
            now=fake_now,
            token_resolver=lambda _t, _s: None,
        )
    assert result["dead_lettered"] == 1
    db.scim_push_queue.mark_dead_letter.assert_called_once()
    reason = db.scim_push_queue.mark_dead_letter.call_args.kwargs["error"]
    assert "no_credential_source" in reason


def test_default_token_resolver_returns_none() -> None:
    # The placeholder resolver intentionally returns None until iteration 5
    # adds an encrypted credential store. Lock that contract in so a
    # behavior change is a conscious decision.
    assert worker._default_token_resolver("tenant", "sp") is None


# ---------------------------------------------------------------------------
# User push: success path
# ---------------------------------------------------------------------------


def test_successful_user_push_deletes_queue_and_marks_log_done(
    fake_now: datetime,
) -> None:
    entry = _entry()
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={
            "id": "user-1",
            "first_name": "Test",
            "last_name": "User",
            "is_inactivated": False,
        },
        scope_sps=[{"id": "sp-1", "scim_membership_mode": "effective"}],
        new_log_id="log-success",
    )
    success = scim_client.PushResult(
        status="success", http_status=201, reason=None, scim_id="ext-1"
    )
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch("services.scim.worker.scim_client.push_user", return_value=success) as push_user_mock,
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )

    assert result["succeeded"] == 1
    db.scim_push_queue.delete_entry.assert_called_once_with("tenant-1", entry["id"])
    db.scim_sync_log.update_status.assert_called_once()
    update_kwargs = db.scim_sync_log.update_status.call_args.kwargs
    assert update_kwargs["status"] == "done"
    assert update_kwargs["entry_id"] == "log-success"
    assert update_kwargs["completed"] is True
    push_user_mock.assert_called_once()


def test_user_no_longer_in_scope_pushes_delete(fake_now: datetime) -> None:
    """A user with primary email but no granting SP must be DELETED."""
    entry = _entry()
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[],  # not in scope for any SP
    )
    success = scim_client.PushResult(status="success", http_status=204, reason=None, scim_id=None)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch(
            "services.scim.worker.scim_client.delete_user", return_value=success
        ) as delete_user_mock,
        patch("services.scim.worker.scim_client.push_user") as push_user_mock,
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )

    assert result["succeeded"] == 1
    delete_user_mock.assert_called_once()
    push_user_mock.assert_not_called()


def test_user_completely_gone_pushes_delete(fake_now: datetime) -> None:
    entry = _entry()
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        user_with_email=None,  # primary-email lookup returns nothing
    )
    success = scim_client.PushResult(status="success", http_status=204, reason=None, scim_id=None)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch(
            "services.scim.worker.scim_client.delete_user", return_value=success
        ) as delete_user_mock,
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )

    assert result["succeeded"] == 1
    delete_user_mock.assert_called_once()


# ---------------------------------------------------------------------------
# Retryable failure -> backoff schedule + dead-letter cap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "current_attempts,expected_delay",
    [
        (0, timedelta(minutes=1)),  # after 1st failure -> wait 1m before 2nd
        (1, timedelta(minutes=5)),  # after 2nd failure -> wait 5m before 3rd
        (2, timedelta(minutes=30)),  # after 3rd failure -> wait 30m
        (3, timedelta(hours=2)),  # after 4th failure -> wait 2h
    ],
)
def test_retryable_failure_schedules_correct_backoff(
    fake_now: datetime,
    current_attempts: int,
    expected_delay: timedelta,
) -> None:
    entry = _entry(attempts=current_attempts)
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[{"id": "sp-1", "scim_membership_mode": "effective"}],
    )
    retryable = scim_client.PushResult(
        status="retryable", http_status=503, reason="service unavailable", scim_id=None
    )
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch("services.scim.worker.scim_client.push_user", return_value=retryable),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )

    assert result["retried"] == 1
    db.scim_push_queue.mark_attempt_failed.assert_called_once()
    call_kwargs = db.scim_push_queue.mark_attempt_failed.call_args.kwargs
    assert call_kwargs["next_attempt_at"] == fake_now + expected_delay
    # Sync log marked failed (terminal state for this attempt).
    update_kwargs = db.scim_sync_log.update_status.call_args.kwargs
    assert update_kwargs["status"] == "failed"


def test_retryable_failure_after_first_attempt_uses_one_minute(
    fake_now: datetime,
) -> None:
    """A brand-new entry that fails its 1st attempt is scheduled 1 minute later."""
    entry = _entry(attempts=0)
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[{"id": "sp-1", "scim_membership_mode": "effective"}],
    )
    retryable = scim_client.PushResult(
        status="retryable", http_status=503, reason="oops", scim_id=None
    )
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch("services.scim.worker.scim_client.push_user", return_value=retryable),
    ):
        worker.process_pending_pushes("tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok")
    call_kwargs = db.scim_push_queue.mark_attempt_failed.call_args.kwargs
    assert call_kwargs["next_attempt_at"] == fake_now + timedelta(minutes=1)


def test_fifth_failed_attempt_dead_letters(fake_now: datetime) -> None:
    """After 5 total failed attempts the entry is dead-lettered."""
    # Entry has already failed 4 times; this run is the 5th attempt.
    entry = _entry(attempts=4)
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[{"id": "sp-1", "scim_membership_mode": "effective"}],
    )
    retryable = scim_client.PushResult(
        status="retryable", http_status=503, reason="still failing", scim_id=None
    )
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch("services.scim.worker.scim_client.push_user", return_value=retryable),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )

    assert result["dead_lettered"] == 1
    db.scim_push_queue.mark_dead_letter.assert_called_once()
    db.scim_push_queue.mark_attempt_failed.assert_not_called()
    update_kwargs = db.scim_sync_log.update_status.call_args.kwargs
    assert update_kwargs["status"] == "dead_letter"


def test_permanent_failure_dead_letters_immediately(fake_now: datetime) -> None:
    entry = _entry(attempts=0)
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[{"id": "sp-1", "scim_membership_mode": "effective"}],
    )
    permanent = scim_client.PushResult(
        status="permanent", http_status=400, reason="bad payload", scim_id=None
    )
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch("services.scim.worker.scim_client.push_user", return_value=permanent),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )

    assert result["dead_lettered"] == 1
    db.scim_push_queue.mark_dead_letter.assert_called_once()
    reason = db.scim_push_queue.mark_dead_letter.call_args.kwargs["error"]
    assert "http=400" in reason
    assert "bad payload" in reason


# ---------------------------------------------------------------------------
# Group push
# ---------------------------------------------------------------------------


def test_successful_group_push_with_effective_members(fake_now: datetime) -> None:
    entry = _entry(resource_type="group", resource_id="group-1")
    sp = _sp(membership_mode="effective")
    members_page = [
        {
            "user_id": "user-a",
            "is_direct": True,
            "email": "a@example.com",
            "first_name": "A",
            "last_name": "Alpha",
        },
        {
            "user_id": "user-b",
            "is_direct": False,
            "email": "b@example.com",
            "first_name": "B",
            "last_name": "Beta",
        },
    ]
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        group_row={"id": "group-1", "name": "Engineers"},
        group_members=[members_page, []],
    )
    success = scim_client.PushResult(
        status="success", http_status=201, reason=None, scim_id="g-ext-1"
    )
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch(
            "services.scim.worker.scim_client.push_group", return_value=success
        ) as push_group_mock,
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )

    assert result["succeeded"] == 1
    push_group_mock.assert_called_once()
    sent_resource = push_group_mock.call_args.args[1]
    assert sent_resource["displayName"] == "Engineers"
    assert len(sent_resource["members"]) == 2


def test_group_direct_mode_filters_indirect_members(fake_now: datetime) -> None:
    entry = _entry(resource_type="group", resource_id="group-1")
    sp = _sp(membership_mode="direct")
    members_page = [
        {
            "user_id": "user-a",
            "is_direct": True,
            "email": "a@example.com",
        },
        {
            "user_id": "user-b",
            "is_direct": False,
            "email": "b@example.com",
        },
    ]
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        group_row={"id": "group-1", "name": "Engineers"},
        group_members=[members_page, []],
    )
    success = scim_client.PushResult(status="success", http_status=201, reason=None, scim_id=None)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch(
            "services.scim.worker.scim_client.push_group", return_value=success
        ) as push_group_mock,
    ):
        worker.process_pending_pushes("tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok")
    sent_resource = push_group_mock.call_args.args[1]
    assert [m["value"] for m in sent_resource["members"]] == ["user-a"]


def test_deleted_group_pushes_delete(fake_now: datetime) -> None:
    entry = _entry(resource_type="group", resource_id="group-gone")
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        group_row=None,
    )
    success = scim_client.PushResult(status="success", http_status=204, reason=None, scim_id=None)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch(
            "services.scim.worker.scim_client.delete_group", return_value=success
        ) as delete_group_mock,
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )
    assert result["succeeded"] == 1
    delete_group_mock.assert_called_once()


# ---------------------------------------------------------------------------
# Per-SP sequencing & multi-SP fan-out
# ---------------------------------------------------------------------------


def test_multiple_sps_each_processed_with_own_token(fake_now: datetime) -> None:
    """Entries for multiple SPs all process; each gets its SP's token."""
    e1 = _entry(sp_id="sp-1", resource_id="user-1")
    e2 = _entry(sp_id="sp-2", resource_id="user-1")
    sp1 = _sp(sp_id="sp-1")
    sp2 = _sp(sp_id="sp-2", target_url="https://scim2.example.com/scim/v2")

    def get_sp(_tenant: Any, sp_id: str) -> dict:
        return {"sp-1": sp1, "sp-2": sp2}[sp_id]

    def resolver(_tenant: str, sp_id: str) -> str:
        return f"tok-{sp_id}"

    db = _build_db_mock(
        queue_entries=[e1, e2],
        sp=sp1,
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[
            {"id": "sp-1", "scim_membership_mode": "effective"},
            {"id": "sp-2", "scim_membership_mode": "effective"},
        ],
    )
    db.service_providers.get_scim_target.side_effect = get_sp
    success = scim_client.PushResult(status="success", http_status=201, reason=None, scim_id=None)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch("services.scim.worker.scim_client.push_user", return_value=success) as push_user_mock,
    ):
        result = worker.process_pending_pushes("tenant-1", now=fake_now, token_resolver=resolver)

    assert result["succeeded"] == 2
    tokens_used = [c.kwargs["token"] for c in push_user_mock.call_args_list]
    assert sorted(tokens_used) == ["tok-sp-1", "tok-sp-2"]


def test_worker_exception_records_retryable_failure(fake_now: datetime) -> None:
    """A programmer error inside the worker is treated as retryable."""
    entry = _entry(attempts=0)
    sp = _sp()
    db = _build_db_mock(
        queue_entries=[entry],
        sp=sp,
        user_with_email={"id": "user-1", "email": "u@example.com"},
        user_full={"id": "user-1"},
        scope_sps=[{"id": "sp-1", "scim_membership_mode": "effective"}],
    )
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
        patch(
            "services.scim.worker.scim_client.push_user",
            side_effect=RuntimeError("boom"),
        ),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )

    assert result["retried"] == 1
    reason = db.scim_push_queue.mark_attempt_failed.call_args.kwargs["error"]
    assert "worker_exception" in reason
    assert "RuntimeError" in reason


def test_unknown_resource_type_dead_letters_immediately(fake_now: datetime) -> None:
    """Unknown resource_type values are permanent; no retry budget burn."""
    entry = _entry(resource_type="widget", resource_id="thing-1")
    sp = _sp()
    db = _build_db_mock(queue_entries=[entry], sp=sp)
    with (
        patch("services.scim.worker.database", db),
        patch("services.scim.sync_log.database", db),
    ):
        result = worker.process_pending_pushes(
            "tenant-1", now=fake_now, token_resolver=lambda _t, _s: "tok"
        )

    assert result["dead_lettered"] == 1
    assert result["retried"] == 0
    db.scim_push_queue.mark_attempt_failed.assert_not_called()
    db.scim_push_queue.mark_dead_letter.assert_called_once()
    reason = db.scim_push_queue.mark_dead_letter.call_args.kwargs["error"]
    assert "unknown_resource_type" in reason
