"""Tests for `services.scim.sync_log` (worker-side sync-log helpers)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from services.scim import sync_log

# ---------------------------------------------------------------------------
# retention_to_interval
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("3", "3 months"),
        ("6", "6 months"),
        ("12", "12 months"),
        ("24", "24 months"),
    ],
)
def test_retention_to_interval_maps_known_values(value: str, expected: str) -> None:
    assert sync_log.retention_to_interval(value) == expected


def test_retention_to_interval_forever_returns_none() -> None:
    assert sync_log.retention_to_interval("forever") is None


@pytest.mark.parametrize("bad", ["", "1", "9999", "three", "3 months", " 3 "])
def test_retention_to_interval_rejects_unknown(bad: str) -> None:
    with pytest.raises(ValueError):
        sync_log.retention_to_interval(bad)


# ---------------------------------------------------------------------------
# start_attempt
# ---------------------------------------------------------------------------


def test_start_attempt_inserts_running_row_and_returns_id() -> None:
    started = datetime(2026, 5, 17, 10, 0, tzinfo=UTC)
    with patch("services.scim.sync_log.database") as db:
        db.scim_sync_log.create_entry.return_value = {"id": "log-123"}
        log_id = sync_log.start_attempt(
            tenant_id="tenant-1",
            sp_id="sp-1",
            resource_type="user",
            resource_id="user-1",
            attempt=2,
            started_at=started,
        )

    assert log_id == "log-123"
    db.scim_sync_log.create_entry.assert_called_once_with(
        tenant_id="tenant-1",
        tenant_id_value="tenant-1",
        sp_id="sp-1",
        resource_type="user",
        resource_id="user-1",
        status="running",
        attempt=2,
        started_at=started,
    )


# ---------------------------------------------------------------------------
# terminal-state marker functions
# ---------------------------------------------------------------------------


def test_mark_done_sets_status_done_and_completed_flag() -> None:
    with patch("services.scim.sync_log.database") as db:
        sync_log.mark_done("tenant-1", "log-1")
    db.scim_sync_log.update_status.assert_called_once_with(
        tenant_id="tenant-1",
        entry_id="log-1",
        status="done",
        error=None,
        completed=True,
    )


def test_mark_failed_sets_status_failed_and_error() -> None:
    with patch("services.scim.sync_log.database") as db:
        sync_log.mark_failed("tenant-1", "log-1", "boom")
    db.scim_sync_log.update_status.assert_called_once_with(
        tenant_id="tenant-1",
        entry_id="log-1",
        status="failed",
        error="boom",
        completed=True,
    )


def test_mark_dead_letter_sets_status_dead_letter() -> None:
    with patch("services.scim.sync_log.database") as db:
        sync_log.mark_dead_letter("tenant-1", "log-1", "five strikes")
    db.scim_sync_log.update_status.assert_called_once_with(
        tenant_id="tenant-1",
        entry_id="log-1",
        status="dead_letter",
        error="five strikes",
        completed=True,
    )


def test_mark_failed_truncates_oversize_error() -> None:
    long_error = "X" * 5000
    with patch("services.scim.sync_log.database") as db:
        sync_log.mark_failed("tenant-1", "log-1", long_error)
    call_kwargs = db.scim_sync_log.update_status.call_args.kwargs
    # Service-layer cap is 3900 chars with a 3-char "..." marker -- leaves
    # 100 chars of headroom under the 4000-char column CHECK so future
    # diagnostic prefixes don't blow the DB constraint.
    assert len(call_kwargs["error"]) <= 3900
    assert call_kwargs["error"].endswith("...")
