"""Tests for `services.scim.remote_ids` (audit-aware mapping helpers)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from services.scim import remote_ids


def _patch_helpers(db: MagicMock, log_event: MagicMock):
    """Patch the module-level `database` and `log_event` references."""
    return (
        patch("services.scim.remote_ids.database", db),
        patch("services.scim.remote_ids.log_event", log_event),
    )


# ---------------------------------------------------------------------------
# record_mapping
# ---------------------------------------------------------------------------


def test_record_mapping_emits_event_on_first_insert() -> None:
    """Audit event fires only when the upsert reports `was_inserted=True`."""
    db = MagicMock()
    db.scim_remote_ids.upsert.return_value = ({"id": "row-1", "remote_id": "rA"}, True)
    log_event = MagicMock()
    p1, p2 = _patch_helpers(db, log_event)
    with p1, p2:
        remote_ids.record_mapping(
            tenant_id="t-1",
            sp_id="sp-1",
            resource_type="user",
            weftid_id="user-1",
            remote_id="rA",
        )

    db.scim_remote_ids.upsert.assert_called_once_with(
        tenant_id="t-1",
        tenant_id_value="t-1",
        sp_id="sp-1",
        resource_type="user",
        weftid_id="user-1",
        remote_id="rA",
    )
    log_event.assert_called_once()
    assert log_event.call_args.kwargs["event_type"] == "scim_remote_id_mapped"
    assert log_event.call_args.kwargs["artifact_id"] == "user-1"
    assert log_event.call_args.kwargs["artifact_type"] == "user"
    md = log_event.call_args.kwargs["metadata"]
    assert md["sp_id"] == "sp-1"
    assert md["remote_id"] == "rA"


def test_record_mapping_silent_on_update() -> None:
    """A subsequent upsert (was_inserted=False) does NOT re-fire the event."""
    db = MagicMock()
    db.scim_remote_ids.upsert.return_value = ({"id": "row-1", "remote_id": "rB"}, False)
    log_event = MagicMock()
    p1, p2 = _patch_helpers(db, log_event)
    with p1, p2:
        remote_ids.record_mapping("t", "sp", "user", "u", "rB")
    log_event.assert_not_called()


def test_record_mapping_swallows_db_error() -> None:
    """A failed upsert is logged via the module logger but not raised."""
    db = MagicMock()
    db.scim_remote_ids.upsert.side_effect = RuntimeError("boom")
    log_event = MagicMock()
    p1, p2 = _patch_helpers(db, log_event)
    with p1, p2:
        remote_ids.record_mapping("t", "sp", "user", "u", "rA")
    log_event.assert_not_called()  # no row inserted -> no event


# ---------------------------------------------------------------------------
# invalidate_mapping
# ---------------------------------------------------------------------------


def test_invalidate_mapping_emits_event_when_row_was_deleted() -> None:
    db = MagicMock()
    db.scim_remote_ids.delete.return_value = 1
    log_event = MagicMock()
    p1, p2 = _patch_helpers(db, log_event)
    with p1, p2:
        out = remote_ids.invalidate_mapping(
            tenant_id="t",
            sp_id="sp",
            resource_type="group",
            weftid_id="g-1",
        )
    assert out is True
    db.scim_remote_ids.delete.assert_called_once_with("t", "sp", "group", "g-1")
    log_event.assert_called_once()
    assert log_event.call_args.kwargs["event_type"] == "scim_remote_id_invalidated"
    assert log_event.call_args.kwargs["artifact_id"] == "g-1"
    assert log_event.call_args.kwargs["artifact_type"] == "group"
    md = log_event.call_args.kwargs["metadata"]
    assert md["sp_id"] == "sp"
    assert md["reason"] == "remote_404"


def test_invalidate_mapping_no_event_when_no_row_was_present() -> None:
    """Defensive call where no mapping existed -- nothing to audit."""
    db = MagicMock()
    db.scim_remote_ids.delete.return_value = 0
    log_event = MagicMock()
    p1, p2 = _patch_helpers(db, log_event)
    with p1, p2:
        out = remote_ids.invalidate_mapping("t", "sp", "user", "u")
    assert out is False
    log_event.assert_not_called()


def test_invalidate_mapping_swallows_db_error() -> None:
    db = MagicMock()
    db.scim_remote_ids.delete.side_effect = RuntimeError("boom")
    log_event = MagicMock()
    p1, p2 = _patch_helpers(db, log_event)
    with p1, p2:
        out = remote_ids.invalidate_mapping("t", "sp", "user", "u")
    assert out is False
    log_event.assert_not_called()
