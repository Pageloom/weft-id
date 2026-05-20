"""Tests for database.scim_push_queue module."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database
import psycopg.errors
import pytest


def _create_sp(tenant_id, user_id, name="SCIM Queue SP"):
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )


# -- upsert_entry --------------------------------------------------------------


def test_upsert_entry_inserts_first_time(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    resource_id = str(uuid4())

    row = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", resource_id
    )

    assert row["id"] is not None
    assert str(row["sp_id"]) == str(sp["id"])
    assert row["resource_type"] == "user"
    assert str(row["resource_id"]) == resource_id
    assert row["attempts"] == 0
    assert row["next_attempt_at"] is None
    assert row["last_error"] is None
    assert row["dead_letter_at"] is None


def test_upsert_entry_resets_attempts_on_re_enqueue(test_tenant, test_user):
    """Re-enqueue must reset attempts/next_attempt_at/last_error and bump enqueued_at."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    resource_id = str(uuid4())

    first = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", resource_id
    )

    # Simulate a failed attempt: bump attempts, set next_attempt_at and last_error
    future = datetime.now(UTC) + timedelta(minutes=5)
    database.scim_push_queue.mark_attempt_failed(
        test_tenant["id"], str(first["id"]), "boom", future
    )
    failed = database.scim_push_queue.get_entry(test_tenant["id"], str(first["id"]))
    assert failed is not None
    assert failed["attempts"] == 1
    assert failed["last_error"] == "boom"
    assert failed["next_attempt_at"] is not None

    # Re-enqueue
    second = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", resource_id
    )

    # Same row (UNIQUE on (sp_id, resource_type, resource_id))
    assert str(second["id"]) == str(first["id"])
    assert second["attempts"] == 0
    assert second["next_attempt_at"] is None
    assert second["last_error"] is None
    # enqueued_at bumped
    assert second["enqueued_at"] >= first["enqueued_at"]


def test_upsert_entry_unique_per_target(test_tenant, test_user):
    """Different resource_type or resource_id produces a new row."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    rid_a = str(uuid4())
    rid_b = str(uuid4())

    a1 = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", rid_a
    )
    a2 = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", rid_a
    )
    b = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", rid_b
    )
    g = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "group", rid_a
    )

    # Same target -> same row
    assert str(a1["id"]) == str(a2["id"])
    # Different resource_id -> new row
    assert str(b["id"]) != str(a1["id"])
    # Same resource_id but different resource_type -> new row
    assert str(g["id"]) != str(a1["id"])


def test_upsert_entry_preserves_dead_letter_flag(test_tenant, test_user):
    """The ON CONFLICT clause must NOT touch dead_letter_at.

    A dead-lettered row should stay invisible to the worker even if new
    changes against the same resource cause a re-enqueue. Operators have to
    explicitly call `clear_dead_letter` to revive it. This guards against
    accidental re-fire of a known-bad target.
    """
    sp = _create_sp(test_tenant["id"], test_user["id"])
    rid = str(uuid4())
    first = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", rid
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(first["id"]), "permaboom")

    second = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", rid
    )
    assert str(second["id"]) == str(first["id"])
    assert second["dead_letter_at"] is not None
    # And it must not surface as ready
    ready_ids = {
        str(r["id"])
        for r in database.scim_push_queue.list_ready_entries(test_tenant["id"], sp_id=sp["id"])
    }
    assert str(first["id"]) not in ready_ids


def test_upsert_entry_invalid_resource_type_rejected(test_tenant, test_user):
    """CHECK constraint enforces ('user' | 'group')."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    with pytest.raises(psycopg.errors.CheckViolation):
        database.scim_push_queue.upsert_entry(
            test_tenant["id"], str(test_tenant["id"]), sp["id"], "device", str(uuid4())
        )


# -- list_ready_entries -------------------------------------------------------


def test_list_ready_entries_excludes_future_and_dead_letter(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    ready = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    future = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    dead = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )

    # Push `future` into the future
    future_ts = datetime.now(UTC) + timedelta(hours=1)
    database.scim_push_queue.mark_attempt_failed(
        test_tenant["id"], str(future["id"]), "later", future_ts
    )
    # Dead-letter
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead["id"]), "give up")

    rows = database.scim_push_queue.list_ready_entries(test_tenant["id"], sp_id=sp["id"])
    ids = {str(r["id"]) for r in rows}
    assert str(ready["id"]) in ids
    assert str(future["id"]) not in ids
    assert str(dead["id"]) not in ids


def test_list_ready_entries_respects_limit(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    for _ in range(3):
        database.scim_push_queue.upsert_entry(
            test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
        )

    rows = database.scim_push_queue.list_ready_entries(test_tenant["id"], sp_id=sp["id"], limit=2)
    assert len(rows) == 2


# -- mark_attempt_failed / mark_dead_letter / clear_dead_letter ---------------


def test_mark_attempt_failed_increments_attempts(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    entry = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )

    next_at = datetime.now(UTC) + timedelta(minutes=5)
    database.scim_push_queue.mark_attempt_failed(test_tenant["id"], str(entry["id"]), "x", next_at)
    database.scim_push_queue.mark_attempt_failed(test_tenant["id"], str(entry["id"]), "y", next_at)

    refreshed = database.scim_push_queue.get_entry(test_tenant["id"], str(entry["id"]))
    assert refreshed is not None
    assert refreshed["attempts"] == 2
    assert refreshed["last_error"] == "y"


def test_clear_dead_letter_revives_entry(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    entry = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(entry["id"]), "stuck")

    refreshed = database.scim_push_queue.get_entry(test_tenant["id"], str(entry["id"]))
    assert refreshed is not None
    assert refreshed["dead_letter_at"] is not None

    rows = database.scim_push_queue.clear_dead_letter(test_tenant["id"], str(entry["id"]))
    assert rows == 1
    revived = database.scim_push_queue.get_entry(test_tenant["id"], str(entry["id"]))
    assert revived is not None
    assert revived["dead_letter_at"] is None
    assert revived["attempts"] == 0
    assert revived["next_attempt_at"] is None


# -- delete_entry -------------------------------------------------------------


def test_delete_entry(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    entry = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )

    rows = database.scim_push_queue.delete_entry(test_tenant["id"], str(entry["id"]))
    assert rows == 1
    assert database.scim_push_queue.get_entry(test_tenant["id"], str(entry["id"])) is None


# -- count_pending_for_sp -----------------------------------------------------


def test_count_pending_for_sp(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    pending = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    dead = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "group", str(uuid4())
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead["id"]), "done in")

    counts = database.scim_push_queue.count_pending_for_sp(test_tenant["id"], sp["id"])
    assert counts == {"pending": 1, "dead_lettered": 1}
    # The active pending row is what we expect
    rows = database.scim_push_queue.list_ready_entries(test_tenant["id"], sp_id=sp["id"])
    assert str(rows[0]["id"]) == str(pending["id"])


# -- revive_dead_lettered_for_sp ----------------------------------------------


def test_revive_dead_lettered_for_sp_clears_flag_and_resets_attempts(test_tenant, test_user):
    """Reviving dead-lettered rows clears the flag, resets attempts/next_attempt_at.

    last_error is preserved as a diagnostic breadcrumb.
    """
    sp = _create_sp(test_tenant["id"], test_user["id"])
    dead_a = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    dead_b = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    pending = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead_a["id"]), error="boom_a")
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead_b["id"]), error="boom_b")

    count = database.scim_push_queue.revive_dead_lettered_for_sp(test_tenant["id"], sp["id"])
    assert count == 2

    counts = database.scim_push_queue.count_pending_for_sp(test_tenant["id"], sp["id"])
    assert counts == {"pending": 3, "dead_lettered": 0}

    revived_a = database.scim_push_queue.get_entry(test_tenant["id"], str(dead_a["id"]))
    assert revived_a is not None
    assert revived_a["dead_letter_at"] is None
    assert revived_a["attempts"] == 0
    assert revived_a["next_attempt_at"] is None
    # last_error preserved
    assert revived_a["last_error"] == "boom_a"

    # Pending row left alone
    pending_after = database.scim_push_queue.get_entry(test_tenant["id"], str(pending["id"]))
    assert pending_after is not None
    assert pending_after["dead_letter_at"] is None


def test_revive_dead_lettered_for_sp_no_dead_letters(test_tenant, test_user):
    """No dead-lettered rows -> 0 revived, no changes."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )

    count = database.scim_push_queue.revive_dead_lettered_for_sp(test_tenant["id"], sp["id"])
    assert count == 0


def test_revive_dead_lettered_for_sp_scoped_to_sp(test_tenant, test_user):
    """Reviving on SP A must not touch SP B's dead-lettered rows."""
    sp_a = _create_sp(test_tenant["id"], test_user["id"], name="A")
    sp_b = _create_sp(test_tenant["id"], test_user["id"], name="B")
    dead_b = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp_b["id"], "user", str(uuid4())
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead_b["id"]), error="boom")

    count = database.scim_push_queue.revive_dead_lettered_for_sp(test_tenant["id"], sp_a["id"])
    assert count == 0

    after = database.scim_push_queue.get_entry(test_tenant["id"], str(dead_b["id"]))
    assert after is not None
    assert after["dead_letter_at"] is not None


# -- RLS scoping --------------------------------------------------------------


def test_rls_isolates_queue_entries_by_tenant(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )

    other_id = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"other-{uuid4().hex[:8]}", "n": "Other"},
    )
    try:
        rows = database.scim_push_queue.list_ready_entries(other_id["id"], sp_id=sp["id"])
        assert rows == []
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other_id["id"]},
        )
