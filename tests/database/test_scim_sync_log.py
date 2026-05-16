"""Tests for database.scim_sync_log module."""

from datetime import UTC, datetime
from uuid import uuid4

import database
import psycopg.errors
import pytest


def _create_sp(tenant_id, user_id, name="SCIM Log SP", **kwargs):
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
        **kwargs,
    )


# -- create_entry -------------------------------------------------------------


def test_create_entry_defaults_to_pending(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    rid = str(uuid4())

    row = database.scim_sync_log.create_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", rid
    )

    assert row["id"] is not None
    assert str(row["sp_id"]) == str(sp["id"])
    assert row["resource_type"] == "user"
    assert str(row["resource_id"]) == rid
    assert row["status"] == "pending"
    assert row["attempt"] == 0
    assert row["error"] is None
    assert row["started_at"] is None
    assert row["completed_at"] is None
    assert row["created_at"] is not None


def test_create_entry_with_running_status(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    now = datetime.now(UTC)

    row = database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "group",
        str(uuid4()),
        status="running",
        attempt=1,
        started_at=now,
    )
    assert row["status"] == "running"
    assert row["attempt"] == 1
    assert row["started_at"] is not None


def test_create_entry_invalid_status_rejected(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    with pytest.raises(psycopg.errors.CheckViolation):
        database.scim_sync_log.create_entry(
            test_tenant["id"],
            str(test_tenant["id"]),
            sp["id"],
            "user",
            str(uuid4()),
            status="bogus",
        )


def test_create_entry_invalid_resource_type_rejected(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    with pytest.raises(psycopg.errors.CheckViolation):
        database.scim_sync_log.create_entry(
            test_tenant["id"],
            str(test_tenant["id"]),
            sp["id"],
            "device",
            str(uuid4()),
        )


# -- update_status ------------------------------------------------------------


def test_update_status_terminal_sets_completed_at(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    row = database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
        status="running",
    )

    affected = database.scim_sync_log.update_status(
        test_tenant["id"], str(row["id"]), "done", completed=True
    )
    assert affected == 1

    rows = database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"])
    assert rows[0]["status"] == "done"
    assert rows[0]["completed_at"] is not None
    assert rows[0]["error"] is None


def test_update_status_non_terminal_keeps_completed_at_null(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    row = database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )

    database.scim_sync_log.update_status(test_tenant["id"], str(row["id"]), "running")
    rows = database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"])
    assert rows[0]["status"] == "running"
    assert rows[0]["completed_at"] is None


def test_update_status_with_error(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    row = database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )
    database.scim_sync_log.update_status(
        test_tenant["id"], str(row["id"]), "failed", error="oops", completed=True
    )
    rows = database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"])
    assert rows[0]["status"] == "failed"
    assert rows[0]["error"] == "oops"
    assert rows[0]["completed_at"] is not None


# -- list_recent_for_sp / count_for_sp ----------------------------------------


def test_list_recent_pagination_and_filter(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    # Build a mix of statuses
    for i in range(3):
        r = database.scim_sync_log.create_entry(
            test_tenant["id"],
            str(test_tenant["id"]),
            sp["id"],
            "user",
            str(uuid4()),
            attempt=i,
        )
        database.scim_sync_log.update_status(
            test_tenant["id"],
            str(r["id"]),
            "done" if i % 2 == 0 else "failed",
            error=None if i % 2 == 0 else "x",
            completed=True,
        )

    all_rows = database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"])
    assert len(all_rows) == 3

    done_only = database.scim_sync_log.list_recent_for_sp(
        test_tenant["id"], sp["id"], status="done"
    )
    assert len(done_only) == 2
    assert all(r["status"] == "done" for r in done_only)

    page = database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"], limit=1)
    assert len(page) == 1

    assert database.scim_sync_log.count_for_sp(test_tenant["id"], sp["id"]) == 3
    assert database.scim_sync_log.count_for_sp(test_tenant["id"], sp["id"], status="failed") == 1


def test_list_recent_orders_in_flight_first(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])

    # Completed first
    completed_row = database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )
    database.scim_sync_log.update_status(
        test_tenant["id"], str(completed_row["id"]), "done", completed=True
    )

    # In-flight second
    in_flight = database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
        status="running",
    )

    rows = database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"])
    assert str(rows[0]["id"]) == str(in_flight["id"])
    assert str(rows[1]["id"]) == str(completed_row["id"])


# -- delete_older_than --------------------------------------------------------


def test_delete_older_than_respects_retention(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])

    # Two completed rows, one with completed_at backdated past the cutoff
    keep = database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )
    database.scim_sync_log.update_status(test_tenant["id"], str(keep["id"]), "done", completed=True)

    drop = database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )
    database.scim_sync_log.update_status(test_tenant["id"], str(drop["id"]), "done", completed=True)
    # Force completed_at into the distant past for the row we expect to drop
    database.execute(
        test_tenant["id"],
        "update scim_sync_log set completed_at = now() - interval '1 year' where id = :id",
        {"id": str(drop["id"])},
    )

    # An in-flight row (completed_at NULL) must never be deleted
    in_flight = database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )

    deleted = database.scim_sync_log.delete_older_than(test_tenant["id"], sp["id"], "3 months")
    assert deleted == 1

    remaining_ids = {
        str(r["id"]) for r in database.scim_sync_log.list_recent_for_sp(test_tenant["id"], sp["id"])
    }
    assert remaining_ids == {str(keep["id"]), str(in_flight["id"])}


def test_delete_older_than_rejects_bad_interval(test_tenant, test_user):
    """Bad interval expressions must raise ValueError, not run unsafe SQL.

    psycopg's named-param parser treats `::interval` casts as named params,
    so the function parses the expression in Python with a strict regex. The
    `'forever'` sentinel that the SP-level retention setting accepts is NOT a
    valid Postgres interval and must be filtered out by the caller before
    reaching this function.
    """
    sp = _create_sp(test_tenant["id"], test_user["id"])
    with pytest.raises(ValueError):
        database.scim_sync_log.delete_older_than(test_tenant["id"], sp["id"], "forever")
    with pytest.raises(ValueError):
        database.scim_sync_log.delete_older_than(test_tenant["id"], sp["id"], "3")
    with pytest.raises(ValueError):
        # SQL-injection style input must not pass the regex
        database.scim_sync_log.delete_older_than(
            test_tenant["id"], sp["id"], "1 day; delete from scim_sync_log"
        )


# -- RLS scoping --------------------------------------------------------------


def test_rls_isolates_sync_log_by_tenant(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    database.scim_sync_log.create_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )

    other_id = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"other-{uuid4().hex[:8]}", "n": "Other"},
    )
    try:
        rows = database.scim_sync_log.list_recent_for_sp(other_id["id"], sp["id"])
        assert rows == []
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other_id["id"]},
        )
