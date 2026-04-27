"""Tests for database.user_attributes (post two-space pivot)."""

from __future__ import annotations

from uuid import uuid4

import database
import pytest

# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------


def test_upsert_inserts_new_row(test_user):
    row = database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    assert row["attribute_key"] == "job_title"
    assert row["value"] == "Engineer"


def test_upsert_overwrites_existing_row(test_user):
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Junior Engineer",
    )
    updated = database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Senior Engineer",
    )
    assert updated["value"] == "Senior Engineer"

    # And only one row exists
    rows = database.user_attributes.list_attributes(test_user["tenant_id"], test_user["id"])
    assert len([r for r in rows if r["attribute_key"] == "job_title"]) == 1


# ---------------------------------------------------------------------------
# Read / list / delete
# ---------------------------------------------------------------------------


def test_get_returns_none_when_missing(test_user):
    assert (
        database.user_attributes.get_attribute(test_user["tenant_id"], test_user["id"], "job_title")
        is None
    )


def test_list_orders_by_attribute_key(test_user):
    for key, value in [
        ("job_title", "Eng"),
        ("city", "NYC"),
        ("country", "US"),
    ]:
        database.user_attributes.upsert_attribute(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            attribute_key=key,
            value=value,
        )
    rows = database.user_attributes.list_attributes(test_user["tenant_id"], test_user["id"])
    keys = [r["attribute_key"] for r in rows]
    assert keys == sorted(keys)


def test_delete_returns_one_on_hit(test_user):
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Eng",
    )
    rows_affected = database.user_attributes.delete_attribute(
        test_user["tenant_id"], test_user["id"], "job_title"
    )
    assert rows_affected == 1
    assert (
        database.user_attributes.get_attribute(test_user["tenant_id"], test_user["id"], "job_title")
        is None
    )


def test_delete_returns_zero_on_miss(test_user):
    rows_affected = database.user_attributes.delete_attribute(
        test_user["tenant_id"], test_user["id"], "job_title"
    )
    assert rows_affected == 0


# ---------------------------------------------------------------------------
# Tenant isolation and cascade
# ---------------------------------------------------------------------------


def test_tenant_isolation(test_user):
    """Attributes in tenant A must not be visible from tenant B."""
    other_subdomain = f"isolated-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n)",
        {"s": other_subdomain, "n": "Isolated"},
    )
    other = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :s",
        {"s": other_subdomain},
    )
    assert other is not None
    try:
        database.user_attributes.upsert_attribute(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=test_user["id"],
            attribute_key="job_title",
            value="Engineer",
        )
        rows = database.user_attributes.list_attributes(other["id"], test_user["id"])
        assert rows == []
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other["id"]},
        )


def test_cascade_delete_on_user(test_user):
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    database.execute(
        test_user["tenant_id"],
        "DELETE FROM users WHERE id = :id",
        {"id": test_user["id"]},
    )
    rows = database.user_attributes.list_attributes(test_user["tenant_id"], test_user["id"])
    assert rows == []


def test_unique_user_attribute_key(test_user):
    """Two rows with the same (user_id, attribute_key) are rejected."""
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Eng",
    )
    # Direct INSERT (bypassing upsert) must violate the unique constraint
    with pytest.raises(Exception):
        database.execute(
            test_user["tenant_id"],
            """
            INSERT INTO user_attributes (
                tenant_id, user_id, attribute_key, value
            ) VALUES (
                :tenant_id, :user_id, 'job_title', 'Other'
            )
            """,
            {
                "tenant_id": str(test_user["tenant_id"]),
                "user_id": test_user["id"],
            },
        )


def test_force_profile_completion_default(test_user):
    """The new users.force_profile_completion column defaults to false."""
    row = database.fetchone(
        test_user["tenant_id"],
        "SELECT force_profile_completion FROM users WHERE id = :id",
        {"id": test_user["id"]},
    )
    assert row is not None
    assert row["force_profile_completion"] is False


# Note on tenant-delete cascade for user_attributes:
# The chain is tenants -> users -> user_attributes via composite FKs with
# ON DELETE CASCADE. The user-level cascade is verified by
# test_cascade_delete_on_user above. The tenant-level cascade through users
# is well-established by the existing tenants/users/users-fkey schema.


def test_cross_tenant_upsert_rejected_by_rls(test_user):
    """An upsert that targets another tenant's tenant_id must be rejected."""
    other_subdomain = f"foreign-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n)",
        {"s": other_subdomain, "n": "Foreign"},
    )
    other = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :s",
        {"s": other_subdomain},
    )
    assert other is not None
    try:
        # Session is scoped to test_user's tenant. Attempting to insert with
        # tenant_id = other['id'] must trigger RLS WITH CHECK.
        with pytest.raises(Exception):
            database.execute(
                test_user["tenant_id"],
                """
                INSERT INTO user_attributes (
                    tenant_id, user_id, attribute_key, value
                ) VALUES (
                    :tenant_id, :user_id, 'job_title', 'Engineer'
                )
                """,
                {
                    "tenant_id": str(other["id"]),
                    "user_id": test_user["id"],
                },
            )
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other["id"]},
        )
