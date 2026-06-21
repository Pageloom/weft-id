"""Tests for database.tenant_attribute_config and the migration seed."""

from __future__ import annotations

from uuid import uuid4

import database
from constants.user_attributes import (
    ATTRIBUTE_KEYS,
    ATTRIBUTES_BY_KEY,
    STANDARD_ATTRIBUTES,
)


def _seed_tenant_config(tenant_id):
    """Helper: emulate the migration seed for a freshly created test tenant.

    Migration 0033 only seeds rows for tenants that exist at apply time. Test
    tenants created later need the same starting state.
    """
    for attr in STANDARD_ATTRIBUTES:
        database.execute(
            tenant_id,
            """
            INSERT INTO tenant_attribute_config (
                tenant_id, attribute_key, category, enabled, required,
                mirror_from_idp, locked_for_users, send_to_sps_default
            ) VALUES (
                :tenant_id, :attribute_key, :category, false, false, true, false, true
            )
            ON CONFLICT (tenant_id, attribute_key) DO NOTHING
            """,
            {
                "tenant_id": str(tenant_id),
                "attribute_key": attr.key,
                "category": attr.category,
            },
        )


# ---------------------------------------------------------------------------
# list_config / get_config
# ---------------------------------------------------------------------------


def test_list_config_after_seed_has_all_fourteen(test_tenant):
    _seed_tenant_config(test_tenant["id"])
    rows = database.tenant_attribute_config.list_config(test_tenant["id"])
    keys = {r["attribute_key"] for r in rows}
    assert keys == ATTRIBUTE_KEYS
    # All defaults match the registry contract
    for r in rows:
        assert r["enabled"] is False
        assert r["required"] is False
        assert r["mirror_from_idp"] is True
        assert r["locked_for_users"] is False
        assert r["send_to_sps_default"] is True
        # Category matches the registry
        assert r["category"] == ATTRIBUTES_BY_KEY[r["attribute_key"]].category


def test_list_config_orders_by_category_then_key(test_tenant):
    _seed_tenant_config(test_tenant["id"])
    rows = database.tenant_attribute_config.list_config(test_tenant["id"])
    category_order = {"contact": 1, "professional": 2, "location": 3, "profile": 4}
    pairs = [(category_order[r["category"]], r["attribute_key"]) for r in rows]
    assert pairs == sorted(pairs)


def test_get_config_returns_row_for_seeded_tenant(test_tenant):
    _seed_tenant_config(test_tenant["id"])
    row = database.tenant_attribute_config.get_config(test_tenant["id"], "job_title")
    assert row is not None
    assert row["category"] == "professional"
    assert row["enabled"] is False


def test_get_config_returns_none_for_unknown_key(test_tenant):
    _seed_tenant_config(test_tenant["id"])
    assert database.tenant_attribute_config.get_config(test_tenant["id"], "no_such_key") is None


# ---------------------------------------------------------------------------
# update_config
# ---------------------------------------------------------------------------


def test_update_config_changes_flags(test_tenant):
    _seed_tenant_config(test_tenant["id"])
    rows_affected = database.tenant_attribute_config.update_config(
        test_tenant["id"],
        attribute_key="job_title",
        enabled=True,
        required=True,
        mirror_from_idp=True,
        locked_for_users=True,
        send_to_sps_default=False,
        allow_self_sourced_to_sp=True,
    )
    assert rows_affected == 1
    row = database.tenant_attribute_config.get_config(test_tenant["id"], "job_title")
    assert row is not None
    assert row["enabled"] is True
    assert row["required"] is True
    assert row["mirror_from_idp"] is True
    assert row["locked_for_users"] is True
    assert row["send_to_sps_default"] is False
    assert row["allow_self_sourced_to_sp"] is True


def test_update_config_returns_zero_for_missing_key(test_tenant):
    _seed_tenant_config(test_tenant["id"])
    rows_affected = database.tenant_attribute_config.update_config(
        test_tenant["id"],
        attribute_key="nonexistent_key",
        enabled=True,
        required=False,
        mirror_from_idp=False,
        locked_for_users=False,
        send_to_sps_default=True,
        allow_self_sourced_to_sp=False,
    )
    assert rows_affected == 0


# ---------------------------------------------------------------------------
# Tenant isolation and cascade
# ---------------------------------------------------------------------------


def test_tenant_isolation(test_tenant):
    """A tenant only sees its own config rows."""
    _seed_tenant_config(test_tenant["id"])

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
        # Other tenant has no rows yet
        rows = database.tenant_attribute_config.list_config(other["id"])
        assert rows == []
        # First tenant still has its 14
        rows = database.tenant_attribute_config.list_config(test_tenant["id"])
        assert len(rows) == 14
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other["id"]},
        )


def test_cascade_on_tenant_delete(test_tenant):
    """Deleting a tenant cascades and removes its config rows.

    Verifies that the FK ``REFERENCES tenants(id) ON DELETE CASCADE`` is in
    place: after the tenant row goes away, no config rows remain that would
    survive a subsequent re-creation under the same id space.
    """
    other_subdomain = f"cascade-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n)",
        {"s": other_subdomain, "n": "Cascade"},
    )
    other = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :s",
        {"s": other_subdomain},
    )
    assert other is not None
    _seed_tenant_config(other["id"])
    assert len(database.tenant_attribute_config.list_config(other["id"])) == 14

    # Delete the tenant; the ON DELETE CASCADE FK removes config rows.
    database.execute(
        database.UNSCOPED,
        "DELETE FROM tenants WHERE id = :id",
        {"id": other["id"]},
    )

    # After tenant delete, config rows are gone (queried with the
    # now-orphaned tenant_id which would still be RLS-scoped if rows existed).
    rows = database.tenant_attribute_config.list_config(other["id"])
    assert rows == []


def test_category_check_constraint_rejects_unknown_category(test_tenant):
    """The CHECK constraint rejects categories outside the four known values."""
    import pytest

    with pytest.raises(Exception):
        database.execute(
            test_tenant["id"],
            """
            INSERT INTO tenant_attribute_config (
                tenant_id, attribute_key, category
            ) VALUES (
                :tenant_id, 'fake_key', 'bogus_category'
            )
            """,
            {"tenant_id": str(test_tenant["id"])},
        )


# ---------------------------------------------------------------------------
# Migration seed integrity (if a tenant exists pre-migration, it should have
# all 14 rows). We seed a tenant in this test session to assert the seed shape
# matches the registry. The actual migration's behaviour against pre-existing
# tenants is exercised when migrations run in CI/dev.
# ---------------------------------------------------------------------------


def test_seed_shape_matches_registry(test_tenant):
    """Every seeded row's category must equal the registry's category."""
    _seed_tenant_config(test_tenant["id"])
    rows = database.tenant_attribute_config.list_config(test_tenant["id"])
    by_key = {r["attribute_key"]: r for r in rows}
    for attr in STANDARD_ATTRIBUTES:
        seeded = by_key[attr.key]
        assert seeded["category"] == attr.category


def test_migration_seeded_dev_tenants():
    """The migration's CROSS JOIN seed must populate the stable dev tenants.

    Targets the well-known dev seed tenants (`dev`, `meridian-health`) that
    are present in dev/CI databases and not modified by the test suite. Skips
    silently if neither exists -- e.g. on a fresh DB before dev seed has run.
    """
    rows = database.fetchall(
        database.UNSCOPED,
        "SELECT id, subdomain FROM tenants WHERE subdomain IN ('dev', 'meridian-health')",
        {},
    )
    if not rows:
        return
    expected = {(a.key, a.category) for a in STANDARD_ATTRIBUTES}
    for r in rows:
        seeded_rows = database.fetchall(
            r["id"],
            "SELECT attribute_key, category FROM tenant_attribute_config",
            {},
        )
        seeded = {(s["attribute_key"], s["category"]) for s in seeded_rows}
        assert seeded == expected, (
            f"Tenant {r['subdomain']} missing or extra rows. "
            f"Missing: {expected - seeded}. Extra: {seeded - expected}."
        )
