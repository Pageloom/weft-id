"""Integration tests for worker-supporting database queries.

Covers the new cross-tenant and SCIM-target accessors added in
iteration 4:
- `scim_push_queue.list_tenants_with_ready_entries`
- `service_providers.get_scim_target`
- `service_providers.list_scim_enabled_sps_all_tenants`
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import database
from database._core import execute


def _create_sp(tenant_id, user_id, name="SCIM Target SP", *, scim_enabled=False):
    sp = database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )
    if scim_enabled:
        execute(
            tenant_id,
            """
            update service_providers
            set scim_enabled = true,
                scim_target_url = 'https://scim.example.com/scim/v2',
                scim_kind = 'generic',
                scim_membership_mode = 'effective',
                scim_log_retention = '6'
            where id = :id
            """,
            {"id": sp["id"]},
        )
    return sp


# ---------------------------------------------------------------------------
# get_scim_target
# ---------------------------------------------------------------------------


def test_get_scim_target_returns_columns(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)
    target = database.service_providers.get_scim_target(test_tenant["id"], str(sp["id"]))
    assert target is not None
    assert target["scim_enabled"] is True
    assert target["scim_target_url"] == "https://scim.example.com/scim/v2"
    assert target["scim_kind"] == "generic"
    assert target["scim_membership_mode"] == "effective"
    assert target["scim_log_retention"] == "6"


def test_get_scim_target_returns_none_for_unknown_sp(test_tenant):
    assert database.service_providers.get_scim_target(test_tenant["id"], str(uuid4())) is None


def test_get_scim_target_returns_disabled_columns_for_non_scim_sp(test_tenant, test_user):
    """Even on a non-SCIM SP the columns are present with their defaults."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    target = database.service_providers.get_scim_target(test_tenant["id"], str(sp["id"]))
    assert target is not None
    assert target["scim_enabled"] is False
    assert target["scim_target_url"] is None
    assert target["scim_kind"] == "generic"  # default
    assert target["scim_log_retention"] == "3"  # default


# ---------------------------------------------------------------------------
# list_scim_enabled_sps_all_tenants
# ---------------------------------------------------------------------------


def test_list_scim_enabled_sps_all_tenants_returns_only_enabled(test_tenant, test_user):
    enabled = _create_sp(test_tenant["id"], test_user["id"], name="enabled", scim_enabled=True)
    _create_sp(test_tenant["id"], test_user["id"], name="disabled")

    rows = database.service_providers.list_scim_enabled_sps_all_tenants()
    ids = {str(r["id"]) for r in rows}
    assert str(enabled["id"]) in ids
    # The disabled one must not be there
    for r in rows:
        if str(r["id"]) == str(enabled["id"]):
            assert r["scim_log_retention"] == "6"


def test_service_providers_rls_strict_for_unscoped_select(test_tenant, test_user):
    """Strict RLS on `service_providers`: an unscoped raw SELECT must see zero rows.

    Migration 0040 reverted the 0037 widening of this table back to strict
    isolation, and routed the cleanup job through a SECURITY DEFINER
    function instead. The widening was kept on the SCIM-specific tables
    (`scim_push_queue`, `scim_sync_log`, `sp_scim_credentials`) -- they
    are low blast radius -- but the `service_providers` table is broad
    enough that an unset `app.tenant_id` must NOT yield cross-tenant rows.
    """
    from database._core import fetchall as _fetchall

    _create_sp(test_tenant["id"], test_user["id"], scim_enabled=True)

    # A direct UNSCOPED select on the table itself must return zero rows.
    rows = _fetchall(
        database.UNSCOPED,
        "select id from service_providers limit 5",
    )
    assert rows == []

    # The sanctioned SECURITY DEFINER accessor still returns the row.
    cross_rows = database.service_providers.list_scim_enabled_sps_all_tenants()
    assert len(cross_rows) >= 1


# ---------------------------------------------------------------------------
# list_tenants_with_ready_entries
# ---------------------------------------------------------------------------


def test_list_tenants_with_ready_entries_skips_dead_letter(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    entry = database.scim_push_queue.upsert_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(entry["id"]), "exhausted")

    # Only dead-lettered entry exists for this tenant for this scope.
    tenants = database.scim_push_queue.list_tenants_with_ready_entries()
    assert str(test_tenant["id"]) not in tenants


def test_list_tenants_with_ready_entries_skips_future_next_attempt(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    entry = database.scim_push_queue.upsert_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )
    future = datetime.now(UTC) + timedelta(hours=1)
    database.scim_push_queue.mark_attempt_failed(
        test_tenant["id"], str(entry["id"]), "wait", future
    )
    tenants = database.scim_push_queue.list_tenants_with_ready_entries()
    assert str(test_tenant["id"]) not in tenants


def test_list_tenants_with_ready_entries_includes_ready_tenant(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    database.scim_push_queue.upsert_entry(
        test_tenant["id"],
        str(test_tenant["id"]),
        sp["id"],
        "user",
        str(uuid4()),
    )
    tenants = database.scim_push_queue.list_tenants_with_ready_entries()
    assert str(test_tenant["id"]) in tenants
