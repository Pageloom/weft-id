"""Tests for the SCIM columns added to service_providers in migration 0036.

Covers the defaults, the CHECK constraints on `scim_membership_mode` and
`scim_log_retention`, and the deliberate absence of a CHECK on
`scim_kind` (validation lives in code; unknown values fall back to
'generic' at runtime).
"""

import database
import psycopg.errors
import pytest


def _create_sp(tenant_id, user_id, name="SCIM Cols SP"):
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )


def _read_scim_cols(tenant_id, sp_id):
    return database.fetchone(
        tenant_id,
        """
        select scim_enabled, scim_target_url, scim_kind,
               scim_membership_mode, scim_log_retention
        from service_providers
        where id = :id
        """,
        {"id": sp_id},
    )


def test_new_sp_has_scim_defaults(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    row = _read_scim_cols(test_tenant["id"], sp["id"])

    assert row["scim_enabled"] is False
    assert row["scim_target_url"] is None
    assert row["scim_kind"] == "generic"
    assert row["scim_membership_mode"] == "effective"
    assert row["scim_log_retention"] == "3"


def test_scim_membership_mode_accepts_known_values(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    for value in ("effective", "direct"):
        database.execute(
            test_tenant["id"],
            "update service_providers set scim_membership_mode = :v where id = :id",
            {"v": value, "id": sp["id"]},
        )
        assert _read_scim_cols(test_tenant["id"], sp["id"])["scim_membership_mode"] == value


def test_scim_membership_mode_rejects_unknown_values(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    with pytest.raises(psycopg.errors.CheckViolation):
        database.execute(
            test_tenant["id"],
            "update service_providers set scim_membership_mode = :v where id = :id",
            {"v": "transitive", "id": sp["id"]},
        )


def test_scim_log_retention_accepts_known_values(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    for value in ("3", "6", "12", "24", "forever"):
        database.execute(
            test_tenant["id"],
            "update service_providers set scim_log_retention = :v where id = :id",
            {"v": value, "id": sp["id"]},
        )
        assert _read_scim_cols(test_tenant["id"], sp["id"])["scim_log_retention"] == value


def test_scim_log_retention_rejects_unknown_values(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    with pytest.raises(psycopg.errors.CheckViolation):
        database.execute(
            test_tenant["id"],
            "update service_providers set scim_log_retention = :v where id = :id",
            {"v": "60", "id": sp["id"]},
        )


def test_scim_kind_has_no_check_constraint(test_tenant, test_user):
    """`scim_kind` is intentionally free-form (validated in code).

    Unknown values must insert successfully so adding a new quirk module
    later does not require a migration.
    """
    sp = _create_sp(test_tenant["id"], test_user["id"])
    database.execute(
        test_tenant["id"],
        "update service_providers set scim_kind = :v where id = :id",
        {"v": "made_up_kind", "id": sp["id"]},
    )
    assert _read_scim_cols(test_tenant["id"], sp["id"])["scim_kind"] == "made_up_kind"
