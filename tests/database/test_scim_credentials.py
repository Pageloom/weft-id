"""Tests for database.scim_credentials module."""

from uuid import uuid4

import database
import pytest


def _create_sp(tenant_id, user_id, name="SCIM Cred SP"):
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )


def _create_credential(test_tenant, test_user, sp, *, encrypted_plaintext=b"cipher"):
    return database.scim_credentials.create_credential(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        sp_id=sp["id"],
        created_by_user_id=str(test_user["id"]),
        encrypted_plaintext=encrypted_plaintext,
    )


# -- create_credential ---------------------------------------------------------


def test_create_credential_returns_row(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])

    row = _create_credential(test_tenant, test_user, sp)

    assert row["id"] is not None
    assert str(row["sp_id"]) == str(sp["id"])
    assert str(row["created_by_user_id"]) == str(test_user["id"])
    assert row["created_at"] is not None
    assert row["revoked_at"] is None
    assert row["last_used_at"] is None


def test_multiple_active_credentials_per_sp_supported(test_tenant, test_user):
    """Rotation needs multiple active rows per SP (overlap window)."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    a = _create_credential(test_tenant, test_user, sp)
    b = _create_credential(test_tenant, test_user, sp)

    active = database.scim_credentials.list_active_credentials(test_tenant["id"], sp["id"])
    ids = {str(r["id"]) for r in active}
    assert {str(a["id"]), str(b["id"])} <= ids


# -- list_active_credentials / list_all_credentials ---------------------------


def test_list_active_excludes_revoked(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    active = _create_credential(test_tenant, test_user, sp)
    revoked = _create_credential(test_tenant, test_user, sp)
    database.scim_credentials.mark_revoked(test_tenant["id"], str(revoked["id"]))

    active_rows = database.scim_credentials.list_active_credentials(test_tenant["id"], sp["id"])
    assert [str(r["id"]) for r in active_rows] == [str(active["id"])]

    all_rows = database.scim_credentials.list_all_credentials(test_tenant["id"], sp["id"])
    assert {str(r["id"]) for r in all_rows} == {str(active["id"]), str(revoked["id"])}


# -- mark_revoked --------------------------------------------------------------


def test_mark_revoked_sets_timestamp(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    cred = _create_credential(test_tenant, test_user, sp)

    rows = database.scim_credentials.mark_revoked(test_tenant["id"], str(cred["id"]))
    assert rows == 1

    # Second revoke is a no-op (already revoked)
    rows = database.scim_credentials.mark_revoked(test_tenant["id"], str(cred["id"]))
    assert rows == 0


# -- schedule_revocation ------------------------------------------------------


def test_schedule_revocation_with_overlap(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    cred = _create_credential(test_tenant, test_user, sp)

    rows = database.scim_credentials.schedule_revocation(
        test_tenant["id"], str(cred["id"]), overlap_interval="1 hour"
    )
    assert rows == 1

    # Active list excludes credentials whose revoked_at is set (even in the future)
    active = database.scim_credentials.list_active_credentials(test_tenant["id"], sp["id"])
    assert str(cred["id"]) not in {str(r["id"]) for r in active}


def test_schedule_revocation_rejects_bad_interval(test_tenant, test_user):
    """The interval-parsing regex must reject anything that isn't `<int> <unit>`.

    psycopg's named-param parser treats `::interval` casts as a named param, so
    the code parses the interval expression in Python with a strict regex.
    Bad input must raise ValueError rather than silently being mishandled or
    pasted into the SQL.
    """
    sp = _create_sp(test_tenant["id"], test_user["id"])
    cred = _create_credential(test_tenant, test_user, sp)
    with pytest.raises(ValueError):
        database.scim_credentials.schedule_revocation(
            test_tenant["id"], str(cred["id"]), overlap_interval="forever"
        )
    with pytest.raises(ValueError):
        database.scim_credentials.schedule_revocation(
            test_tenant["id"], str(cred["id"]), overlap_interval="24"
        )
    with pytest.raises(ValueError):
        # SQL-injection style input must not be accepted
        database.scim_credentials.schedule_revocation(
            test_tenant["id"], str(cred["id"]), overlap_interval="1 hour; drop table x"
        )


def test_schedule_revocation_with_explicit_timestamp(test_tenant, test_user):
    """When revoke_at is provided, the interval branch is bypassed entirely."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    cred = _create_credential(test_tenant, test_user, sp)
    rows = database.scim_credentials.schedule_revocation(
        test_tenant["id"],
        str(cred["id"]),
        revoke_at="2099-01-01T00:00:00+00:00",
    )
    assert rows == 1
    active = database.scim_credentials.list_active_credentials(test_tenant["id"], sp["id"])
    assert str(cred["id"]) not in {str(r["id"]) for r in active}


# -- update_last_used ---------------------------------------------------------


def test_update_last_used(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    cred = _create_credential(test_tenant, test_user, sp)
    assert cred["last_used_at"] is None

    rows = database.scim_credentials.update_last_used(test_tenant["id"], str(cred["id"]))
    assert rows == 1

    fetched = next(
        r
        for r in database.scim_credentials.list_active_credentials(test_tenant["id"], sp["id"])
        if str(r["id"]) == str(cred["id"])
    )
    assert fetched["last_used_at"] is not None


# -- list_usable_credentials --------------------------------------------------


def test_list_usable_includes_pending_revocation(test_tenant, test_user):
    """A credential whose `revoked_at` is set in the future is still usable.

    Rotation overlap relies on this: the old token must remain valid until
    its scheduled revocation time so in-flight pushes complete cleanly.
    """
    sp = _create_sp(test_tenant["id"], test_user["id"])
    pending = _create_credential(test_tenant, test_user, sp)
    database.scim_credentials.schedule_revocation(
        test_tenant["id"], str(pending["id"]), overlap_interval="1 hour"
    )

    usable = database.scim_credentials.list_usable_credentials(test_tenant["id"], sp["id"])
    assert str(pending["id"]) in {str(r["id"]) for r in usable}

    active = database.scim_credentials.list_active_credentials(test_tenant["id"], sp["id"])
    assert str(pending["id"]) not in {str(r["id"]) for r in active}


def test_list_usable_excludes_revoked(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    cred = _create_credential(test_tenant, test_user, sp)
    database.scim_credentials.mark_revoked(test_tenant["id"], str(cred["id"]))

    usable = database.scim_credentials.list_usable_credentials(test_tenant["id"], sp["id"])
    assert str(cred["id"]) not in {str(r["id"]) for r in usable}


# -- get_active_credential_for_outbound ---------------------------------------


def test_get_active_credential_for_outbound_picks_newest(test_tenant, test_user):
    """The newest non-revoked credential with plaintext is returned."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    _create_credential(test_tenant, test_user, sp, encrypted_plaintext=b"older-cipher")
    newest = _create_credential(test_tenant, test_user, sp, encrypted_plaintext=b"newest-cipher")

    row = database.scim_credentials.get_active_credential_for_outbound(test_tenant["id"], sp["id"])
    assert row is not None
    assert str(row["id"]) == str(newest["id"])
    assert bytes(row["encrypted_plaintext"]) == b"newest-cipher"


def test_get_active_credential_for_outbound_skips_rows_without_plaintext(test_tenant, test_user):
    """A row whose `encrypted_plaintext` is NULL must be skipped.

    Returning such a row would lead the worker to dead-letter the queue entry
    with a confusing reason; better to skip cleanly and let the resolver
    return None.
    """
    sp = _create_sp(test_tenant["id"], test_user["id"])
    _create_credential(test_tenant, test_user, sp, encrypted_plaintext=None)

    row = database.scim_credentials.get_active_credential_for_outbound(test_tenant["id"], sp["id"])
    assert row is None


def test_get_active_credential_for_outbound_returns_none_when_revoked(test_tenant, test_user):
    sp = _create_sp(test_tenant["id"], test_user["id"])
    cred = _create_credential(test_tenant, test_user, sp, encrypted_plaintext=b"will-be-revoked")
    database.scim_credentials.mark_revoked(test_tenant["id"], str(cred["id"]))

    row = database.scim_credentials.get_active_credential_for_outbound(test_tenant["id"], sp["id"])
    assert row is None


def test_get_active_credential_for_outbound_returns_pending_revocation(test_tenant, test_user):
    """Inside the overlap window the soon-to-be-revoked credential is still active."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    cred = _create_credential(test_tenant, test_user, sp, encrypted_plaintext=b"still-usable")
    database.scim_credentials.schedule_revocation(
        test_tenant["id"], str(cred["id"]), overlap_interval="2 hours"
    )

    row = database.scim_credentials.get_active_credential_for_outbound(test_tenant["id"], sp["id"])
    assert row is not None
    assert str(row["id"]) == str(cred["id"])


# -- RLS scoping --------------------------------------------------------------


def test_rls_isolates_credentials_by_tenant(test_tenant, test_user):
    """A second tenant's user cannot see this tenant's credentials."""
    sp = _create_sp(test_tenant["id"], test_user["id"])
    _create_credential(test_tenant, test_user, sp)

    # Create an unrelated tenant
    other_id = database.fetchone(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
        {"s": f"other-{uuid4().hex[:8]}", "n": "Other"},
    )
    try:
        rows = database.scim_credentials.list_all_credentials(other_id["id"], sp["id"])
        assert rows == []
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other_id["id"]},
        )
