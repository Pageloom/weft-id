"""Tests for `services.scim.admin` (config, credentials, sync log, queue actions)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import database
import pytest
from schemas.scim_admin import ScimConfigUpdate
from services.exceptions import NotFoundError, ValidationError
from services.scim import admin as scim_admin
from services.types import RequestingUser
from utils.scim_crypto import decrypt_token


def _create_sp(tenant_id, user_id, name="SCIM Admin SP"):
    return database.service_providers.create_service_provider(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        name=name,
        created_by=str(user_id),
    )


def _requesting_user(tenant_id, user_id, role="admin") -> RequestingUser:
    return RequestingUser(id=str(user_id), tenant_id=str(tenant_id), role=role)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_get_scim_config_returns_defaults(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    config = scim_admin.get_scim_config(ru, str(sp["id"]))
    assert config.sp_id == str(sp["id"])
    assert config.scim_enabled is False
    assert config.scim_kind == "generic"
    assert config.scim_membership_mode == "effective"
    assert config.scim_log_retention == "3"


def test_get_scim_config_unknown_sp_raises(test_tenant, test_admin_user):
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        scim_admin.get_scim_config(ru, str(uuid4()))


def test_update_scim_config_writes_changes_and_logs(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    updated = scim_admin.update_scim_config(
        ru,
        str(sp["id"]),
        ScimConfigUpdate(
            scim_enabled=True,
            scim_target_url="https://example.com/scim",
            scim_kind="slack",
            scim_membership_mode="direct",
            scim_log_retention="12",
        ),
    )
    assert updated.scim_enabled is True
    assert updated.scim_target_url == "https://example.com/scim"
    assert updated.scim_kind == "slack"
    assert updated.scim_membership_mode == "direct"
    assert updated.scim_log_retention == "12"

    # Audit event captured.
    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT el.event_type, elm.metadata
        FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_config_updated' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert len(events) == 1
    metadata = events[0]["metadata"]
    assert set(metadata["changed_fields"]) == {
        "scim_enabled",
        "scim_target_url",
        "scim_kind",
        "scim_membership_mode",
        "scim_log_retention",
    }


def test_update_scim_config_no_fields_raises(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError):
        scim_admin.update_scim_config(ru, str(sp["id"]), ScimConfigUpdate())


def test_update_scim_config_enable_without_url_raises(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(ValidationError):
        scim_admin.update_scim_config(ru, str(sp["id"]), ScimConfigUpdate(scim_enabled=True))


def test_update_scim_config_clears_target_url_with_empty_string(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    scim_admin.update_scim_config(
        ru, str(sp["id"]), ScimConfigUpdate(scim_target_url="https://example.com/scim")
    )
    cleared = scim_admin.update_scim_config(ru, str(sp["id"]), ScimConfigUpdate(scim_target_url=""))
    assert cleared.scim_target_url is None


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def test_create_credential_returns_plaintext_and_stores_ciphertext(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    response = scim_admin.create_credential(ru, str(sp["id"]))
    assert response.plaintext
    assert len(response.plaintext) >= 24

    # The encrypted plaintext column round-trips through the Fernet key.
    row = database.scim_credentials.get_active_credential_for_outbound(
        test_tenant["id"], str(sp["id"])
    )
    assert row is not None
    decrypted = decrypt_token(bytes(row["encrypted_plaintext"]))
    assert decrypted == response.plaintext

    # Audit event.
    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT el.event_type, elm.metadata
        FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_token_created' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert len(events) == 1
    assert events[0]["metadata"]["credential_id"] == response.id


def test_list_credentials_includes_pending_revocation(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))
    rotated = scim_admin.rotate_credential(ru, str(sp["id"]), first.id, overlap_hours=24)

    listing = scim_admin.list_credentials(ru, str(sp["id"]))
    ids = {item.id for item in listing.items}
    assert first.id in ids  # still inside overlap window
    assert rotated.id in ids


def test_rotate_credential_creates_new_and_schedules_old(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))

    rotated = scim_admin.rotate_credential(ru, str(sp["id"]), first.id, overlap_hours=24)
    assert rotated.rotated_from_id == first.id
    assert rotated.rotated_from_revoke_at is not None
    assert rotated.plaintext != first.plaintext

    # The new token is what the worker would receive.
    row = database.scim_credentials.get_active_credential_for_outbound(
        test_tenant["id"], str(sp["id"])
    )
    assert row is not None
    assert str(row["id"]) == rotated.id

    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT elm.metadata FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_token_rotated' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert len(events) == 1
    assert events[0]["metadata"]["old_credential_id"] == first.id
    assert events[0]["metadata"]["new_credential_id"] == rotated.id


def test_rotate_credential_zero_overlap_revokes_immediately(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))

    scim_admin.rotate_credential(ru, str(sp["id"]), first.id, overlap_hours=0)

    listing = scim_admin.list_credentials(ru, str(sp["id"]))
    # Old credential is hard-revoked, not in usable list.
    assert first.id not in {item.id for item in listing.items}


def test_rotate_credential_unknown_id_raises(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        scim_admin.rotate_credential(ru, str(sp["id"]), str(uuid4()))


def test_rotate_credential_overlap_out_of_range(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))
    with pytest.raises(ValidationError):
        scim_admin.rotate_credential(ru, str(sp["id"]), first.id, overlap_hours=1000)


def test_revoke_credential_marks_revoked_and_logs(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    first = scim_admin.create_credential(ru, str(sp["id"]))

    scim_admin.revoke_credential(ru, str(sp["id"]), first.id)

    listing = scim_admin.list_credentials(ru, str(sp["id"]))
    assert first.id not in {item.id for item in listing.items}

    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT elm.metadata FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_token_revoked' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert len(events) == 1
    assert events[0]["metadata"]["credential_id"] == first.id


def test_revoke_credential_unknown_raises(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    with pytest.raises(NotFoundError):
        scim_admin.revoke_credential(ru, str(sp["id"]), str(uuid4()))


# ---------------------------------------------------------------------------
# Sync activity
# ---------------------------------------------------------------------------


def _write_sync_log_row(tenant_id, sp_id, status, started_at=None, completed=False):
    row = database.scim_sync_log.create_entry(
        tenant_id=tenant_id,
        tenant_id_value=str(tenant_id),
        sp_id=str(sp_id),
        resource_type="user",
        resource_id=str(uuid4()),
        status=status,
        attempt=1,
        started_at=started_at or datetime.now(UTC),
    )
    if completed:
        database.scim_sync_log.update_status(tenant_id, str(row["id"]), status, completed=True)
    return row


def test_list_sync_log_paginates_and_orders(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])

    # Mix completed and in-flight; completed first so in-flight has newer created_at
    _write_sync_log_row(test_tenant["id"], sp["id"], "done", completed=True)
    in_flight = _write_sync_log_row(test_tenant["id"], sp["id"], "running")

    page = scim_admin.list_sync_log(ru, str(sp["id"]), page=1, page_size=10)
    assert page.total == 2
    assert page.page_size == 10
    # In-flight surfaces first thanks to `completed_at DESC NULLS FIRST`.
    assert page.items[0].id == str(in_flight["id"])


def test_list_sync_log_filters_by_status(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    _write_sync_log_row(test_tenant["id"], sp["id"], "done", completed=True)
    failed = _write_sync_log_row(test_tenant["id"], sp["id"], "failed", completed=True)

    page = scim_admin.list_sync_log(ru, str(sp["id"]), status="failed")
    assert page.total == 1
    assert page.items[0].id == str(failed["id"])


def test_get_queue_status_counts(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    dead = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead["id"]), error="x")

    snap = scim_admin.get_queue_status(ru, str(sp["id"]))
    assert snap.pending == 1
    assert snap.dead_lettered == 1


def test_retry_dead_lettered_revives_rows_and_logs(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    dead_a = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    dead_b = database.scim_push_queue.upsert_entry(
        test_tenant["id"], str(test_tenant["id"]), sp["id"], "user", str(uuid4())
    )
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead_a["id"]), error="a")
    database.scim_push_queue.mark_dead_letter(test_tenant["id"], str(dead_b["id"]), error="b")

    result = scim_admin.retry_dead_lettered(ru, str(sp["id"]))
    assert result.revived == 2

    counts = database.scim_push_queue.count_pending_for_sp(test_tenant["id"], str(sp["id"]))
    assert counts == {"pending": 2, "dead_lettered": 0}

    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT elm.metadata FROM event_logs el
        JOIN event_log_metadata elm ON elm.metadata_hash = el.metadata_hash
        WHERE el.event_type = 'scim_config_updated' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    # Must include a retry_dead_lettered action breadcrumb.
    actions = [e["metadata"].get("action") for e in events]
    assert "retry_dead_lettered" in actions


def test_retry_dead_lettered_no_rows_returns_zero(test_tenant, test_admin_user):
    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    ru = _requesting_user(test_tenant["id"], test_admin_user["id"])
    result = scim_admin.retry_dead_lettered(ru, str(sp["id"]))
    assert result.revived == 0

    # No-op retry must NOT emit a scim_config_updated audit event.
    events = database.fetchall(
        database.UNSCOPED,
        """
        SELECT el.id FROM event_logs el
        WHERE el.event_type = 'scim_config_updated' AND el.artifact_id = :sp_id
        """,
        {"sp_id": str(sp["id"])},
    )
    assert events == []


# ---------------------------------------------------------------------------
# Authorization boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fn,args_factory",
    [
        ("get_scim_config", lambda sp_id: (sp_id,)),
        (
            "update_scim_config",
            lambda sp_id: (sp_id, ScimConfigUpdate(scim_kind="slack")),
        ),
        ("list_credentials", lambda sp_id: (sp_id,)),
        ("create_credential", lambda sp_id: (sp_id,)),
        ("rotate_credential", lambda sp_id: (sp_id, str(uuid4()))),
        ("revoke_credential", lambda sp_id: (sp_id, str(uuid4()))),
        ("list_sync_log", lambda sp_id: (sp_id,)),
        ("get_queue_status", lambda sp_id: (sp_id,)),
        ("retry_dead_lettered", lambda sp_id: (sp_id,)),
    ],
)
def test_admin_service_requires_admin_role(fn, args_factory, test_tenant, test_admin_user):
    """Every admin service entry point must reject non-admin roles."""
    from services.exceptions import ForbiddenError

    sp = _create_sp(test_tenant["id"], test_admin_user["id"])
    non_admin = _requesting_user(test_tenant["id"], test_admin_user["id"], role="user")

    func = getattr(scim_admin, fn)
    with pytest.raises(ForbiddenError):
        func(non_admin, *args_factory(str(sp["id"])))
