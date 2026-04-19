"""Shared fixtures for service tests."""

import uuid

import pytest


def _is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError):
        return False


@pytest.fixture(autouse=True)
def _guard_db_calls_with_fake_ids(mocker):
    """Block database calls with invalid or non-existent IDs.

    Service tests that use real fixtures (test_tenant, test_user) pass valid
    UUIDs for records that exist in the database. Tests with fake IDs or
    UUIDs for non-existent records get silently blocked, preventing noisy
    FK/UUID errors in PG logs.
    """
    import database
    import database.event_log
    import database.user_activity

    real_upsert = database.user_activity.upsert_activity
    real_create_event = database.event_log.create_event

    def guarded_upsert(tenant_id, user_id):
        if not _is_valid_uuid(tenant_id) or not _is_valid_uuid(user_id):
            return
        row = database.fetchone(
            tenant_id,
            "SELECT 1 FROM users WHERE id = :uid",
            {"uid": user_id},
        )
        if not row:
            return
        return real_upsert(tenant_id, user_id)

    def guarded_create_event(**kwargs):
        for field in ("tenant_id", "actor_user_id", "artifact_id"):
            val = kwargs.get(field, "")
            if val and not _is_valid_uuid(val):
                return
        tid = kwargs.get("tenant_id", "")
        row = database.fetchone(
            database.UNSCOPED,
            "SELECT 1 FROM tenants WHERE id = :id",
            {"id": tid},
        )
        if not row:
            return
        return real_create_event(**kwargs)

    mocker.patch("database.user_activity.upsert_activity", side_effect=guarded_upsert)
    mocker.patch("database.event_log.create_event", side_effect=guarded_create_event)
