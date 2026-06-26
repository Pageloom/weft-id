"""Shared fixtures for router tests."""

import uuid

import pytest


def _is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError, AttributeError:
        return False


@pytest.fixture(autouse=True)
def bypass_saml_acs_ratelimit(mocker):
    """Bypass SAML ACS rate limiting for all router tests.

    Tests run in parallel and share the 'testclient' IP. In CI where Memcached
    is available, the shared counter exhausts the 20-request limit and unrelated
    tests start receiving 429. Tests that specifically test rate limiting override
    this by patching the entire `ratelimit` object with @patch(...ratelimit).
    """
    mocker.patch("routers.saml.authentication.ratelimit.prevent", return_value=1)


@pytest.fixture(autouse=True)
def _guard_db_calls_with_fake_ids(mocker):
    """Block database calls with invalid or non-existent IDs.

    Router tests that use real fixtures pass valid UUIDs for records that
    exist in the database. Tests with fake IDs or UUIDs for non-existent
    records get silently blocked, preventing noisy FK/UUID errors in PG logs.
    """
    import database
    import database.event_log
    import database.saml
    import database.user_activity

    real_upsert = database.user_activity.upsert_activity
    real_create_event = database.event_log.create_event
    real_get_idp = database.saml.get_identity_provider

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

    def guarded_get_idp(tenant_id, idp_id):
        if not _is_valid_uuid(idp_id):
            return None
        return real_get_idp(tenant_id, idp_id)

    mocker.patch("database.user_activity.upsert_activity", side_effect=guarded_upsert)
    mocker.patch("database.event_log.create_event", side_effect=guarded_create_event)
    mocker.patch("database.saml.get_identity_provider", side_effect=guarded_get_idp)
