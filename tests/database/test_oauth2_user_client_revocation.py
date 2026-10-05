"""Database tests: revoking everything one user granted one client.

``revoke_user_client_tokens`` runs when a consent grant is revoked. It must
take that client's tokens, unredeemed codes and approved device requests for
that user, and nothing belonging to another user or another client.
"""

from datetime import UTC, datetime

import database
import pytest

REDIRECT_URI = "http://localhost:3000/callback"


def _client(test_tenant, test_admin_user, name):
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=name,
        redirect_uris=[REDIRECT_URI],
        created_by=str(test_admin_user["id"]),
    )


def _tokens(tid, client, user) -> tuple[str, str]:
    refresh, refresh_id = database.oauth2.create_refresh_token(
        tenant_id=tid, tenant_id_value=tid, client_id=str(client["id"]), user_id=str(user["id"])
    )
    access = database.oauth2.create_access_token(
        tenant_id=tid,
        tenant_id_value=tid,
        client_id=str(client["id"]),
        user_id=str(user["id"]),
        parent_token_id=refresh_id,
    )
    return access, refresh


def _code(tid, client, user) -> str:
    return database.oauth2.create_authorization_code(
        tenant_id=tid,
        tenant_id_value=tid,
        client_id=str(client["id"]),
        user_id=str(user["id"]),
        redirect_uri=REDIRECT_URI,
    )


def _approved_device_code(tid, client, user) -> dict:
    created = database.oauth2.create_device_code(
        tenant_id=tid, tenant_id_value=tid, client_id=str(client["id"]), scope=None
    )
    database.oauth2.decide_device_code(
        tid, created["id"], approved=True, user_id=str(user["id"]), auth_time=datetime.now(UTC)
    )
    return created


def _count(tid, table, client, user) -> int:
    row = database.fetchone(
        tid,
        f"select count(*) as n from {table} where client_id = :c and user_id = :u",
        {"c": str(client["id"]), "u": str(user["id"])},
    )
    return int(row["n"])


@pytest.fixture
def apps(test_tenant, test_admin_user):
    return (
        _client(test_tenant, test_admin_user, "Revoked App"),
        _client(test_tenant, test_admin_user, "Other App"),
    )


def test_revokes_the_users_tokens_for_the_client(test_tenant, apps, test_user):
    tid = str(test_tenant["id"])
    app, _ = apps
    access, refresh = _tokens(tid, app, test_user)
    assert database.oauth2.validate_token(access, tid) is not None

    revoked = database.oauth2.revoke_user_client_tokens(tid, str(test_user["id"]), str(app["id"]))

    assert revoked == 2
    assert database.oauth2.validate_token(access, tid) is None
    assert database.oauth2.validate_refresh_token(tid, refresh, str(app["id"])) is None


def test_leaves_other_clients_and_users(test_tenant, apps, test_user, test_admin_user):
    tid = str(test_tenant["id"])
    app, other = apps
    _tokens(tid, app, test_user)
    other_client_access, _ = _tokens(tid, other, test_user)
    other_user_access, _ = _tokens(tid, app, test_admin_user)
    _code(tid, other, test_user)
    _code(tid, app, test_admin_user)
    _approved_device_code(tid, other, test_user)

    database.oauth2.revoke_user_client_tokens(tid, str(test_user["id"]), str(app["id"]))

    assert database.oauth2.validate_token(other_client_access, tid) is not None
    assert database.oauth2.validate_token(other_user_access, tid) is not None
    assert _count(tid, "oauth2_authorization_codes", other, test_user) == 1
    assert _count(tid, "oauth2_authorization_codes", app, test_admin_user) == 1
    assert _count(tid, "oauth2_device_codes", other, test_user) == 1


def test_unredeemed_code_cannot_be_redeemed_afterwards(test_tenant, apps, test_user):
    tid = str(test_tenant["id"])
    app, _ = apps
    code = _code(tid, app, test_user)

    database.oauth2.revoke_user_client_tokens(tid, str(test_user["id"]), str(app["id"]))

    assert (
        database.oauth2.validate_and_consume_code(tid, code, str(app["id"]), REDIRECT_URI) is None
    )


def test_redeemed_code_is_kept_for_replay_detection(test_tenant, apps, test_user):
    tid = str(test_tenant["id"])
    app, _ = apps
    code = _code(tid, app, test_user)
    assert database.oauth2.validate_and_consume_code(tid, code, str(app["id"]), REDIRECT_URI)

    database.oauth2.revoke_user_client_tokens(tid, str(test_user["id"]), str(app["id"]))

    replay = database.oauth2.validate_and_consume_code(tid, code, str(app["id"]), REDIRECT_URI)
    assert replay is not None and replay["reused"] is True


def test_approved_device_code_is_deleted(test_tenant, apps, test_user):
    tid = str(test_tenant["id"])
    app, _ = apps
    created = _approved_device_code(tid, app, test_user)

    database.oauth2.revoke_user_client_tokens(tid, str(test_user["id"]), str(app["id"]))

    assert database.oauth2.redeem_device_code(tid, created["id"]) is None
    assert _count(tid, "oauth2_device_codes", app, test_user) == 0


def test_nothing_to_revoke(test_tenant, apps, test_user):
    tid = str(test_tenant["id"])
    app, _ = apps
    assert database.oauth2.revoke_user_client_tokens(tid, str(test_user["id"]), str(app["id"])) == 0
