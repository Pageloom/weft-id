"""User lifecycle paths end the user's OIDC sessions (back-channel logout).

Deactivation, anonymization and deletion queue one logout token per
(session, back-channel client) the user holds. Real database throughout.
"""

import database
import pytest
from services import users as users_service
from services.oidc import tokens as tokens_service
from services.types import RequestingUser

ISSUER = "https://tenant.example.com"


@pytest.fixture
def bc_client(test_tenant, test_admin_user):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        name="BC",
        redirect_uris=["https://rp.example/cb"],
        created_by=test_admin_user["id"],
        backchannel_logout_uri="https://rp.example/bc",
    )
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], client["client_id"], oidc_enabled=True
    )
    return client


def _signed_in(test_tenant, client, user, *sids):
    for sid in sids:
        tokens_service.issue_id_token(
            tenant_id=str(test_tenant["id"]),
            issuer=ISSUER,
            client_uuid=str(client["id"]),
            client_id=client["client_id"],
            user_id=str(user["id"]),
            scopes={"openid"},
            sid=sid,
        )


def _deliveries(test_tenant) -> list[dict]:
    return database.fetchall(
        str(test_tenant["id"]), "select * from oidc_backchannel_logout_deliveries order by sid"
    )


def _session_rows(test_tenant, user) -> list[dict]:
    return database.fetchall(
        str(test_tenant["id"]),
        "select * from oidc_session_clients where user_id = :u",
        {"u": user["id"]},
    )


def _as(user, test_tenant, role) -> RequestingUser:
    return RequestingUser(id=str(user["id"]), tenant_id=str(test_tenant["id"]), role=role)


def test_inactivate_queues_logout_for_every_session(
    test_tenant, test_admin_user, test_user, bc_client
):
    _signed_in(test_tenant, bc_client, test_user, "s-1", "s-2")

    users_service.inactivate_user(_as(test_admin_user, test_tenant, "admin"), str(test_user["id"]))

    rows = _deliveries(test_tenant)
    assert [r["sid"] for r in rows] == ["s-1", "s-2"]
    assert {r["sub"] for r in rows} == {str(test_user["id"])}
    assert {r["issuer"] for r in rows} == {ISSUER}
    assert _session_rows(test_tenant, test_user) == []


def test_inactivate_leaves_other_users_sessions(
    test_tenant, test_admin_user, test_super_admin_user, test_user, bc_client
):
    _signed_in(test_tenant, bc_client, test_super_admin_user, "admin-s")

    users_service.inactivate_user(_as(test_admin_user, test_tenant, "admin"), str(test_user["id"]))

    assert _deliveries(test_tenant) == []
    assert len(_session_rows(test_tenant, test_super_admin_user)) == 1


def test_anonymize_queues_logout_and_revokes_tokens(
    test_tenant, test_super_admin_user, test_user, bc_client
):
    tid = str(test_tenant["id"])
    _signed_in(test_tenant, bc_client, test_user, "s-1")
    refresh, _ = database.oauth2.create_refresh_token(
        tid, tid, str(bc_client["id"]), str(test_user["id"])
    )
    database.oauth2.upsert_consent_grant(
        tid, tid, str(bc_client["id"]), str(test_user["id"]), ["openid"]
    )

    users_service.anonymize_user(
        _as(test_super_admin_user, test_tenant, "super_admin"), str(test_user["id"])
    )

    assert [r["sid"] for r in _deliveries(test_tenant)] == ["s-1"]
    assert database.oauth2.validate_refresh_token(tid, refresh, str(bc_client["id"])) is None
    assert (
        database.oauth2.get_consent_grant(tid, str(bc_client["id"]), str(test_user["id"])) is None
    )


def test_delete_queues_logout_before_the_user_goes(
    test_tenant, test_admin_user, test_user, bc_client
):
    """Session records cascade with the user; the deliveries must already exist."""
    _signed_in(test_tenant, bc_client, test_user, "s-1")

    users_service.delete_user(_as(test_admin_user, test_tenant, "admin"), str(test_user["id"]))

    assert database.users.get_user_by_id(str(test_tenant["id"]), str(test_user["id"])) is None
    (row,) = _deliveries(test_tenant)
    assert row["sub"] == str(test_user["id"])
    assert row["sid"] == "s-1"


def test_rejected_inactivation_queues_nothing(test_tenant, test_admin_user, bc_client):
    """A refused request (self-inactivation) never reaches the fan-out."""
    from services.exceptions import ValidationError

    _signed_in(test_tenant, bc_client, test_admin_user, "s-1")
    with pytest.raises(ValidationError):
        users_service.inactivate_user(
            _as(test_admin_user, test_tenant, "admin"), str(test_admin_user["id"])
        )
    assert _deliveries(test_tenant) == []
