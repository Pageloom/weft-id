"""Unit tests for OIDC-client access-control enforcement.

The service reuses the shared DAG-aware grant resolver and audits every denial
with an ``oidc_access_denied`` event. Enforcement applies only to OIDC-enabled
clients; the router (not this service) is responsible for skipping plain OAuth2
clients.
"""

from unittest.mock import patch

import database
from services.oidc import access as access_service


def _create_oidc_client(tid, uid, available_to_all=False):
    client = database.oauth2.create_normal_client(
        tenant_id=tid,
        tenant_id_value=str(tid),
        name="Access OIDC Client",
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(uid),
    )
    database.execute(
        tid,
        "update oauth2_clients set oidc_enabled = true, available_to_all = :ata where id = :id",
        {"id": client["id"], "ata": available_to_all},
    )
    return client


def _grant(tid, uid, client_id, group_id):
    database.execute(
        tid,
        """
        insert into sp_group_assignments (tenant_id, oauth2_client_id, group_id, assigned_by)
        values (:tid, :cid, :gid, :by)
        """,
        {"tid": str(tid), "cid": client_id, "gid": group_id, "by": str(uid)},
    )


def test_allows_user_with_group_grant(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    oidc = _create_oidc_client(tid, uid)
    group = database.groups.create_group(tenant_id=tid, tenant_id_value=str(tid), name="Granted")
    _grant(tid, uid, oidc["id"], group["id"])
    database.groups.add_group_member(tid, str(tid), group["id"], str(uid))

    with patch("services.oidc.access.log_event") as mock_log:
        allowed = access_service.user_can_access_client(
            tenant_id=str(tid),
            user_id=str(uid),
            client_uuid=str(oidc["id"]),
            client_id=oidc["client_id"],
            client_name="Access OIDC Client",
        )

    assert allowed is True
    # An allow is NOT audited here (the id-token issuance records the hand-off).
    mock_log.assert_not_called()


def test_allows_available_to_all(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    oidc = _create_oidc_client(tid, uid, available_to_all=True)

    allowed = access_service.user_can_access_client(
        tenant_id=str(tid),
        user_id=str(uid),
        client_uuid=str(oidc["id"]),
        client_id=oidc["client_id"],
    )
    assert allowed is True


def test_denies_and_audits_when_no_grant(test_tenant, test_user):
    tid = test_tenant["id"]
    uid = test_user["id"]
    oidc = _create_oidc_client(tid, uid)
    group = database.groups.create_group(tenant_id=tid, tenant_id_value=str(tid), name="NotMine")
    _grant(tid, uid, oidc["id"], group["id"])  # user is not a member

    with patch("services.oidc.access.log_event") as mock_log:
        allowed = access_service.user_can_access_client(
            tenant_id=str(tid),
            user_id=str(uid),
            client_uuid=str(oidc["id"]),
            client_id=oidc["client_id"],
            client_name="Access OIDC Client",
        )

    assert allowed is False
    mock_log.assert_called_once()
    kwargs = mock_log.call_args.kwargs
    assert kwargs["event_type"] == "oidc_access_denied"
    assert kwargs["artifact_type"] == "oauth2_client"
    assert kwargs["artifact_id"] == str(oidc["id"])
    assert kwargs["metadata"]["client_id"] == oidc["client_id"]
