"""Tests for routers.api.v1.account_authorized_apps (against the real app and DB)."""

from uuid import uuid4

import database


def _grant(test_tenant, test_admin_user, user, name="API Grant App", scopes=("openid",)):
    client = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=name,
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(test_admin_user["id"]),
    )
    grant = database.oauth2.upsert_consent_grant(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        client_id=str(client["id"]),
        user_id=str(user["id"]),
        scopes=list(scopes),
    )
    return client, grant


def test_list_authorized_apps(
    client, test_tenant_host, test_tenant, test_admin_user, test_user, oauth2_authorization_header
):
    # Two of the user's own grants plus one that belongs to the admin.
    app_a, _ = _grant(test_tenant, test_admin_user, test_user, "Zulu", ("openid", "email"))
    app_b, _ = _grant(test_tenant, test_admin_user, test_user, "Alpha")
    _grant(test_tenant, test_admin_user, test_admin_user, "Admin Only")

    response = client.get(
        "/api/v1/account/authorized-apps",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 200
    body = response.json()
    assert [g["client_name"] for g in body] == ["Alpha", "Zulu"]
    assert body[0]["client_id"] == app_b["client_id"]
    assert body[1]["scopes"] == ["email", "openid"]
    assert body[1]["client_is_active"] is True
    assert set(body[0]) >= {"id", "client_id", "client_name", "scopes", "granted_at", "updated_at"}


def test_list_authorized_apps_empty(client, test_tenant_host, oauth2_authorization_header):
    response = client.get(
        "/api/v1/account/authorized-apps",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 200
    assert response.json() == []


def test_list_authorized_apps_requires_auth(client, test_tenant_host):
    response = client.get("/api/v1/account/authorized-apps", headers={"Host": test_tenant_host})
    assert response.status_code == 401


def test_revoke_authorized_app(
    client, test_tenant_host, test_tenant, test_admin_user, test_user, oauth2_authorization_header
):
    _, grant = _grant(test_tenant, test_admin_user, test_user)

    response = client.delete(
        f"/api/v1/account/authorized-apps/{grant['id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 204
    assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(grant["id"])) is None


def test_revoke_authorized_app_of_another_user_is_404(
    client, test_tenant_host, test_tenant, test_admin_user, test_user, oauth2_authorization_header
):
    _, grant = _grant(test_tenant, test_admin_user, test_admin_user)

    response = client.delete(
        f"/api/v1/account/authorized-apps/{grant['id']}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 404
    assert database.oauth2.get_consent_grant_by_id(test_tenant["id"], str(grant["id"]))


def test_revoke_authorized_app_unknown_is_404(
    client, test_tenant_host, oauth2_authorization_header
):
    response = client.delete(
        f"/api/v1/account/authorized-apps/{uuid4()}",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 404
