"""API tests for OIDC client management endpoints.

Exercises the /api/v1/oauth2/clients/{client_id}/oidc* surface end-to-end
against the real service + database layers, using the shared OAuth2 admin
bearer fixtures.
"""

from uuid import uuid4

import database
import pytest


@pytest.fixture
def a_group(test_tenant):
    return database.groups.create_group(
        tenant_id=test_tenant["id"], tenant_id_value=str(test_tenant["id"]), name="API OIDC Group"
    )


def _admin_headers(test_tenant_host, oauth2_admin_authorization_header):
    return {"Host": test_tenant_host, **oauth2_admin_authorization_header}


class TestOidcSettingsAPI:
    def test_enable_oidc(
        self, client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
    ):
        resp = client.patch(
            f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/oidc",
            headers=_admin_headers(test_tenant_host, oauth2_admin_authorization_header),
            json={"oidc_enabled": True},
        )
        assert resp.status_code == 200
        assert resp.json()["oidc_enabled"] is True

    def test_toggle_available_to_all(
        self, client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
    ):
        resp = client.patch(
            f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/oidc",
            headers=_admin_headers(test_tenant_host, oauth2_admin_authorization_header),
            json={"available_to_all": True},
        )
        assert resp.status_code == 200
        assert resp.json()["available_to_all"] is True

    def test_member_forbidden(
        self, client, test_tenant_host, oauth2_authorization_header, normal_oauth2_client
    ):
        resp = client.patch(
            f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/oidc",
            headers={"Host": test_tenant_host, **oauth2_authorization_header},
            json={"oidc_enabled": True},
        )
        assert resp.status_code == 403

    def test_b2b_client_rejected(
        self, client, test_tenant_host, oauth2_admin_authorization_header, b2b_oauth2_client
    ):
        resp = client.patch(
            f"/api/v1/oauth2/clients/{b2b_oauth2_client['client_id']}/oidc",
            headers=_admin_headers(test_tenant_host, oauth2_admin_authorization_header),
            json={"oidc_enabled": True},
        )
        assert resp.status_code == 400

    def test_unknown_client_404(self, client, test_tenant_host, oauth2_admin_authorization_header):
        resp = client.patch(
            "/api/v1/oauth2/clients/weft-id_client_nope/oidc",
            headers=_admin_headers(test_tenant_host, oauth2_admin_authorization_header),
            json={"oidc_enabled": True},
        )
        assert resp.status_code == 404


class TestOidcUrlsAPI:
    def test_urls_scoped_to_host(
        self, client, test_tenant_host, oauth2_admin_authorization_header, normal_oauth2_client
    ):
        resp = client.get(
            f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/oidc/urls",
            headers=_admin_headers(test_tenant_host, oauth2_admin_authorization_header),
        )
        assert resp.status_code == 200
        body = resp.json()
        base = f"https://{test_tenant_host}"
        assert body["issuer"] == base
        assert body["discovery_url"] == f"{base}/.well-known/openid-configuration"
        assert body["jwks_uri"] == f"{base}/.well-known/jwks.json"
        assert body["userinfo_endpoint"] == f"{base}/userinfo"


class TestOidcGroupsAPI:
    def test_assign_list_remove(
        self,
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        normal_oauth2_client,
        a_group,
    ):
        headers = _admin_headers(test_tenant_host, oauth2_admin_authorization_header)
        cid = normal_oauth2_client["client_id"]

        assign = client.post(
            f"/api/v1/oauth2/clients/{cid}/groups",
            headers=headers,
            json={"group_id": str(a_group["id"])},
        )
        assert assign.status_code == 201
        assert assign.json()["group_id"] == str(a_group["id"])

        listing = client.get(f"/api/v1/oauth2/clients/{cid}/groups", headers=headers)
        assert listing.status_code == 200
        assert listing.json()["total"] == 1

        remove = client.delete(
            f"/api/v1/oauth2/clients/{cid}/groups/{a_group['id']}", headers=headers
        )
        assert remove.status_code == 204
        assert (
            client.get(f"/api/v1/oauth2/clients/{cid}/groups", headers=headers).json()["total"] == 0
        )

    def test_bulk_assign(
        self,
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        normal_oauth2_client,
        test_tenant,
    ):
        headers = _admin_headers(test_tenant_host, oauth2_admin_authorization_header)
        cid = normal_oauth2_client["client_id"]
        g1 = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=str(test_tenant["id"]), name="Bulk API 1"
        )
        g2 = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=str(test_tenant["id"]), name="Bulk API 2"
        )
        resp = client.post(
            f"/api/v1/oauth2/clients/{cid}/groups/bulk",
            headers=headers,
            json={"group_ids": [str(g1["id"]), str(g2["id"])]},
        )
        assert resp.status_code == 201
        assert resp.json()["assigned"] == 2

    def test_assign_unknown_group_404(
        self,
        client,
        test_tenant_host,
        oauth2_admin_authorization_header,
        normal_oauth2_client,
    ):
        resp = client.post(
            f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/groups",
            headers=_admin_headers(test_tenant_host, oauth2_admin_authorization_header),
            json={"group_id": str(uuid4())},
        )
        assert resp.status_code == 404

    def test_groups_member_forbidden(
        self,
        client,
        test_tenant_host,
        oauth2_authorization_header,
        normal_oauth2_client,
    ):
        resp = client.get(
            f"/api/v1/oauth2/clients/{normal_oauth2_client['client_id']}/groups",
            headers={"Host": test_tenant_host, **oauth2_authorization_header},
        )
        assert resp.status_code == 403
