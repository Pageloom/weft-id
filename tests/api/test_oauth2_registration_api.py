"""Admin API for dynamic client registration (/api/v1/oauth2/registration)
and the registration fields on /api/v1/oauth2/clients."""

import database
from services import oauth2_registration as registration_service

BASE = "/api/v1/oauth2/registration"


def _h(host, auth):
    return {"Host": host, **auth}


class TestSettingsApi:
    def test_get_defaults(self, client, test_tenant_host, oauth2_admin_authorization_header):
        response = client.get(
            f"{BASE}/settings", headers=_h(test_tenant_host, oauth2_admin_authorization_header)
        )

        assert response.status_code == 200
        assert response.json() == {
            "policy": "off",
            "default_access": "none",
            "registration_endpoint": None,
        }

    def test_patch(self, client, test_tenant, test_tenant_host, oauth2_admin_authorization_header):
        response = client.patch(
            f"{BASE}/settings",
            headers=_h(test_tenant_host, oauth2_admin_authorization_header),
            json={"policy": "open"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["policy"] == "open"
        assert body["default_access"] == "none"
        assert body["registration_endpoint"] == f"https://{test_tenant_host}/oauth2/register"
        assert registration_service.is_registration_enabled(test_tenant["id"])

    def test_patch_rejects_unknown_value(
        self, client, test_tenant_host, oauth2_admin_authorization_header
    ):
        response = client.patch(
            f"{BASE}/settings",
            headers=_h(test_tenant_host, oauth2_admin_authorization_header),
            json={"default_access": "everyone"},
        )
        assert response.status_code == 422

    def test_member_forbidden(self, client, test_tenant_host, oauth2_authorization_header):
        headers = _h(test_tenant_host, oauth2_authorization_header)
        assert client.get(f"{BASE}/settings", headers=headers).status_code == 403
        assert (
            client.patch(f"{BASE}/settings", headers=headers, json={"policy": "open"}).status_code
            == 403
        )


class TestTokensApi:
    def test_create_list_revoke(self, client, test_tenant_host, oauth2_admin_authorization_header):
        headers = _h(test_tenant_host, oauth2_admin_authorization_header)

        created = client.post(
            f"{BASE}/initial-access-tokens",
            headers=headers,
            json={"name": "Partner", "expires_in_days": 10},
        )
        listed = client.get(f"{BASE}/initial-access-tokens", headers=headers)
        token_id = created.json()["id"]
        revoked = client.post(f"{BASE}/initial-access-tokens/{token_id}/revoke", headers=headers)
        again = client.post(f"{BASE}/initial-access-tokens/{token_id}/revoke", headers=headers)

        assert created.status_code == 201
        assert created.json()["token"].startswith("weft-id_iat_")
        assert created.json()["status"] == "active"
        assert listed.status_code == 200
        assert [t["id"] for t in listed.json()] == [token_id]
        assert "token" not in listed.json()[0]
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "revoked"
        assert again.status_code == 404

    def test_create_validation(self, client, test_tenant_host, oauth2_admin_authorization_header):
        headers = _h(test_tenant_host, oauth2_admin_authorization_header)
        for body in ({"name": ""}, {"name": "x", "expires_in_days": 0}, {"name": "x" * 256}):
            response = client.post(f"{BASE}/initial-access-tokens", headers=headers, json=body)
            assert response.status_code == 422

    def test_revoke_bad_id(self, client, test_tenant_host, oauth2_admin_authorization_header):
        response = client.post(
            f"{BASE}/initial-access-tokens/not-a-uuid/revoke",
            headers=_h(test_tenant_host, oauth2_admin_authorization_header),
        )
        assert response.status_code == 404

    def test_member_forbidden(self, client, test_tenant_host, oauth2_authorization_header):
        headers = _h(test_tenant_host, oauth2_authorization_header)
        assert client.get(f"{BASE}/initial-access-tokens", headers=headers).status_code == 403
        assert (
            client.post(
                f"{BASE}/initial-access-tokens", headers=headers, json={"name": "x"}
            ).status_code
            == 403
        )
        assert (
            client.post(
                f"{BASE}/initial-access-tokens/00000000-0000-0000-0000-000000000001/revoke",
                headers=headers,
            ).status_code
            == 403
        )


class TestClientFields:
    def test_registered_client_fields_in_client_api(
        self,
        client,
        test_tenant,
        test_tenant_host,
        test_admin_user,
        oauth2_admin_authorization_header,
        normal_oauth2_client,
    ):
        database.oauth2.upsert_registration_settings(
            test_tenant["id"],
            test_tenant["id"],
            policy="open",
            default_access="none",
            updated_by=str(test_admin_user["id"]),
        )
        body = registration_service.register_client(
            test_tenant["id"],
            {
                "redirect_uris": ["https://rp.example/cb"],
                "logo_uri": "https://rp.example/logo.png",
                "tos_uri": "https://rp.example/tos",
            },
            initial_access_token=None,
            base_url="https://unused.example",
        )

        listed = client.get(
            "/api/v1/oauth2/clients",
            headers=_h(test_tenant_host, oauth2_admin_authorization_header),
        ).json()

        by_id = {c["client_id"]: c for c in listed}
        registered = by_id[body["client_id"]]
        assert registered["dynamically_registered"] is True
        assert registered["logo_uri"] == "https://rp.example/logo.png"
        assert registered["tos_uri"] == "https://rp.example/tos"
        assert registered["oidc_enabled"] is True
        assert by_id[normal_oauth2_client["client_id"]]["dynamically_registered"] is False


class TestResetRegistrationTokenApi:
    def _registered(self, test_tenant, admin):
        database.oauth2.upsert_registration_settings(
            test_tenant["id"],
            test_tenant["id"],
            policy="open",
            default_access="none",
            updated_by=str(admin["id"]),
        )
        return registration_service.register_client(
            test_tenant["id"],
            {"redirect_uris": ["https://rp.example/cb"]},
            initial_access_token=None,
            base_url="https://unused.example",
        )

    def test_reset(
        self,
        client,
        test_tenant,
        test_admin_user,
        test_tenant_host,
        oauth2_admin_authorization_header,
    ):
        body = self._registered(test_tenant, test_admin_user)

        response = client.post(
            f"{BASE}/clients/{body['client_id']}/reset-registration-token",
            headers=_h(test_tenant_host, oauth2_admin_authorization_header),
        )

        assert response.status_code == 200
        data = response.json()
        assert data["client_id"] == body["client_id"]
        registration_service.authenticate_registration(
            test_tenant["id"], body["client_id"], data["registration_access_token"]
        )

    def test_unknown_client(self, client, test_tenant_host, oauth2_admin_authorization_header):
        response = client.post(
            f"{BASE}/clients/weft-id_client_nope/reset-registration-token",
            headers=_h(test_tenant_host, oauth2_admin_authorization_header),
        )
        assert response.status_code == 404

    def test_member_forbidden(
        self, client, test_tenant, test_admin_user, test_tenant_host, oauth2_authorization_header
    ):
        body = self._registered(test_tenant, test_admin_user)
        response = client.post(
            f"{BASE}/clients/{body['client_id']}/reset-registration-token",
            headers=_h(test_tenant_host, oauth2_authorization_header),
        )
        assert response.status_code == 403
