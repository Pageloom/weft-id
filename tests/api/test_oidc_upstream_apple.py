"""Sign in with Apple connection fields through the API."""

import pytest

from tests.fixtures import apple as fx


@pytest.fixture
def api_headers(test_tenant_host, oauth2_super_admin_access_token):
    return {"Host": test_tenant_host, "Authorization": f"Bearer {oauth2_super_admin_access_token}"}


class TestApi:
    def _body(self, **overrides):
        body = {
            "name": "Apple",
            "provider_type": "apple",
            "client_id": fx.CLIENT_ID,
            "apple_team_id": fx.TEAM_ID,
            "apple_key_id": fx.KEY_ID,
            "apple_private_key": fx.auth_key_pem(),
        }
        body.update(overrides)
        return body

    def test_create(self, client, api_headers):
        response = client.post(
            "/api/v1/oidc-upstream/connections", headers=api_headers, json=self._body()
        )
        assert response.status_code == 201, response.text
        data = response.json()
        assert data["provider_label"] == "Apple"
        assert data["apple_team_id"] == fx.TEAM_ID
        assert data["apple_key_id"] == fx.KEY_ID
        assert data["apple_private_key_set"] is True
        assert "apple_private_key" not in data
        assert data["uses_discovery"] is True

    def test_create_bad_key(self, client, api_headers):
        response = client.post(
            "/api/v1/oidc-upstream/connections",
            headers=api_headers,
            json=self._body(apple_private_key="junk"),
        )
        assert response.status_code == 400

    def test_create_bad_team_id(self, client, api_headers):
        response = client.post(
            "/api/v1/oidc-upstream/connections",
            headers=api_headers,
            json=self._body(apple_team_id="team"),
        )
        assert response.status_code == 422

    def test_create_with_client_secret(self, client, api_headers):
        response = client.post(
            "/api/v1/oidc-upstream/connections",
            headers=api_headers,
            json=self._body(client_secret="secret"),
        )
        assert response.status_code == 400

    def test_apple_fields_on_google(self, client, api_headers):
        response = client.post(
            "/api/v1/oidc-upstream/connections",
            headers=api_headers,
            json={"name": "G", "provider_type": "google", "apple_team_id": fx.TEAM_ID},
        )
        assert response.status_code == 400

    def test_patch(self, client, api_headers):
        created = client.post(
            "/api/v1/oidc-upstream/connections", headers=api_headers, json=self._body()
        ).json()
        response = client.patch(
            f"/api/v1/oidc-upstream/connections/{created['id']}",
            headers=api_headers,
            json={"apple_key_id": "NEWKEY0001"},
        )
        assert response.status_code == 200
        assert response.json()["apple_key_id"] == "NEWKEY0001"
        assert response.json()["apple_private_key_set"] is True
