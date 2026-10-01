"""Web tests: the Client Authentication section on the App and Service
Account detail pages (real database).

Covers the section's rendering per client kind, switching to private_key_jwt
with pasted keys or a JWKS URL, switching back (new secret shown once),
validation errors, the regenerate action refused for a private_key_jwt
client, and role checks.
"""

import json

import database
import pytest
from main import app

from tests.helpers.client import TestClient
from tests.helpers.client_keys import JWKS

URI = "https://keys.example.com/jwks.json"


@pytest.fixture
def public_app(test_tenant, test_admin_user):
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="TV App",
        redirect_uris=[],
        created_by=str(test_admin_user["id"]),
        device_grant_enabled=True,
        is_public=True,
    )


def _post(path, data):
    return TestClient(app).post(
        path, data={**data, "csrf_token": "test-token"}, follow_redirects=False
    )


def _saved(test_tenant, client_id):
    return database.oauth2.get_client_by_client_id(test_tenant["id"], client_id)


def _to_private_key_jwt(test_tenant, client_id):
    database.oauth2.set_client_authentication(
        test_tenant["id"],
        client_id,
        client_auth_method="private_key_jwt",
        jwks=None,
        jwks_uri=URI,
        token_endpoint_auth_signing_alg="PS256",
        rotate_secret=True,
    )


class TestAppDetailSection:
    def test_secret_client(self, test_admin_user, override_auth, normal_oauth2_client):
        override_auth(test_admin_user, level="admin")
        text = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}").text
        assert "Client Authentication" in text
        assert f"/applications/oauth/{normal_oauth2_client['client_id']}/authentication" in text
        assert 'data-current-method="client_secret"' in text
        assert 'id="client-auth-keys" class="space-y-3 hidden"' in text
        assert 'id="show-regenerate-btn"' in text

    def test_private_key_jwt_client(
        self, test_tenant, test_admin_user, override_auth, normal_oauth2_client
    ):
        _to_private_key_jwt(test_tenant, normal_oauth2_client["client_id"])
        override_auth(test_admin_user, level="admin")
        text = TestClient(app).get(f"/applications/oauth/{normal_oauth2_client['client_id']}").text
        assert 'data-current-method="private_key_jwt"' in text
        assert f'value="{URI}"' in text
        assert "This client registered PS256" in text
        assert 'id="show-regenerate-btn"' not in text

    def test_public_client_has_no_section(self, test_admin_user, override_auth, public_app):
        override_auth(test_admin_user, level="admin")
        text = TestClient(app).get(f"/applications/oauth/{public_app['client_id']}").text
        assert 'id="client-auth-form"' not in text
        assert "/authentication" not in text


class TestAppSetAuthentication:
    def test_paste_keys(self, test_tenant, test_admin_user, override_auth, normal_oauth2_client):
        override_auth(test_admin_user, level="admin")
        client_id = normal_oauth2_client["client_id"]
        response = _post(
            f"/applications/oauth/{client_id}/authentication",
            {
                "method": "private_key_jwt",
                "key_source": "jwks",
                "jwks": json.dumps(JWKS),
                # Ignored: the key source is the pasted set.
                "jwks_uri": "https://ignored.example/jwks",
            },
        )
        assert response.status_code == 303
        assert response.headers["location"].endswith("?success=authentication_updated")
        saved = _saved(test_tenant, client_id)
        assert saved["client_auth_method"] == "private_key_jwt"
        assert saved["jwks"] == JWKS
        assert saved["jwks_uri"] is None

    def test_jwks_url(self, test_tenant, test_admin_user, override_auth, normal_oauth2_client):
        override_auth(test_admin_user, level="admin")
        client_id = normal_oauth2_client["client_id"]
        response = _post(
            f"/applications/oauth/{client_id}/authentication",
            {
                "method": "private_key_jwt",
                "key_source": "jwks_uri",
                "jwks": "{bad",
                "jwks_uri": URI,
            },
        )
        assert "success=authentication_updated" in response.headers["location"]
        saved = _saved(test_tenant, client_id)
        assert saved["jwks_uri"] == URI
        assert saved["jwks"] is None

    def test_switch_back_shows_new_secret_once(
        self, test_tenant, test_admin_user, override_auth, normal_oauth2_client
    ):
        client_id = normal_oauth2_client["client_id"]
        _to_private_key_jwt(test_tenant, client_id)
        override_auth(test_admin_user, level="admin")
        http = TestClient(app)
        response = http.post(
            f"/applications/oauth/{client_id}/authentication",
            data={"method": "client_secret", "key_source": "jwks", "csrf_token": "t"},
            follow_redirects=False,
        )
        assert "success=authentication_updated" in response.headers["location"]
        assert _saved(test_tenant, client_id)["client_auth_method"] == "client_secret"

        page = http.get(response.headers["location"]).text
        assert "New Client Secret" in page
        assert 'id="cred-client-secret"' in page
        # Shown once.
        assert 'id="cred-client-secret"' not in http.get(f"/applications/oauth/{client_id}").text

    @pytest.mark.parametrize(
        ("data", "error"),
        [
            (
                {"method": "private_key_jwt", "key_source": "jwks", "jwks": "{not json"},
                "invalid_client_keys",
            ),
            (
                {"method": "private_key_jwt", "key_source": "jwks", "jwks": '{"keys": []}'},
                "invalid_client_keys",
            ),
            (
                {"method": "private_key_jwt", "key_source": "jwks_uri", "jwks_uri": "http://x/j"},
                "invalid_client_keys",
            ),
            (
                {"method": "private_key_jwt", "key_source": "jwks", "jwks": ""},
                "client_keys_required",
            ),
            ({"method": "magic", "key_source": "jwks"}, "authentication_update_failed"),
        ],
    )
    def test_errors(
        self, test_tenant, test_admin_user, override_auth, normal_oauth2_client, data, error
    ):
        override_auth(test_admin_user, level="admin")
        client_id = normal_oauth2_client["client_id"]
        response = _post(f"/applications/oauth/{client_id}/authentication", data)
        assert response.headers["location"].endswith(f"?error={error}")
        assert _saved(test_tenant, client_id)["client_auth_method"] == "client_secret"
        page = TestClient(app).get(response.headers["location"]).text
        assert "An error occurred" not in page

    def test_public_client_refused(self, test_admin_user, override_auth, public_app):
        override_auth(test_admin_user, level="admin")
        response = _post(
            f"/applications/oauth/{public_app['client_id']}/authentication",
            {"method": "private_key_jwt", "key_source": "jwks_uri", "jwks_uri": URI},
        )
        assert "error=authentication_update_failed" in response.headers["location"]

    def test_member_redirected(self, test_user, override_auth, normal_oauth2_client):
        override_auth(test_user, level="user")
        response = _post(
            f"/applications/oauth/{normal_oauth2_client['client_id']}/authentication",
            {"method": "private_key_jwt", "key_source": "jwks_uri", "jwks_uri": URI},
        )
        assert response.status_code == 303
        assert response.headers["location"] in ("/dashboard", "/login")

    def test_regenerate_refused_for_private_key_jwt(
        self, test_tenant, test_admin_user, override_auth, normal_oauth2_client
    ):
        client_id = normal_oauth2_client["client_id"]
        _to_private_key_jwt(test_tenant, client_id)
        before = _saved(test_tenant, client_id)["client_secret_hash"]
        override_auth(test_admin_user, level="admin")
        response = _post(f"/applications/oauth/{client_id}/regenerate-secret", {})
        assert "error=private_key_jwt_client_no_secret" in response.headers["location"]
        assert _saved(test_tenant, client_id)["client_secret_hash"] == before


class TestServiceAccounts:
    def test_section_rendered(self, test_super_admin_user, override_auth, b2b_oauth2_client):
        override_auth(test_super_admin_user, level="super_admin")
        text = (
            TestClient(app)
            .get(f"/applications/service-accounts/{b2b_oauth2_client['client_id']}")
            .text
        )
        assert "Client Authentication" in text
        assert (
            f"/applications/service-accounts/{b2b_oauth2_client['client_id']}/authentication"
            in text
        )

    def test_switch(self, test_tenant, test_super_admin_user, override_auth, b2b_oauth2_client):
        override_auth(test_super_admin_user, level="super_admin")
        client_id = b2b_oauth2_client["client_id"]
        response = _post(
            f"/applications/service-accounts/{client_id}/authentication",
            {"method": "private_key_jwt", "key_source": "jwks_uri", "jwks_uri": URI},
        )
        assert "success=authentication_updated" in response.headers["location"]
        assert _saved(test_tenant, client_id)["client_auth_method"] == "private_key_jwt"

        text = TestClient(app).get(f"/applications/service-accounts/{client_id}").text
        assert 'id="show-regenerate-btn"' not in text

    def test_regenerate_refused(
        self, test_tenant, test_super_admin_user, override_auth, b2b_oauth2_client
    ):
        client_id = b2b_oauth2_client["client_id"]
        _to_private_key_jwt(test_tenant, client_id)
        override_auth(test_super_admin_user, level="super_admin")
        response = _post(f"/applications/service-accounts/{client_id}/regenerate-secret", {})
        assert "error=private_key_jwt_client_no_secret" in response.headers["location"]

    def test_admin_cannot_change_b2b(
        self, test_tenant, test_admin_user, override_auth, b2b_oauth2_client
    ):
        override_auth(test_admin_user, level="admin")
        client_id = b2b_oauth2_client["client_id"]
        response = _post(
            f"/applications/service-accounts/{client_id}/authentication",
            {"method": "private_key_jwt", "key_source": "jwks_uri", "jwks_uri": URI},
        )
        assert response.status_code == 303
        assert _saved(test_tenant, client_id)["client_auth_method"] == "client_secret"
