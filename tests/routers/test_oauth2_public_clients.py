"""Public OAuth2 clients (RFC 6749 section 2.1) for the device grant, end to
end through the real app.

A public client sends ``client_id`` alone (no secret, no Authorization
header) at the device authorization, token, and revocation endpoints. It may
use only the device_code and refresh_token grants, and it cannot introspect.
A confidential client cannot pass for a public one (client_id alone), and a
public client cannot pass for a confidential one (any secret is refused).
"""

import base64

import database
import pytest
from services import oauth2_device as device_service

GRANT = "urn:ietf:params:oauth:grant-type:device_code"


@pytest.fixture
def public_client(test_tenant, test_admin_user):
    created = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="TV App",
        redirect_uris=[],
        created_by=str(test_admin_user["id"]),
        device_grant_enabled=True,
        is_public=True,
    )
    database.execute(
        test_tenant["id"],
        "update oauth2_clients set oidc_enabled = true, available_to_all = true where id = :id",
        {"id": created["id"]},
    )
    return created


@pytest.fixture
def confidential_device_client(test_tenant, test_admin_user):
    return database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Confidential CLI",
        redirect_uris=["http://localhost:3000/callback"],
        created_by=str(test_admin_user["id"]),
        device_grant_enabled=True,
    )


def _post(http, host, path, data, headers=None):
    return http.post(path, headers={"Host": host, **(headers or {})}, data=data)


def _start(http, host, client_id, **extra):
    return _post(
        http,
        host,
        "/oauth2/device_authorization",
        {"client_id": client_id, "scope": "openid"} | extra,
    )


def _assert_invalid_client(response):
    assert response.status_code == 401, response.text
    assert response.json()["error"] == "invalid_client"
    assert response.headers["www-authenticate"] == 'Basic realm="oauth2"'


def _signed_in_tokens(http, host, test_tenant, test_user, client_id) -> dict:
    """Run the device flow for a public client and return the token response."""
    started = _start(http, host, client_id).json()
    pending = device_service.find_pending_request(test_tenant["id"], started["user_code"])
    assert device_service.decide_request(
        test_tenant["id"], pending, str(test_user["id"]), approved=True, auth_time=None
    )
    response = _post(
        http,
        host,
        "/oauth2/token",
        {"grant_type": GRANT, "device_code": started["device_code"], "client_id": client_id},
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestPublicClientAuthentication:
    def test_client_id_alone_starts_device_authorization(
        self, client, test_tenant_host, public_client
    ):
        assert "client_secret" not in public_client
        response = _start(client, test_tenant_host, public_client["client_id"])
        assert response.status_code == 200, response.text
        assert response.json()["user_code"]

    def test_public_client_presenting_a_secret_is_refused(
        self, client, test_tenant_host, public_client
    ):
        response = _start(
            client, test_tenant_host, public_client["client_id"], client_secret="anything"
        )
        _assert_invalid_client(response)

    def test_public_client_using_basic_is_refused(self, client, test_tenant_host, public_client):
        creds = base64.b64encode(f"{public_client['client_id']}:x".encode()).decode()
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/device_authorization",
            {"scope": "openid"},
            headers={"Authorization": f"Basic {creds}"},
        )
        _assert_invalid_client(response)

    def test_client_id_with_basic_header_is_not_public_auth(
        self, client, test_tenant_host, public_client
    ):
        """A form client_id next to an Authorization header is never read as
        a public client identifying itself."""
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/device_authorization",
            {"client_id": public_client["client_id"]},
            headers={"Authorization": "Bearer something"},
        )
        _assert_invalid_client(response)

    def test_confidential_client_cannot_skip_its_secret(
        self, client, test_tenant_host, confidential_device_client
    ):
        response = _start(client, test_tenant_host, confidential_device_client["client_id"])
        _assert_invalid_client(response)

    def test_unknown_client_id(self, client, test_tenant_host):
        _assert_invalid_client(_start(client, test_tenant_host, "weft-id_client_nope"))

    def test_deactivated_public_client(self, client, test_tenant, test_tenant_host, public_client):
        database.oauth2.deactivate_client(test_tenant["id"], public_client["client_id"])
        response = _start(client, test_tenant_host, public_client["client_id"])
        _assert_invalid_client(response)
        assert response.json()["error_description"] == "Client is deactivated"


class TestPublicClientGrants:
    def test_device_grant_issues_tokens(
        self, client, test_tenant, test_tenant_host, public_client, test_user
    ):
        tokens = _signed_in_tokens(
            client, test_tenant_host, test_tenant, test_user, public_client["client_id"]
        )
        assert tokens["access_token"] and tokens["refresh_token"] and tokens["id_token"]

    def test_refresh_rotates_with_client_id_alone(
        self, client, test_tenant, test_tenant_host, public_client, test_user
    ):
        tokens = _signed_in_tokens(
            client, test_tenant_host, test_tenant, test_user, public_client["client_id"]
        )
        refresh = {
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": public_client["client_id"],
        }
        rotated = _post(client, test_tenant_host, "/oauth2/token", refresh)
        assert rotated.status_code == 200, rotated.text
        new_refresh = rotated.json()["refresh_token"]
        assert new_refresh != tokens["refresh_token"]

        # The presented refresh token stopped working; the new one works.
        replay = _post(client, test_tenant_host, "/oauth2/token", refresh)
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"
        again = _post(
            client, test_tenant_host, "/oauth2/token", refresh | {"refresh_token": new_refresh}
        )
        assert again.status_code == 200

    def test_refresh_token_bound_to_the_public_client(
        self,
        client,
        test_tenant,
        test_tenant_host,
        public_client,
        confidential_device_client,
        test_user,
    ):
        tokens = _signed_in_tokens(
            client, test_tenant_host, test_tenant, test_user, public_client["client_id"]
        )
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": confidential_device_client["client_id"],
                "client_secret": confidential_device_client["client_secret"],
            },
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_grant"

    def test_authorization_code_grant_refused(self, client, test_tenant_host, public_client):
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/token",
            {
                "grant_type": "authorization_code",
                "code": "x",
                "redirect_uri": "https://example.com/cb",
                "client_id": public_client["client_id"],
            },
        )
        assert response.status_code == 400
        assert response.json()["error"] == "unauthorized_client"

    def test_client_credentials_grant_refused(self, client, test_tenant_host, public_client):
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/token",
            {"grant_type": "client_credentials", "client_id": public_client["client_id"]},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "unauthorized_client"

    def test_authorize_endpoint_refuses_public_client(
        self, client, test_tenant_host, public_client
    ):
        response = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={
                "client_id": public_client["client_id"],
                "redirect_uri": "https://example.com/cb",
                "response_type": "code",
            },
            follow_redirects=False,
        )
        # The error page, never a redirect (a public client has no redirect URIs).
        assert response.status_code == 200
        assert "This client is not authorized for this flow." in response.text


class TestPublicClientIntrospectionAndRevocation:
    def test_cannot_introspect(
        self, client, test_tenant, test_tenant_host, public_client, test_user
    ):
        tokens = _signed_in_tokens(
            client, test_tenant_host, test_tenant, test_user, public_client["client_id"]
        )
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/introspect",
            {"token": tokens["access_token"], "client_id": public_client["client_id"]},
        )
        _assert_invalid_client(response)

    def test_revokes_its_refresh_token_with_client_id_alone(
        self, client, test_tenant, test_tenant_host, public_client, test_user
    ):
        tokens = _signed_in_tokens(
            client, test_tenant_host, test_tenant, test_user, public_client["client_id"]
        )
        revoked = _post(
            client,
            test_tenant_host,
            "/oauth2/revoke",
            {"token": tokens["refresh_token"], "client_id": public_client["client_id"]},
        )
        assert revoked.status_code == 200

        refresh = _post(
            client,
            test_tenant_host,
            "/oauth2/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": public_client["client_id"],
            },
        )
        assert refresh.json()["error"] == "invalid_grant"
        userinfo = client.get(
            "/userinfo",
            headers={
                "Host": test_tenant_host,
                "Authorization": f"Bearer {tokens['access_token']}",
            },
        )
        assert userinfo.status_code == 401

    def test_revoke_with_secret_refused(self, client, test_tenant_host, public_client):
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/revoke",
            {"token": "x", "client_id": public_client["client_id"], "client_secret": "x"},
        )
        _assert_invalid_client(response)
