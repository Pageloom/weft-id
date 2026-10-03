"""POST /oauth2/register (RFC 7591), GET|PUT|DELETE /oauth2/register/{client_id}
(RFC 7592), registration_endpoint in discovery, and the consent page showing a
registered client's logo and links.

Driven through the assembled app (real middleware stack, real tenant host,
real database), so CSRF exemption, the bearer-token challenge, and the JSON
error format are proven as wired.
"""

import json
import time

import database
import pytest
from schemas.oauth2 import InitialAccessTokenCreate, RegistrationSettingsUpdate
from services import oauth2_registration as registration_service
from services.exceptions import RateLimitError, UnauthorizedError

METADATA = {
    "redirect_uris": ["https://rp.example/cb"],
    "client_name": "Acme",
    "logo_uri": "https://cdn.rp.example/logo.png",
    "policy_uri": "https://rp.example/privacy",
    "tos_uri": "https://rp.example/tos",
}


def _admin(test_tenant, test_admin_user):
    return {"id": str(test_admin_user["id"]), "tenant_id": str(test_tenant["id"]), "role": "admin"}


@pytest.fixture
def set_policy(test_tenant, test_admin_user):
    def _set(policy, default_access="none"):
        registration_service.update_registration_settings(
            _admin(test_tenant, test_admin_user),
            RegistrationSettingsUpdate(policy=policy, default_access=default_access),
            "https://unused.example",
        )

    return _set


def _register(client, host, body=None, token=None, **kw):
    headers = {"Host": host}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.post(
        "/oauth2/register", headers=headers, json=METADATA if body is None else body, **kw
    )


def _bearer(host, token):
    return {"Host": host, "Authorization": f"Bearer {token}"}


class TestDiscovery:
    def test_registration_endpoint_advertised_only_when_on(
        self, client, test_tenant_host, set_policy
    ):
        def discovery():
            return client.get(
                "/.well-known/openid-configuration", headers={"Host": test_tenant_host}
            ).json()

        assert "registration_endpoint" not in discovery()

        set_policy("token_required")
        body = discovery()
        assert body["registration_endpoint"] == f"{body['issuer']}/oauth2/register"

        set_policy("off")
        assert "registration_endpoint" not in discovery()


class TestRegister:
    def test_off_is_404(self, client, test_tenant_host):
        response = _register(client, test_tenant_host)
        assert response.status_code == 404

    def test_open_registration(self, client, test_tenant, test_tenant_host, set_policy):
        set_policy("open")

        response = _register(client, test_tenant_host)

        assert response.status_code == 201
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        assert body["client_name"] == "Acme"
        assert body["client_secret"]
        assert body["client_secret_expires_at"] == 0
        assert body["registration_access_token"]
        assert body["registration_client_uri"] == (
            f"https://{test_tenant_host}/oauth2/register/{body['client_id']}"
        )
        stored = database.oauth2.get_client_by_client_id(test_tenant["id"], body["client_id"])
        assert stored["dynamically_registered"] is True

    def test_no_csrf_token_needed(self, client, test_tenant_host, set_policy):
        set_policy("open")
        with client.without_csrf():
            response = _register(client, test_tenant_host)
        assert response.status_code == 201

    def test_token_required(
        self, client, test_tenant, test_tenant_host, test_admin_user, set_policy
    ):
        set_policy("token_required")
        token = registration_service.create_initial_access_token(
            _admin(test_tenant, test_admin_user), InitialAccessTokenCreate(name="Partner")
        ).token

        missing = _register(client, test_tenant_host)
        wrong = _register(client, test_tenant_host, token="weft-id_iat_wrong")
        good = _register(client, test_tenant_host, token=token)

        for response in (missing, wrong):
            assert response.status_code == 401
            assert response.json()["error"] == "invalid_token"
            assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'
        assert good.status_code == 201

    def test_overlong_bearer_is_invalid(self, client, test_tenant_host, set_policy):
        set_policy("token_required")
        response = _register(client, test_tenant_host, token="x" * 5000)
        assert response.status_code == 401

    @pytest.mark.parametrize(
        ("body", "error"),
        [
            ({"redirect_uris": ["https://rp.example/cb#f"]}, "invalid_redirect_uri"),
            ({}, "invalid_redirect_uri"),
            (
                {**METADATA, "token_endpoint_auth_method": "private_key_jwt"},
                "invalid_client_metadata",
            ),
            (["not", "an", "object"], "invalid_client_metadata"),
            # 3rd Party-Init OP, oidcc-3rd_party-init-login-nohttps.
            (
                {**METADATA, "initiate_login_uri": "http://rp.example/login"},
                "invalid_client_metadata",
            ),
        ],
    )
    def test_invalid_metadata(self, client, test_tenant_host, set_policy, body, error):
        set_policy("open")

        response = _register(client, test_tenant_host, body=body)

        assert response.status_code == 400
        assert response.json()["error"] == error
        assert response.json()["error_description"]

    def test_body_not_json(self, client, test_tenant_host, set_policy):
        set_policy("open")
        response = client.post(
            "/oauth2/register",
            headers={"Host": test_tenant_host, "Content-Type": "application/json"},
            content=b"{not json",
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_body_too_large(self, client, test_tenant_host, set_policy):
        set_policy("open")
        big = {**METADATA, "padding": "x" * 70000}
        response = client.post(
            "/oauth2/register",
            headers={"Host": test_tenant_host, "Content-Type": "application/json"},
            content=json.dumps(big).encode(),
        )
        assert response.status_code == 400
        assert "too large" in response.json()["error_description"]

    def test_rate_limited(self, client, test_tenant_host, set_policy, mocker):
        set_policy("open")
        mocker.patch(
            "routers.oauth2_registration.ratelimit.prevent",
            side_effect=RateLimitError(message="Too many", retry_after=60),
        )

        response = _register(client, test_tenant_host)

        assert response.status_code == 429
        assert response.headers["retry-after"] == "60"

    def test_rate_limit_keyed_by_tenant_and_ip(
        self, client, test_tenant, test_tenant_host, set_policy, mocker
    ):
        set_policy("open")
        prevent = mocker.patch("routers.oauth2_registration.ratelimit.prevent")

        _register(client, test_tenant_host)

        kwargs = prevent.call_args.kwargs
        assert str(kwargs["tenant_id"]) == str(test_tenant["id"])
        assert kwargs["limit"] == 100
        assert kwargs["ip"]


@pytest.fixture
def registered(client, test_tenant_host, set_policy):
    set_policy("open")
    response = _register(client, test_tenant_host)
    assert response.status_code == 201
    return response.json()


class TestClientConfigurationEndpoint:
    @pytest.mark.parametrize("method", ["get", "put", "delete"])
    def test_rate_limited_before_the_token_is_checked(
        self, client, test_tenant_host, registered, mocker, method
    ):
        mocker.patch(
            "routers.oauth2_registration.ratelimit.prevent",
            side_effect=RateLimitError(message="Too many", retry_after=30),
        )
        authenticate = mocker.patch(
            "routers.oauth2_registration.registration_service.authenticate_registration"
        )
        response = getattr(client, method)(
            f"/oauth2/register/{registered['client_id']}",
            headers=_bearer(test_tenant_host, registered["registration_access_token"]),
        )
        assert response.status_code == 429
        assert response.headers["retry-after"] == "30"
        authenticate.assert_not_called()

    def test_client_gone_during_update_is_invalid_token(
        self, client, test_tenant_host, registered, mocker
    ):
        """The client was deleted between the token check and the update."""
        mocker.patch(
            "routers.oauth2_registration.registration_service.update_client_configuration",
            side_effect=UnauthorizedError(message="The registration access token is not valid"),
        )
        response = client.put(
            f"/oauth2/register/{registered['client_id']}",
            headers={
                **_bearer(test_tenant_host, registered["registration_access_token"]),
                "Content-Type": "application/json",
            },
            content=json.dumps({**METADATA, "client_id": registered["client_id"]}).encode(),
        )
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_token"

    def test_initiate_login_uri_registered_and_read_back(
        self, client, test_tenant_host, set_policy
    ):
        """3rd Party-Init OP, oidcc-3rd_party-init-login: the registration
        response and the client configuration endpoint both return it."""
        set_policy("open")
        login_uri = "https://rp.example/initiate_login"
        response = _register(
            client, test_tenant_host, body={**METADATA, "initiate_login_uri": login_uri}
        )
        assert response.status_code == 201
        registered = response.json()
        assert registered["initiate_login_uri"] == login_uri

        read = client.get(
            f"/oauth2/register/{registered['client_id']}",
            headers=_bearer(test_tenant_host, registered["registration_access_token"]),
        )

        assert read.status_code == 200
        assert read.headers["content-type"].startswith("application/json")
        assert read.json()["initiate_login_uri"] == login_uri

    def test_read(self, client, test_tenant_host, registered):
        response = client.get(
            f"/oauth2/register/{registered['client_id']}",
            headers=_bearer(test_tenant_host, registered["registration_access_token"]),
        )

        assert response.status_code == 200
        body = response.json()
        assert body["client_id"] == registered["client_id"]
        assert body["logo_uri"] == METADATA["logo_uri"]
        assert "client_secret" not in body
        assert "registration_access_token" not in body

    def test_wrong_token_and_missing_token(self, client, test_tenant_host, registered):
        url = f"/oauth2/register/{registered['client_id']}"
        wrong = client.get(url, headers=_bearer(test_tenant_host, "weft-id_rat_wrong"))
        missing = client.get(url, headers={"Host": test_tenant_host})

        for response in (wrong, missing):
            assert response.status_code == 401
            assert response.headers["www-authenticate"].startswith("Bearer")

    def test_works_after_policy_turned_off(self, client, test_tenant_host, registered, set_policy):
        set_policy("off")
        response = client.get(
            f"/oauth2/register/{registered['client_id']}",
            headers=_bearer(test_tenant_host, registered["registration_access_token"]),
        )
        assert response.status_code == 200

    def test_update(self, client, test_tenant, test_tenant_host, registered):
        with client.without_csrf():
            response = client.put(
                f"/oauth2/register/{registered['client_id']}",
                headers=_bearer(test_tenant_host, registered["registration_access_token"]),
                json={
                    "client_id": registered["client_id"],
                    "redirect_uris": ["https://rp.example/two"],
                },
            )

        assert response.status_code == 200
        assert response.json()["redirect_uris"] == ["https://rp.example/two"]
        stored = database.oauth2.get_client_by_client_id(test_tenant["id"], registered["client_id"])
        assert stored["redirect_uris"] == ["https://rp.example/two"]
        assert stored["logo_uri"] is None
        # The token rotates: the new one reads the configuration, the old one is refused.
        new_token = response.json()["registration_access_token"]
        url = f"/oauth2/register/{registered['client_id']}"
        assert client.get(url, headers=_bearer(test_tenant_host, new_token)).status_code == 200
        old = _bearer(test_tenant_host, registered["registration_access_token"])
        assert client.get(url, headers=old).status_code == 401

    def test_update_invalid(self, client, test_tenant_host, registered):
        url = f"/oauth2/register/{registered['client_id']}"
        headers = _bearer(test_tenant_host, registered["registration_access_token"])

        mismatch = client.put(url, headers=headers, json={"client_id": "other", **METADATA})
        not_json = client.put(
            url, headers={**headers, "Content-Type": "application/json"}, content=b"nope"
        )

        assert mismatch.status_code == 400
        assert mismatch.json()["error"] == "invalid_client_metadata"
        assert not_json.status_code == 400

    def test_update_unauthenticated(self, client, test_tenant_host, registered):
        response = client.put(
            f"/oauth2/register/{registered['client_id']}",
            headers={"Host": test_tenant_host},
            json={"client_id": registered["client_id"], **METADATA},
        )
        assert response.status_code == 401

    def test_delete(self, client, test_tenant, test_tenant_host, registered):
        url = f"/oauth2/register/{registered['client_id']}"
        headers = _bearer(test_tenant_host, registered["registration_access_token"])

        with client.without_csrf():
            deleted = client.delete(url, headers=headers)
        after = client.get(url, headers=headers)

        assert deleted.status_code == 204
        assert after.status_code == 401
        assert (
            database.oauth2.get_client_by_client_id(test_tenant["id"], registered["client_id"])
            is None
        )

    def test_delete_unauthenticated(self, client, test_tenant_host, registered):
        response = client.delete(
            f"/oauth2/register/{registered['client_id']}", headers={"Host": test_tenant_host}
        )
        assert response.status_code == 401

    def test_other_tenant_cannot_reach_client(self, client, registered):
        other = database.fetchone(
            database.UNSCOPED,
            "insert into tenants (subdomain, name) values (:s, 'Other') returning id, subdomain",
            {"s": f"dcr-rt-{int(time.time() * 1000)}"},
        )
        try:
            import settings

            response = client.get(
                f"/oauth2/register/{registered['client_id']}",
                headers=_bearer(
                    f"{other['subdomain']}.{settings.BASE_DOMAIN}",
                    registered["registration_access_token"],
                ),
            )
            assert response.status_code == 401
        finally:
            database.execute(
                database.UNSCOPED, "delete from tenants where id = :id", {"id": str(other["id"])}
            )


@pytest.fixture
def session_data(mocker) -> dict:
    data: dict = {}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: data),
    )
    return data


class TestConsentPage:
    def test_shows_logo_and_links_with_csp(
        self,
        client,
        test_tenant_host,
        test_user,
        override_auth,
        session_data,
        set_policy,
    ):
        set_policy("open", default_access="all")
        registered = _register(client, test_tenant_host).json()
        override_auth(test_user)
        session_data["user_id"] = str(test_user["id"])
        session_data["session_start"] = int(time.time())

        response = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={
                "client_id": registered["client_id"],
                "redirect_uri": "https://rp.example/cb",
                "response_type": "code",
                "scope": "openid",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        assert 'id="client-logo"' in response.text
        assert 'src="https://cdn.rp.example/logo.png"' in response.text
        assert 'href="https://rp.example/privacy"' in response.text
        assert 'href="https://rp.example/tos"' in response.text
        csp = response.headers["content-security-policy"]
        assert "img-src 'self' data: https://cdn.rp.example;" in csp

    def test_no_logo_keeps_default_csp(
        self, client, test_tenant_host, test_user, override_auth, session_data, set_policy
    ):
        set_policy("open", default_access="all")
        registered = _register(
            client, test_tenant_host, body={"redirect_uris": ["https://rp.example/cb"]}
        ).json()
        override_auth(test_user)
        session_data["user_id"] = str(test_user["id"])
        session_data["session_start"] = int(time.time())

        response = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={
                "client_id": registered["client_id"],
                "redirect_uri": "https://rp.example/cb",
                "response_type": "code",
                "scope": "openid",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        assert 'id="client-logo"' not in response.text
        assert 'id="client-policy"' not in response.text
        assert "img-src 'self' data:;" in response.headers["content-security-policy"]

    def test_stored_logo_uri_cannot_add_csp_directives(
        self,
        client,
        test_tenant,
        test_tenant_host,
        test_user,
        override_auth,
        session_data,
        set_policy,
    ):
        """A row written before registration refused such URIs is harmless."""
        set_policy("open", default_access="all")
        registered = _register(
            client, test_tenant_host, body={"redirect_uris": ["https://rp.example/cb"]}
        ).json()
        database.execute(
            test_tenant["id"],
            "update oauth2_clients set logo_uri = :logo_uri where client_id = :client_id",
            {
                "logo_uri": "https://a.example; frame-ancestors *; script-src-elem *;x/logo.png",
                "client_id": registered["client_id"],
            },
        )
        override_auth(test_user)
        session_data["user_id"] = str(test_user["id"])
        session_data["session_start"] = int(time.time())

        response = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={
                "client_id": registered["client_id"],
                "redirect_uri": "https://rp.example/cb",
                "response_type": "code",
                "scope": "openid",
            },
            follow_redirects=False,
        )

        assert response.status_code == 200
        csp = response.headers["content-security-policy"]
        assert "img-src 'self' data:;" in csp
        assert "frame-ancestors 'none'" in csp
        assert "frame-ancestors *" not in csp
        assert "script-src-elem" not in csp
        assert csp.endswith("form-action 'self' https://rp.example")

    def test_default_access_none_denies(
        self, client, test_tenant_host, test_user, override_auth, session_data, set_policy
    ):
        set_policy("open")
        registered = _register(client, test_tenant_host).json()
        override_auth(test_user)
        session_data["user_id"] = str(test_user["id"])
        session_data["session_start"] = int(time.time())

        response = client.get(
            "/oauth2/authorize",
            headers={"Host": test_tenant_host},
            params={
                "client_id": registered["client_id"],
                "redirect_uri": "https://rp.example/cb",
                "response_type": "code",
                "scope": "openid",
            },
            follow_redirects=False,
        )

        assert response.status_code == 403
        assert "do not have access" in response.text


class TestPublicDeviceClientRegistration:
    def test_registered_public_client_signs_in_with_client_id_alone(
        self, client, test_tenant_host, set_policy
    ):
        set_policy("open", default_access="all")
        response = _register(
            client,
            test_tenant_host,
            {
                "client_name": "TV App",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert "client_secret" not in body
        assert body["token_endpoint_auth_method"] == "none"

        started = client.post(
            "/oauth2/device_authorization",
            headers={"Host": test_tenant_host},
            data={"client_id": body["client_id"], "scope": "openid"},
        )
        assert started.status_code == 200, started.text
