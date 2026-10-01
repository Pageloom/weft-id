"""POST /oauth2/introspect (RFC 7662) and POST /oauth2/revoke (RFC 7009).

Driven through the assembled app (real middleware stack, real tenant host,
real database), so CSRF exemption, client authentication, and the RFC 6749
error format are proven as wired, not just in isolation.
"""

import base64

import database
import pytest


def _basic(oauth_client) -> dict[str, str]:
    raw = f"{oauth_client['client_id']}:{oauth_client['client_secret']}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode()}"}


def _tokens(test_tenant, oauth_client, user):
    refresh, refresh_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=oauth_client["id"],
        user_id=user["id"],
        scope="openid profile",
    )
    access = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=oauth_client["id"],
        user_id=user["id"],
        parent_token_id=refresh_id,
        scope="openid profile",
    )
    return refresh, access


def _introspect(client, host, oauth_client, token, **extra):
    return client.post(
        "/oauth2/introspect",
        headers={"Host": host, **_basic(oauth_client)},
        data={"token": token, **extra},
    )


def _revoke(client, host, oauth_client, token, **extra):
    return client.post(
        "/oauth2/revoke",
        headers={"Host": host, **_basic(oauth_client)},
        data={"token": token, **extra},
    )


class TestIntrospection:
    def test_active_access_token(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        response = _introspect(
            client, test_tenant_host, normal_oauth2_client, access, token_type_hint="access_token"
        )

        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        body = response.json()
        assert body["active"] is True
        assert body["scope"] == "openid profile"
        assert body["client_id"] == normal_oauth2_client["client_id"]
        assert body["sub"] == str(test_user["id"])
        assert body["token_type"] == "Bearer"
        assert body["iss"] == f"https://{test_tenant_host}"
        assert body["exp"] > body["iat"]

    def test_client_secret_post(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        refresh, _ = _tokens(test_tenant, normal_oauth2_client, test_user)

        response = client.post(
            "/oauth2/introspect",
            headers={"Host": test_tenant_host},
            data={
                "token": refresh,
                "client_id": normal_oauth2_client["client_id"],
                "client_secret": normal_oauth2_client["client_secret"],
            },
        )

        assert response.status_code == 200
        assert response.json()["active"] is True

    @pytest.mark.parametrize("hint", ["refresh_token", "access_token", "something_else"])
    def test_hint_does_not_matter(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user, hint
    ):
        refresh, _ = _tokens(test_tenant, normal_oauth2_client, test_user)

        response = _introspect(
            client, test_tenant_host, normal_oauth2_client, refresh, token_type_hint=hint
        )

        assert response.json()["active"] is True

    def test_unknown_token_inactive(self, client, test_tenant_host, normal_oauth2_client):
        response = _introspect(client, test_tenant_host, normal_oauth2_client, "unknown")

        assert response.status_code == 200
        assert response.json() == {"active": False}

    def test_other_clients_token_inactive(
        self,
        client,
        test_tenant,
        test_tenant_host,
        normal_oauth2_client,
        b2b_oauth2_client,
        test_user,
    ):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        response = _introspect(client, test_tenant_host, b2b_oauth2_client, access)

        assert response.json() == {"active": False}

    def test_resource_server_sees_other_clients_token(
        self,
        client,
        test_tenant,
        test_tenant_host,
        normal_oauth2_client,
        b2b_oauth2_client,
        test_user,
    ):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        database.oauth2.set_client_tenant_introspection(
            test_tenant["id"], b2b_oauth2_client["client_id"], True
        )

        response = _introspect(client, test_tenant_host, b2b_oauth2_client, access)

        body = response.json()
        assert body["active"] is True
        assert body["client_id"] == normal_oauth2_client["client_id"]

    def test_wrong_secret(self, client, test_tenant_host, normal_oauth2_client):
        response = _introspect(
            client,
            test_tenant_host,
            {**normal_oauth2_client, "client_secret": "wrong"},
            "anything",
        )

        assert response.status_code == 401
        assert response.headers["www-authenticate"] == 'Basic realm="oauth2"'
        assert response.json()["error"] == "invalid_client"

    def test_no_credentials(self, client, test_tenant_host):
        response = client.post(
            "/oauth2/introspect", headers={"Host": test_tenant_host}, data={"token": "x"}
        )

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_deactivated_client(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_admin_user
    ):
        database.oauth2.deactivate_client(test_tenant["id"], normal_oauth2_client["client_id"])

        response = _introspect(client, test_tenant_host, normal_oauth2_client, "x")

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_missing_token(self, client, test_tenant_host, normal_oauth2_client):
        response = client.post(
            "/oauth2/introspect",
            headers={"Host": test_tenant_host, **_basic(normal_oauth2_client)},
            data={},
        )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_over_long_token(self, client, test_tenant_host, normal_oauth2_client):
        response = _introspect(client, test_tenant_host, normal_oauth2_client, "x" * 256)

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_no_csrf_token_needed(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        with client.without_csrf():
            response = _introspect(client, test_tenant_host, normal_oauth2_client, access)

        assert response.status_code == 200
        assert response.json()["active"] is True


class TestRevocation:
    def test_revoke_access_token(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        refresh, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        response = _revoke(client, test_tenant_host, normal_oauth2_client, access)

        assert response.status_code == 200
        assert response.content == b""
        assert response.headers["cache-control"] == "no-store"
        assert _introspect(client, test_tenant_host, normal_oauth2_client, access).json() == {
            "active": False
        }
        assert (
            _introspect(client, test_tenant_host, normal_oauth2_client, refresh).json()["active"]
            is True
        )

    def test_revoked_access_token_rejected_by_api(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """The revocation is effective where tokens are used, not just at introspection."""
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        bearer = {"Host": test_tenant_host, "Authorization": f"Bearer {access}"}
        assert client.get("/api/v1/users/me", headers=bearer).status_code == 200

        _revoke(client, test_tenant_host, normal_oauth2_client, access)

        assert client.get("/api/v1/users/me", headers=bearer).status_code == 401

    def test_revoke_refresh_token_revokes_access_tokens(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        refresh, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        response = _revoke(
            client, test_tenant_host, normal_oauth2_client, refresh, token_type_hint="refresh_token"
        )

        assert response.status_code == 200
        for token in (refresh, access):
            body = _introspect(client, test_tenant_host, normal_oauth2_client, token).json()
            assert body == {"active": False}
        refreshed = client.post(
            "/oauth2/token",
            headers={"Host": test_tenant_host, **_basic(normal_oauth2_client)},
            data={"grant_type": "refresh_token", "refresh_token": refresh},
        )
        assert refreshed.status_code == 400
        assert refreshed.json()["error"] == "invalid_grant"

    def test_audited(self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        _revoke(client, test_tenant_host, normal_oauth2_client, access)

        events = [
            e
            for e in database.event_log.list_events(test_tenant["id"], limit=20)
            if e["event_type"] == "oauth2_token_revoked"
        ]
        assert len(events) == 1
        assert events[0]["metadata"]["token_type"] == "access"

    def test_unknown_token_is_200(self, client, test_tenant_host, normal_oauth2_client):
        response = _revoke(client, test_tenant_host, normal_oauth2_client, "unknown")

        assert response.status_code == 200
        assert response.content == b""

    def test_other_clients_token_untouched(
        self,
        client,
        test_tenant,
        test_tenant_host,
        normal_oauth2_client,
        b2b_oauth2_client,
        test_user,
    ):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        database.oauth2.set_client_tenant_introspection(
            test_tenant["id"], b2b_oauth2_client["client_id"], True
        )

        response = _revoke(client, test_tenant_host, b2b_oauth2_client, access)

        assert response.status_code == 200
        body = _introspect(client, test_tenant_host, normal_oauth2_client, access).json()
        assert body["active"] is True

    def test_wrong_secret(self, client, test_tenant, test_tenant_host, normal_oauth2_client):
        response = _revoke(
            client, test_tenant_host, {**normal_oauth2_client, "client_secret": "wrong"}, "x"
        )

        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"

    def test_missing_token(self, client, test_tenant_host, normal_oauth2_client):
        response = client.post(
            "/oauth2/revoke",
            headers={"Host": test_tenant_host, **_basic(normal_oauth2_client)},
            data={},
        )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_no_csrf_token_needed(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)

        with client.without_csrf():
            response = _revoke(client, test_tenant_host, normal_oauth2_client, access)

        assert response.status_code == 200
        assert database.oauth2.find_token(test_tenant["id"], access) is None


class TestCrossTenant:
    def test_token_from_another_tenant_is_invisible(
        self, client, test_tenant, test_tenant_host, normal_oauth2_client, test_user
    ):
        """A client cannot reach another tenant's tokens, even with the same secret shape."""
        _, access = _tokens(test_tenant, normal_oauth2_client, test_user)
        other = database.fetchone(
            database.UNSCOPED,
            "insert into tenants (subdomain, name) values (:s, :n) returning id, subdomain",
            {"s": f"introspect-{test_tenant_host.split('.')[0]}", "n": "Other"},
        )
        try:
            admin = database.fetchone(
                str(other["id"]),
                "insert into users (tenant_id, first_name, last_name, role) "
                "values (:t, 'O', 'A', 'admin') returning id",
                {"t": other["id"]},
            )
            other_client = database.oauth2.create_b2b_client(
                tenant_id=str(other["id"]),
                tenant_id_value=str(other["id"]),
                name="Other RS",
                role="member",
                created_by=str(admin["id"]),
            )
            database.oauth2.set_client_tenant_introspection(
                str(other["id"]), other_client["client_id"], True
            )
            other_host = test_tenant_host.replace(
                test_tenant_host.split(".")[0], other["subdomain"], 1
            )

            assert _introspect(client, other_host, other_client, access).json() == {"active": False}
            assert _revoke(client, other_host, other_client, access).status_code == 200
            assert database.oauth2.find_token(test_tenant["id"], access) is not None
            # And this tenant does not accept the other tenant's client.
            response = _introspect(client, test_tenant_host, other_client, access)
            assert response.status_code == 401
        finally:
            database.execute(
                database.UNSCOPED, "delete from tenants where id = :id", {"id": other["id"]}
            )
