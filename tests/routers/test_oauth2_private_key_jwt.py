"""``private_key_jwt`` client authentication (RFC 7523, OpenID Connect Core
1.0 section 9), end to end through the real app.

A client set to ``private_key_jwt`` authenticates at the token, device
authorization, introspection, and revocation endpoints with a JWT signed by
one of its keys. The assertion must be signed by a registered key with an
allowed algorithm, name the client in ``iss`` and ``sub``, name WeftID in
``aud``, carry ``exp`` (at most an hour away) and a ``jti`` used once. The
client's secret never authenticates it, and an assertion never authenticates
a client that uses a secret.
"""

import base64
import hashlib
import hmac
import json
import time
import uuid
from unittest.mock import patch

import database
import pytest
from services import oauth2_client_auth

from tests.helpers.client_keys import (
    ASSERTION_TYPE,
    EC_KEY,
    JWKS,
    OTHER_RSA_KEY,
    RSA_KEY,
    make_assertion,
    public_jwk,
)


def _use_private_key_jwt(tenant_id, client_id, *, jwks=JWKS, jwks_uri=None, alg=None):
    updated = database.oauth2.set_client_authentication(
        tenant_id,
        client_id,
        client_auth_method="private_key_jwt",
        jwks=jwks,
        jwks_uri=jwks_uri,
        token_endpoint_auth_signing_alg=alg,
        rotate_secret=True,
    )
    assert updated is not None
    oauth2_client_auth.clear_jwks_cache(str(tenant_id), str(updated["id"]))
    return updated


@pytest.fixture
def jwt_client(test_tenant, test_admin_user):
    created = database.oauth2.create_normal_client(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Signed CLI",
        redirect_uris=["https://app.example.com/callback"],
        created_by=str(test_admin_user["id"]),
        device_grant_enabled=True,
    )
    _use_private_key_jwt(test_tenant["id"], created["client_id"])
    return created


@pytest.fixture
def issuer(test_tenant_host):
    return f"https://{test_tenant_host}"


GRANT_DEVICE = "urn:ietf:params:oauth:grant-type:device_code"


def _b64(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()


def _post(http, host, path, data, headers=None):
    return http.post(path, headers={"Host": host, **(headers or {})}, data=data)


def _device_start(http, host, assertion, **extra):
    return _post(
        http,
        host,
        "/oauth2/device_authorization",
        {
            "scope": "openid",
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion,
        }
        | extra,
    )


def _assert_invalid_client(response):
    assert response.status_code == 401, response.text
    assert response.json()["error"] == "invalid_client"


class TestAssertionAccepted:
    @pytest.mark.parametrize("aud_path", ["", "/oauth2/token", "/oauth2/device_authorization"])
    def test_accepted_audiences(self, client, test_tenant_host, issuer, jwt_client, aud_path):
        assertion = make_assertion(jwt_client["client_id"], f"{issuer}{aud_path}")
        response = _device_start(client, test_tenant_host, assertion)
        assert response.status_code == 200, response.text
        assert response.json()["device_code"]

    def test_audience_list_containing_issuer(self, client, test_tenant_host, issuer, jwt_client):
        assertion = make_assertion(jwt_client["client_id"], ["https://elsewhere.example", issuer])
        assert _device_start(client, test_tenant_host, assertion).status_code == 200

    def test_matching_client_id_field_is_accepted(
        self, client, test_tenant_host, issuer, jwt_client
    ):
        assertion = make_assertion(jwt_client["client_id"], issuer)
        response = _device_start(
            client, test_tenant_host, assertion, client_id=jwt_client["client_id"]
        )
        assert response.status_code == 200, response.text

    @pytest.mark.parametrize(
        ("key", "alg", "kid"),
        [(RSA_KEY, "PS256", "rsa-1"), (EC_KEY, "ES256", "ec-1")],
    )
    def test_other_algorithms(self, client, test_tenant_host, issuer, jwt_client, key, alg, kid):
        assertion = make_assertion(jwt_client["client_id"], issuer, key=key, alg=alg, kid=kid)
        assert _device_start(client, test_tenant_host, assertion).status_code == 200

    def test_no_kid_tries_the_keys_of_the_right_type(
        self, client, test_tenant_host, issuer, jwt_client
    ):
        assertion = make_assertion(jwt_client["client_id"], issuer, kid=None)
        assert _device_start(client, test_tenant_host, assertion).status_code == 200

    def test_introspection_and_revocation(self, client, test_tenant_host, issuer, jwt_client):
        for path in ("/oauth2/introspect", "/oauth2/revoke"):
            response = _post(
                client,
                test_tenant_host,
                path,
                {
                    "token": "unknown",
                    "client_assertion_type": ASSERTION_TYPE,
                    "client_assertion": make_assertion(jwt_client["client_id"], issuer),
                },
            )
            assert response.status_code == 200, (path, response.text)
        body = _post(
            client,
            test_tenant_host,
            "/oauth2/introspect",
            {
                "token": "unknown",
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": make_assertion(
                    jwt_client["client_id"], f"{issuer}/oauth2/introspect"
                ),
            },
        ).json()
        assert body == {"active": False}

    def test_b2b_client_credentials(
        self, client, test_tenant, test_tenant_host, issuer, b2b_oauth2_client
    ):
        _use_private_key_jwt(test_tenant["id"], b2b_oauth2_client["client_id"])
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/token",
            {
                "grant_type": "client_credentials",
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": make_assertion(
                    b2b_oauth2_client["client_id"], f"{issuer}/oauth2/token"
                ),
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["access_token"]


class TestAssertionRefused:
    def test_replayed_jti(self, client, test_tenant_host, issuer, jwt_client):
        assertion = make_assertion(jwt_client["client_id"], issuer)
        assert _device_start(client, test_tenant_host, assertion).status_code == 200
        _assert_invalid_client(_device_start(client, test_tenant_host, assertion))

    @pytest.mark.parametrize(
        "overrides",
        [
            {"exp": int(time.time()) - 600},
            {"exp": int(time.time()) + 7200},
            {"exp": None},
            {"jti": None},
            {"jti": "x" * 256},
            {"jti": 12345},
            {"aud": None},
            {"aud": "https://elsewhere.example"},
            {"sub": "someone-else"},
            {"sub": None},
            {"iss": None},
            {"nbf": int(time.time()) + 600},
            {"iat": int(time.time()) + 600},
        ],
    )
    def test_bad_claims(self, client, test_tenant_host, issuer, jwt_client, overrides):
        assertion = make_assertion(jwt_client["client_id"], issuer, **overrides)
        _assert_invalid_client(_device_start(client, test_tenant_host, assertion))

    def test_client_id_field_mismatch(
        self, client, test_tenant_host, issuer, jwt_client, b2b_oauth2_client
    ):
        assertion = make_assertion(jwt_client["client_id"], issuer)
        response = _device_start(
            client, test_tenant_host, assertion, client_id=b2b_oauth2_client["client_id"]
        )
        _assert_invalid_client(response)

    def test_unregistered_key(self, client, test_tenant_host, issuer, jwt_client):
        assertion = make_assertion(jwt_client["client_id"], issuer, key=OTHER_RSA_KEY)
        _assert_invalid_client(_device_start(client, test_tenant_host, assertion))

    def test_unknown_kid(self, client, test_tenant_host, issuer, jwt_client):
        assertion = make_assertion(jwt_client["client_id"], issuer, kid="nope")
        _assert_invalid_client(_device_start(client, test_tenant_host, assertion))

    def test_hmac_with_the_public_key_is_refused(
        self, client, test_tenant_host, issuer, jwt_client
    ):
        """Algorithm confusion: an HS256 'signature' keyed with the public JWK."""
        header = _b64({"alg": "HS256", "kid": "rsa-1"})
        body = _b64(
            {
                "iss": jwt_client["client_id"],
                "sub": jwt_client["client_id"],
                "aud": issuer,
                "exp": int(time.time()) + 60,
                "jti": uuid.uuid4().hex,
            }
        )
        secret = json.dumps(JWKS["keys"][0]).encode()
        mac = hmac.new(secret, f"{header}.{body}".encode(), hashlib.sha256).digest()
        signature = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
        _assert_invalid_client(
            _device_start(client, test_tenant_host, f"{header}.{body}.{signature}")
        )

    def test_unsigned_assertion(self, client, test_tenant_host, issuer, jwt_client):
        header = _b64({"alg": "none"})
        body = _b64(
            {
                "iss": jwt_client["client_id"],
                "sub": jwt_client["client_id"],
                "aud": issuer,
                "exp": int(time.time()) + 60,
                "jti": "x",
            }
        )
        _assert_invalid_client(_device_start(client, test_tenant_host, f"{header}.{body}."))

    def test_not_a_jwt(self, client, test_tenant_host, jwt_client):
        _assert_invalid_client(_device_start(client, test_tenant_host, "not-a-jwt"))

    def test_registered_signing_alg_is_enforced(
        self, client, test_tenant, test_tenant_host, issuer, jwt_client
    ):
        _use_private_key_jwt(test_tenant["id"], jwt_client["client_id"], alg="PS256")
        rs256 = make_assertion(jwt_client["client_id"], issuer)
        _assert_invalid_client(_device_start(client, test_tenant_host, rs256))
        ps256 = make_assertion(jwt_client["client_id"], issuer, alg="PS256")
        assert _device_start(client, test_tenant_host, ps256).status_code == 200

    def test_deactivated_client(self, client, test_tenant, test_tenant_host, issuer, jwt_client):
        database.oauth2.deactivate_client(test_tenant["id"], jwt_client["client_id"])
        assertion = make_assertion(jwt_client["client_id"], issuer)
        _assert_invalid_client(_device_start(client, test_tenant_host, assertion))

    def test_unknown_client(self, client, test_tenant_host, issuer):
        assertion = make_assertion("weft-id_client_unknown", issuer)
        _assert_invalid_client(_device_start(client, test_tenant_host, assertion))

    def test_assertion_for_a_secret_client(
        self, client, test_tenant_host, issuer, b2b_oauth2_client
    ):
        """A client that uses a secret cannot be opened with an assertion, even
        one signed by keys it holds."""
        assertion = make_assertion(b2b_oauth2_client["client_id"], issuer)
        _assert_invalid_client(_device_start(client, test_tenant_host, assertion))

    def test_assertion_at_another_tenant(self, client, jwt_client):
        """The client exists only in its own tenant: the same assertion shape
        sent to another tenant's host finds no client."""
        import settings

        other = database.fetchone(
            database.UNSCOPED,
            "insert into tenants (subdomain, name) values (:s, 'Other') returning id, subdomain",
            {"s": f"pkjwt-{uuid.uuid4().hex[:8]}"},
        )
        try:
            host = f"{other['subdomain']}.{settings.BASE_DOMAIN}"
            assertion = make_assertion(jwt_client["client_id"], f"https://{host}")
            _assert_invalid_client(_device_start(client, host, assertion))
        finally:
            database.execute(
                database.UNSCOPED, "delete from tenants where id = :id", {"id": str(other["id"])}
            )


class TestOneMethodPerRequest:
    def test_assertion_with_secret(self, client, test_tenant_host, issuer, jwt_client):
        assertion = make_assertion(jwt_client["client_id"], issuer)
        response = _device_start(client, test_tenant_host, assertion, client_secret="x")
        _assert_invalid_client(response)

    def test_assertion_with_authorization_header(
        self, client, test_tenant_host, issuer, jwt_client
    ):
        creds = base64.b64encode(f"{jwt_client['client_id']}:x".encode()).decode()
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/device_authorization",
            {
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": make_assertion(jwt_client["client_id"], issuer),
            },
            headers={"Authorization": f"Basic {creds}"},
        )
        _assert_invalid_client(response)

    @pytest.mark.parametrize(
        "fields",
        [
            {"client_assertion_type": "urn:example:other"},
            {"client_assertion_type": ASSERTION_TYPE, "client_assertion": ""},
            {"client_assertion_type": ASSERTION_TYPE},
        ],
    )
    def test_incomplete_assertion_fields(
        self, client, test_tenant_host, issuer, jwt_client, fields
    ):
        data = dict(fields)
        if data.get("client_assertion_type") == "urn:example:other":
            data["client_assertion"] = make_assertion(jwt_client["client_id"], issuer)
        response = _post(client, test_tenant_host, "/oauth2/device_authorization", data)
        _assert_invalid_client(response)

    def test_assertion_without_type(self, client, test_tenant_host, issuer, jwt_client):
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/device_authorization",
            {"client_assertion": make_assertion(jwt_client["client_id"], issuer)},
        )
        _assert_invalid_client(response)

    def test_secret_no_longer_opens_a_private_key_jwt_client(
        self, client, test_tenant, test_tenant_host, test_admin_user
    ):
        """Even when the stored hash still matches (switched without rotating),
        a private_key_jwt client is never authenticated by a secret."""
        created = database.oauth2.create_normal_client(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            name="Switched",
            redirect_uris=["https://app.example.com/callback"],
            created_by=str(test_admin_user["id"]),
            device_grant_enabled=True,
        )
        database.oauth2.set_client_authentication(
            test_tenant["id"],
            created["client_id"],
            client_auth_method="private_key_jwt",
            jwks=JWKS,
            jwks_uri=None,
            token_endpoint_auth_signing_alg=None,
            rotate_secret=False,
        )
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/device_authorization",
            {"client_id": created["client_id"], "client_secret": created["client_secret"]},
        )
        _assert_invalid_client(response)

    def test_client_id_alone_is_not_enough(self, client, test_tenant_host, jwt_client):
        response = _post(
            client,
            test_tenant_host,
            "/oauth2/device_authorization",
            {"client_id": jwt_client["client_id"]},
        )
        _assert_invalid_client(response)

    def test_overlong_assertion_is_invalid_request(self, client, test_tenant_host, jwt_client):
        response = _device_start(client, test_tenant_host, "a" * 8193)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"


class TestJwksUri:
    URI = "https://keys.example.com/jwks.json"

    def test_keys_are_fetched_and_cached(
        self, client, test_tenant, test_tenant_host, issuer, jwt_client
    ):
        _use_private_key_jwt(
            test_tenant["id"], jwt_client["client_id"], jwks=None, jwks_uri=self.URI
        )
        with patch.object(oauth2_client_auth, "_fetch_jwks", return_value=JWKS) as fetch:
            for _ in range(2):
                assertion = make_assertion(jwt_client["client_id"], issuer)
                assert _device_start(client, test_tenant_host, assertion).status_code == 200
        fetch.assert_called_once_with(self.URI)

    def test_rotated_key_triggers_one_refetch(
        self, client, test_tenant, test_tenant_host, issuer, jwt_client
    ):
        _use_private_key_jwt(
            test_tenant["id"], jwt_client["client_id"], jwks=None, jwks_uri=self.URI
        )
        rotated = {"keys": [public_jwk(OTHER_RSA_KEY, "rsa-2")]}
        with patch.object(oauth2_client_auth, "_fetch_jwks", side_effect=[JWKS, rotated]) as fetch:
            first = make_assertion(jwt_client["client_id"], issuer)
            assert _device_start(client, test_tenant_host, first).status_code == 200
            second = make_assertion(jwt_client["client_id"], issuer, key=OTHER_RSA_KEY, kid="rsa-2")
            assert _device_start(client, test_tenant_host, second).status_code == 200
        assert fetch.call_count == 2

    def test_refetch_is_rate_limited(
        self, client, test_tenant, test_tenant_host, issuer, jwt_client
    ):
        _use_private_key_jwt(
            test_tenant["id"], jwt_client["client_id"], jwks=None, jwks_uri=self.URI
        )
        with patch.object(oauth2_client_auth, "_fetch_jwks", return_value=JWKS) as fetch:
            for _ in range(3):
                bad = make_assertion(jwt_client["client_id"], issuer, key=OTHER_RSA_KEY, kid="nope")
                _assert_invalid_client(_device_start(client, test_tenant_host, bad))
        # The initial fetch plus one forced refetch; later misses wait a minute.
        assert fetch.call_count == 2

    def test_fetch_failure_refuses(self, client, test_tenant, test_tenant_host, issuer, jwt_client):
        _use_private_key_jwt(
            test_tenant["id"], jwt_client["client_id"], jwks=None, jwks_uri=self.URI
        )
        with patch.object(
            oauth2_client_auth,
            "_fetch_jwks",
            side_effect=oauth2_client_auth._AssertionRejectedError("down"),
        ):
            assertion = make_assertion(jwt_client["client_id"], issuer)
            _assert_invalid_client(_device_start(client, test_tenant_host, assertion))


class TestRegisteredClient:
    """The Dynamic OP plan's shape: register with private_key_jwt and inline
    keys, then authenticate with an assertion signed by one of them."""

    def test_register_then_authenticate(
        self, client, test_tenant, test_admin_user, test_tenant_host, issuer
    ):
        from schemas.oauth2 import RegistrationSettingsUpdate
        from services import oauth2_registration

        oauth2_registration.update_registration_settings(
            {
                "id": str(test_admin_user["id"]),
                "tenant_id": str(test_tenant["id"]),
                "role": "admin",
            },
            RegistrationSettingsUpdate(policy="open", default_access="all"),
            "https://unused.example",
        )
        registered = client.post(
            "/oauth2/register",
            headers={"Host": test_tenant_host},
            json={
                "redirect_uris": ["https://rp.example/cb"],
                "grant_types": ["authorization_code", GRANT_DEVICE],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": JWKS,
            },
        )
        assert registered.status_code == 201, registered.text
        body = registered.json()
        assert "client_secret" not in body
        assert body["token_endpoint_auth_method"] == "private_key_jwt"

        assertion = make_assertion(body["client_id"], f"{issuer}/oauth2/token")
        response = _device_start(client, test_tenant_host, assertion)
        assert response.status_code == 200, response.text
