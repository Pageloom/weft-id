"""Multi-tenant isolation tests for the OIDC provider surface.

These prove that the tenant-resolved OIDC endpoints (discovery, JWKS, token
issuance, userinfo) never leak another tenant's signing keys, clients, issuer,
or claims. Every assertion crosses tenant hosts: a request that arrives on
tenant A's host must never surface anything belonging to tenant B.
"""

import json
from uuid import uuid4

import database
import jwt
import pytest
import settings
from jwt.algorithms import RSAAlgorithm
from services.oidc import tokens as tokens_service

TEST_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
)


@pytest.fixture
def two_tenants():
    """Create two independent tenants (A = the shared test_tenant style, B = a
    second tenant), each with a host, an OIDC-enabled client, and a user.
    """
    tenants = {}
    for label in ("a", "b"):
        sub = f"iso-{label}-{uuid4().hex[:8]}"
        t = database.fetchone(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id, subdomain",
            {"s": sub, "n": f"Iso Tenant {label.upper()}"},
        )
        tid = t["id"]
        user = database.fetchone(
            tid,
            """
            INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
            VALUES (:tid, :ph, :fn, 'User', 'member')
            RETURNING id
            """,
            {"tid": tid, "ph": TEST_PASSWORD_HASH, "fn": f"Iso{label.upper()}"},
        )
        database.execute(
            tid,
            """
            INSERT INTO user_emails (tenant_id, user_id, email, is_primary, verified_at)
            VALUES (:tid, :uid, :email, true, now())
            """,
            {"tid": tid, "uid": user["id"], "email": f"iso-{label}@example.com"},
        )
        client = database.oauth2.create_normal_client(
            tenant_id=tid,
            tenant_id_value=str(tid),
            name=f"Iso Client {label.upper()}",
            redirect_uris=["http://localhost:3000/callback"],
            created_by=str(user["id"]),
        )
        database.execute(
            tid,
            "update oauth2_clients set oidc_enabled = true, available_to_all = true where id = :id",
            {"id": client["id"]},
        )
        tenants[label] = {
            "id": tid,
            "host": f"{sub}.{settings.BASE_DOMAIN}",
            "user": user,
            "client": client,
        }
    yield tenants
    for t in tenants.values():
        database.execute(database.UNSCOPED, "DELETE FROM tenants WHERE id = :id", {"id": t["id"]})


def _jwks(client, host):
    return client.get("/.well-known/jwks.json", headers={"Host": host}).json()


def _kids(jwks_body):
    return {k["kid"] for k in jwks_body["keys"]}


class TestDiscoveryIssuerIsolation:
    def test_issuer_never_crosses_hosts(self, client, two_tenants):
        a, b = two_tenants["a"], two_tenants["b"]
        iss_a = client.get("/.well-known/openid-configuration", headers={"Host": a["host"]}).json()[
            "issuer"
        ]
        iss_b = client.get("/.well-known/openid-configuration", headers={"Host": b["host"]}).json()[
            "issuer"
        ]
        assert iss_a == f"https://{a['host']}"
        assert iss_b == f"https://{b['host']}"
        assert iss_a != iss_b


class TestJwksKeyIsolation:
    def test_each_host_serves_its_own_disjoint_keys(self, client, two_tenants):
        a, b = two_tenants["a"], two_tenants["b"]
        kids_a = _kids(_jwks(client, a["host"]))
        kids_b = _kids(_jwks(client, b["host"]))
        assert kids_a and kids_b
        # No signing key id is ever shared across tenants.
        assert kids_a.isdisjoint(kids_b)

    def test_no_private_material_in_jwks(self, client, two_tenants):
        body = _jwks(client, two_tenants["a"]["host"])
        for key in body["keys"]:
            for private in ("d", "p", "q", "dp", "dq", "qi"):
                assert private not in key


class TestIdTokenSignatureIsolation:
    def test_token_signed_by_tenant_a_not_verifiable_under_tenant_b(self, client, two_tenants):
        a, b = two_tenants["a"], two_tenants["b"]
        issuer = f"https://{a['host']}"
        token = tokens_service.issue_id_token(
            tenant_id=str(a["id"]),
            issuer=issuer,
            client_uuid=str(a["client"]["id"]),
            client_id=a["client"]["client_id"],
            user_id=str(a["user"]["id"]),
            scopes={"openid"},
        )
        kid = jwt.get_unverified_header(token)["kid"]

        # Tenant A publishes the signing kid; tenant B never does.
        assert kid in _kids(_jwks(client, a["host"]))
        assert kid not in _kids(_jwks(client, b["host"]))

        # The key is simply absent from tenant B's JWKS -> no way to verify.
        b_jwks = _jwks(client, b["host"])
        assert all(k["kid"] != kid for k in b_jwks["keys"])

        # Sanity: it DOES verify against tenant A's published key.
        a_entry = next(k for k in _jwks(client, a["host"])["keys"] if k["kid"] == kid)
        public_key = RSAAlgorithm.from_jwk(json.dumps(a_entry))
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=a["client"]["client_id"],
            issuer=issuer,
        )
        assert decoded["iss"] == issuer


class TestUserInfoTokenIsolation:
    def test_access_token_invisible_across_hosts(self, client, two_tenants):
        a, b = two_tenants["a"], two_tenants["b"]
        token = database.oauth2.create_access_token(
            tenant_id=a["id"],
            tenant_id_value=str(a["id"]),
            client_id=a["client"]["id"],
            user_id=a["user"]["id"],
            scope="openid email",
        )

        # Valid on the owning tenant's host.
        ok = client.get(
            "/userinfo",
            headers={"Host": a["host"], "Authorization": f"Bearer {token}"},
        )
        assert ok.status_code == 200
        assert ok.json()["sub"] == str(a["user"]["id"])

        # The same token presented on tenant B's host is invisible under RLS.
        leaked = client.get(
            "/userinfo",
            headers={"Host": b["host"], "Authorization": f"Bearer {token}"},
        )
        assert leaked.status_code == 401
        body = leaked.json()
        # No tenant-A claim (sub/email) ever appears in the rejection.
        assert "sub" not in body
        assert str(a["user"]["id"]) not in json.dumps(body)


class TestClientIsolation:
    def test_client_id_not_resolvable_under_other_tenant(self, two_tenants):
        a, b = two_tenants["a"], two_tenants["b"]
        # Tenant A's client is invisible when queried under tenant B's RLS scope.
        assert database.oauth2.get_client_by_client_id(b["id"], a["client"]["client_id"]) is None
        assert (
            database.oauth2.get_client_by_client_id(a["id"], a["client"]["client_id"]) is not None
        )
