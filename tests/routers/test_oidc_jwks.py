"""Router tests for the public OIDC JWKS endpoint (/.well-known/jwks.json).

Verifies the endpoint is unauthenticated, tenant-resolved, spec-shaped,
public-only, and isolates tenants (one tenant's host never yields another
tenant's keys). Runs against the real schema via lazy provisioning.
"""

import database
import jwt
import pytest
from dependencies import get_tenant_id_from_request
from jwt.algorithms import RSAAlgorithm
from main import app
from services import oidc as oidc_service


@pytest.fixture
def as_tenant(client):
    """Override host->tenant resolution to a chosen tenant id for the JWKS route."""

    def _apply(tenant_id):
        app.dependency_overrides[get_tenant_id_from_request] = lambda: str(tenant_id)
        return client

    return _apply


class TestJWKSEndpoint:
    def test_returns_spec_shaped_jwks(self, as_tenant, test_tenant):
        resp = as_tenant(test_tenant["id"]).get("/.well-known/jwks.json")
        assert resp.status_code == 200
        body = resp.json()
        assert "keys" in body and len(body["keys"]) == 1
        key = body["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert key["kid"]
        assert key["n"] and key["e"]

    def test_lazily_provisions(self, as_tenant, test_tenant):
        assert database.oidc.get_signing_key(test_tenant["id"]) is None
        resp = as_tenant(test_tenant["id"]).get("/.well-known/jwks.json")
        assert resp.status_code == 200
        assert database.oidc.get_signing_key(test_tenant["id"]) is not None

    def test_no_private_material_exposed(self, as_tenant, test_tenant):
        resp = as_tenant(test_tenant["id"]).get("/.well-known/jwks.json")
        raw = resp.text
        for leak in ('"d"', "PRIVATE", "private_key", "pem_enc"):
            assert leak not in raw

    def test_verifies_signed_token(self, as_tenant, test_tenant):
        """A token signed by the tenant's active key verifies against the served JWKS."""
        active = oidc_service.get_active_signing_key(str(test_tenant["id"]))
        token = jwt.encode(
            {"sub": "abc"},
            active.private_key_pem,
            algorithm="RS256",
            headers={"kid": active.kid},
        )
        resp = as_tenant(test_tenant["id"]).get("/.well-known/jwks.json")
        entry = next(k for k in resp.json()["keys"] if k["kid"] == active.kid)
        import json

        public_key = RSAAlgorithm.from_jwk(json.dumps(entry))
        assert jwt.decode(token, public_key, algorithms=["RS256"])["sub"] == "abc"

    def test_tenant_isolation_across_hosts(self, as_tenant, test_tenant):
        """One tenant's host must not surface another tenant's keys."""
        other_subdomain = "other-oidc-host"
        from uuid import uuid4

        other = database.fetchone(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
            {"s": f"{other_subdomain}-{uuid4().hex[:6]}", "n": "Other"},
        )
        try:
            kid_a = (
                as_tenant(test_tenant["id"]).get("/.well-known/jwks.json").json()["keys"][0]["kid"]
            )
            kid_b = as_tenant(other["id"]).get("/.well-known/jwks.json").json()["keys"][0]["kid"]
            assert kid_a != kid_b
            # Re-resolving tenant A returns A's key, never B's.
            kid_a2 = (
                as_tenant(test_tenant["id"]).get("/.well-known/jwks.json").json()["keys"][0]["kid"]
            )
            assert kid_a2 == kid_a
        finally:
            database.execute(
                database.UNSCOPED,
                "DELETE FROM tenants WHERE id = :id",
                {"id": other["id"]},
            )
