"""Router tests for the OIDC discovery endpoint.

`GET /.well-known/openid-configuration` is public, tenant-resolved by request
host, and must advertise ONLY what is implemented today. These tests lock the
spec shape, the host-scoped issuer/endpoints, cross-host isolation, and the
absence of not-yet-implemented capabilities (logout, introspection, ...).
"""

from uuid import uuid4

import database
import pytest
import settings


def _discovery(client, host):
    return client.get("/.well-known/openid-configuration", headers={"Host": host})


class TestDiscoveryDocument:
    def test_returns_all_required_fields(self, client, test_tenant_host):
        resp = _discovery(client, test_tenant_host)
        assert resp.status_code == 200
        body = resp.json()
        required = {
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
            "scopes_supported",
            "response_types_supported",
            "grant_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
            "claims_supported",
        }
        assert required <= set(body.keys())

    def test_endpoints_are_host_scoped(self, client, test_tenant_host):
        body = _discovery(client, test_tenant_host).json()
        base = f"https://{test_tenant_host}"
        assert body["issuer"] == base
        assert body["authorization_endpoint"] == f"{base}/oauth2/authorize"
        assert body["token_endpoint"] == f"{base}/oauth2/token"
        assert body["userinfo_endpoint"] == f"{base}/userinfo"
        assert body["jwks_uri"] == f"{base}/.well-known/jwks.json"

    def test_static_capability_values(self, client, test_tenant_host):
        body = _discovery(client, test_tenant_host).json()
        assert body["subject_types_supported"] == ["public"]
        assert body["id_token_signing_alg_values_supported"] == ["RS256"]
        assert body["response_types_supported"] == ["code"]
        assert set(body["grant_types_supported"]) == {
            "authorization_code",
            "refresh_token",
            "client_credentials",
        }

    def test_scopes_supported_reflects_implemented_scopes(self, client, test_tenant_host):
        """Advertises openid/profile/email; `groups` is deferred to Iteration 4."""
        body = _discovery(client, test_tenant_host).json()
        assert set(body["scopes_supported"]) == {"openid", "profile", "email"}
        assert "groups" not in body["scopes_supported"]

    def test_claims_supported_covers_envelope_and_scope_claims(self, client, test_tenant_host):
        body = _discovery(client, test_tenant_host).json()
        claims = set(body["claims_supported"])
        # Envelope claims from the ID-token minter / userinfo.
        assert {"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"} <= claims
        # profile + email scope claims from the shared assembler.
        assert {
            "name",
            "given_name",
            "family_name",
            "locale",
            "updated_at",
            "email",
            "email_verified",
        } <= claims
        # groups claim is deferred to Iteration 4.
        assert "groups" not in claims

    def test_does_not_advertise_unimplemented_capabilities(self, client, test_tenant_host):
        """Logout, introspection, revocation, device grant, DCR are out of scope."""
        body = _discovery(client, test_tenant_host).json()
        for absent in (
            "end_session_endpoint",
            "introspection_endpoint",
            "revocation_endpoint",
            "registration_endpoint",
            "device_authorization_endpoint",
            "pushed_authorization_request_endpoint",
        ):
            assert absent not in body

    def test_unknown_host_404s(self, client):
        resp = client.get(
            "/.well-known/openid-configuration",
            headers={"Host": "no-such-tenant.example.invalid"},
        )
        assert resp.status_code == 404

    def test_cross_host_isolation(self, client, test_tenant, test_tenant_host):
        """One tenant's host must never surface another tenant's issuer."""
        other_sub = f"disc-other-{uuid4().hex[:8]}"
        other = database.fetchone(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id, subdomain",
            {"s": other_sub, "n": "Other Disc"},
        )
        try:
            other_host = f"{other['subdomain']}.{settings.BASE_DOMAIN}"
            iss_a = _discovery(client, test_tenant_host).json()["issuer"]
            iss_b = _discovery(client, other_host).json()["issuer"]
            assert iss_a == f"https://{test_tenant_host}"
            assert iss_b == f"https://{other_host}"
            assert iss_a != iss_b
        finally:
            database.execute(
                database.UNSCOPED,
                "DELETE FROM tenants WHERE id = :id",
                {"id": other["id"]},
            )


@pytest.mark.parametrize("path", ["/.well-known/openid-configuration"])
def test_discovery_is_registered_public(path):
    """The discovery path is registered PUBLIC in the page authorization registry."""
    import pages

    match = next((p for p in _iter_pages(pages.PAGES) if p.path == path), None)
    assert match is not None, f"{path} not registered in pages.py"
    assert match.permission == pages.PagePermission.PUBLIC


def _iter_pages(pages_list):
    for page in pages_list:
        yield page
        yield from getattr(page, "children", None) or []
