"""Tests for the Iteration 6 routing/binding surface (deferred test layer).

Covers every ``determine_auth_route`` branch involving OIDC, plus the OIDC
domain-binding CRUD and cross-protocol exclusivity.
"""

import pytest
from services.exceptions import ConflictError
from services.types import RequestingUser


@pytest.fixture
def test_idp_data():
    """Provide test SAML IdP data (mirrors tests/services/test_saml.py)."""
    return {
        "name": "Test Okta IdP",
        "provider_type": "okta",
        "entity_id": "https://idp.example.com/entity",
        "sso_url": "https://idp.example.com/sso",
        "certificate_pem": """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
ZZK9p7a2W3F8V3fVT3Z7m7bZa5W3WwJGfGQ7Pt6aQcBK9TN9bvG3a5mV6K9CQGZV
8Qm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3
F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5
Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Y
n3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
ADsT4qF3dPQ8QfQq9Y7q8f5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K
-----END CERTIFICATE-----""",
    }


def _make_requesting_user(user, tenant_id, role="super_admin"):
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role,
    )


def _make_connection(test_tenant, test_user, **overrides):
    import database

    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=overrides.pop("name", "Route OIDC"),
        provider_type="generic",
        issuer="https://idp.example.com",
        created_by=str(test_user["id"]),
        **overrides,
    )


def _add_domain(test_tenant, test_user, domain):
    from schemas.settings import PrivilegedDomainCreate
    from services import settings as settings_service

    requesting = _make_requesting_user(test_user, test_tenant["id"], "admin")
    return settings_service.add_privileged_domain(requesting, PrivilegedDomainCreate(domain=domain))


def _link(test_tenant, connection, user, sub="subject-123"):
    import database

    return database.oidc_upstream.create_link(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        idp_id=str(connection["id"]),
        sub=sub,
        user_id=str(user["id"]),
    )


class TestDetermineAuthRouteOidc:
    def test_linked_oidc_user_routes_to_idp_oidc(
        self, test_tenant, test_super_admin_user, test_user
    ):
        from services.auth_routing import determine_auth_route

        conn = _make_connection(test_tenant, test_super_admin_user, is_enabled=True)
        _link(test_tenant, conn, test_user)

        result = determine_auth_route(test_tenant["id"], test_user["email"])
        assert result.route_type == "idp_oidc"
        assert result.idp_id == str(conn["id"])
        assert result.user_id == str(test_user["id"])

    def test_linked_oidc_user_disabled_connection(
        self, test_tenant, test_super_admin_user, test_user
    ):
        from services.auth_routing import determine_auth_route

        conn = _make_connection(test_tenant, test_super_admin_user, is_enabled=False)
        _link(test_tenant, conn, test_user)

        result = determine_auth_route(test_tenant["id"], test_user["email"])
        assert result.route_type == "idp_oidc_disabled"
        assert result.user_id == str(test_user["id"])

    def test_unknown_user_domain_bound_jit_routes_to_idp_oidc_jit(
        self, test_tenant, test_super_admin_user
    ):
        from services import oidc_upstream as svc
        from services.auth_routing import determine_auth_route

        conn = _make_connection(
            test_tenant, test_super_admin_user, is_enabled=True, jit_provisioning=True
        )
        domain = _add_domain(test_tenant, test_super_admin_user, "oidcroute.example.com")
        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        svc.bind_domain_to_connection(requesting, str(conn["id"]), domain.id)

        result = determine_auth_route(test_tenant["id"], "newuser@oidcroute.example.com")
        assert result.route_type == "idp_oidc_jit"
        assert result.idp_id == str(conn["id"])

    def test_unknown_user_default_connection_jit(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc
        from services.auth_routing import determine_auth_route

        conn = _make_connection(
            test_tenant, test_super_admin_user, is_enabled=True, jit_provisioning=True
        )
        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        svc.set_connection_default(requesting, str(conn["id"]), "https://test.example.com")

        result = determine_auth_route(test_tenant["id"], "unknown@randomdomain.com")
        assert result.route_type == "idp_oidc_jit"
        assert result.idp_id == str(conn["id"])

    def test_unknown_user_domain_bound_jit_disabled_not_found(
        self, test_tenant, test_super_admin_user
    ):
        from services import oidc_upstream as svc
        from services.auth_routing import determine_auth_route

        conn = _make_connection(
            test_tenant, test_super_admin_user, is_enabled=True, jit_provisioning=False
        )
        domain = _add_domain(test_tenant, test_super_admin_user, "nojitoidc.example.com")
        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        svc.bind_domain_to_connection(requesting, str(conn["id"]), domain.id)

        result = determine_auth_route(test_tenant["id"], "newuser@nojitoidc.example.com")
        assert result.route_type == "not_found"

    def test_saml_takes_precedence_over_oidc_link(
        self, test_tenant, test_super_admin_user, test_user, test_idp_data
    ):
        """A user with both a SAML assignment and an OIDC link routes to SAML."""
        import database
        from schemas.saml import IdPCreate
        from services import saml as saml_service
        from services.auth_routing import determine_auth_route

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        idp = saml_service.create_identity_provider(
            requesting, IdPCreate(**test_idp_data, is_enabled=True), "https://test.example.com"
        )
        database.users.update_user_saml_idp(test_tenant["id"], str(test_user["id"]), idp.id)

        conn = _make_connection(test_tenant, test_super_admin_user, is_enabled=True)
        _link(test_tenant, conn, test_user)

        result = determine_auth_route(test_tenant["id"], test_user["email"])
        assert result.route_type == "idp"
        assert result.idp_id == idp.id


class TestDomainBinding:
    def test_bind_and_list(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        domain = _add_domain(test_tenant, test_super_admin_user, "bind.example.com")
        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])

        binding = svc.bind_domain_to_connection(requesting, str(conn["id"]), domain.id)
        assert binding.idp_id == str(conn["id"])

        bindings = svc.list_domain_bindings(requesting, str(conn["id"]))
        assert bindings.items[0].domain == "bind.example.com"

    def test_bind_saml_bound_domain_conflict(
        self, test_tenant, test_super_admin_user, test_idp_data
    ):
        from schemas.saml import IdPCreate
        from services import oidc_upstream as oidc_svc
        from services import saml as saml_svc

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        idp = saml_svc.create_identity_provider(
            requesting, IdPCreate(**test_idp_data, is_enabled=True), "https://test.example.com"
        )
        domain = _add_domain(test_tenant, test_super_admin_user, "conflict.example.com")
        saml_svc.bind_domain_to_idp(requesting, idp.id, domain.id)

        conn = _make_connection(test_tenant, test_super_admin_user)
        with pytest.raises(ConflictError) as exc_info:
            oidc_svc.bind_domain_to_connection(requesting, str(conn["id"]), domain.id)
        assert exc_info.value.code == "domain_bound_to_saml_idp"

    def test_unbind(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        domain = _add_domain(test_tenant, test_super_admin_user, "unbind.example.com")
        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        svc.bind_domain_to_connection(requesting, str(conn["id"]), domain.id)

        svc.unbind_domain_from_connection(requesting, domain.id)
        assert svc.list_domain_bindings(requesting, str(conn["id"])).items == []

    def test_rebind(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        conn_a = _make_connection(test_tenant, test_super_admin_user)
        conn_b = _make_connection(test_tenant, test_super_admin_user, name="Route OIDC B")
        domain = _add_domain(test_tenant, test_super_admin_user, "rebind.example.com")
        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])

        svc.bind_domain_to_connection(requesting, str(conn_a["id"]), domain.id)
        binding = svc.rebind_domain_to_connection(requesting, domain.id, str(conn_b["id"]))
        assert binding.idp_id == str(conn_b["id"])

    def test_get_unbound_domains_excludes_bound(self, test_tenant, test_super_admin_user):
        from services import oidc_upstream as svc

        conn = _make_connection(test_tenant, test_super_admin_user)
        domain = _add_domain(test_tenant, test_super_admin_user, "unboundcheck.example.com")
        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"])

        before = svc.get_unbound_domains(requesting)
        assert any(d.id == domain.id for d in before)

        svc.bind_domain_to_connection(requesting, str(conn["id"]), domain.id)
        after = svc.get_unbound_domains(requesting)
        assert not any(d.id == domain.id for d in after)
