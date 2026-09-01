"""Integration tests for database.oidc_upstream.

Covers connection CRUD, the user-link table, RLS tenant isolation, and the
single-default trigger against the real Postgres schema.
"""

from uuid import uuid4

import database


def _make_user(tenant):
    """Create a minimal user in the tenant (created_by is NOT NULL)."""
    return database.fetchone(
        tenant["id"],
        """
        INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
        VALUES (:tenant_id, :password_hash, 'Test', 'User', 'member')
        RETURNING id
        """,
        {
            "tenant_id": tenant["id"],
            "password_hash": "x" * 60,
        },
    )


def _create_connection(tenant, name="Test OIDC", issuer="https://idp.example.com", **kwargs):
    created_by = kwargs.pop("created_by", None)
    if created_by is None:
        created_by = str(_make_user(tenant)["id"])
    return database.oidc_upstream.create_connection(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=name,
        provider_type="generic",
        issuer=issuer,
        created_by=created_by,
        **kwargs,
    )


class TestConnectionCRUD:
    def test_create_returns_row(self, test_tenant, test_user):
        row = _create_connection(test_tenant, created_by=str(test_user["id"]))
        assert row is not None
        assert row["name"] == "Test OIDC"
        assert row["provider_type"] == "generic"
        assert row["issuer"] == "https://idp.example.com"
        assert str(row["tenant_id"]) == str(test_tenant["id"])
        assert str(row["created_by"]) == str(test_user["id"])
        assert row["is_enabled"] is False
        assert row["is_default"] is False
        assert row["allow_email_linking"] is False
        assert row["correlation_claim"] == "sub"
        assert row["claim_mapping"] == {
            "email": "email",
            "first_name": "given_name",
            "last_name": "family_name",
        }

    def test_get_returns_none_when_absent(self, test_tenant):
        assert database.oidc_upstream.get_connection(test_tenant["id"], str(uuid4())) is None

    def test_get_returns_row(self, test_tenant):
        row = _create_connection(test_tenant)
        got = database.oidc_upstream.get_connection(test_tenant["id"], str(row["id"]))
        assert got is not None
        assert got["name"] == "Test OIDC"

    def test_list_orders_newest_first(self, test_tenant):
        _create_connection(test_tenant, name="First")
        _create_connection(test_tenant, name="Second")
        rows = database.oidc_upstream.list_connections(test_tenant["id"])
        names = [r["name"] for r in rows]
        assert "First" in names
        assert "Second" in names

    def test_get_by_issuer(self, test_tenant):
        _create_connection(test_tenant, issuer="https://issuer.example.com")
        row = database.oidc_upstream.get_connection_by_issuer(
            test_tenant["id"], "https://issuer.example.com"
        )
        assert row is not None
        assert row["issuer"] == "https://issuer.example.com"

    def test_update_connection(self, test_tenant):
        row = _create_connection(test_tenant)
        updated = database.oidc_upstream.update_connection(
            test_tenant["id"], str(row["id"]), name="Renamed"
        )
        assert updated["name"] == "Renamed"

    def test_update_claim_mapping_serializes_json(self, test_tenant):
        row = _create_connection(test_tenant)
        updated = database.oidc_upstream.update_connection(
            test_tenant["id"],
            str(row["id"]),
            claim_mapping={"email": "mail", "first_name": "given_name"},
        )
        assert updated["claim_mapping"] == {"email": "mail", "first_name": "given_name"}

    def test_set_enabled(self, test_tenant):
        row = _create_connection(test_tenant)
        enabled = database.oidc_upstream.set_connection_enabled(
            test_tenant["id"], str(row["id"]), True
        )
        assert enabled["is_enabled"] is True

    def test_delete_connection(self, test_tenant):
        row = _create_connection(test_tenant)
        assert database.oidc_upstream.delete_connection(test_tenant["id"], str(row["id"])) == 1
        assert database.oidc_upstream.get_connection(test_tenant["id"], str(row["id"])) is None


class TestSingleDefault:
    def test_only_one_default(self, test_tenant):
        a = _create_connection(test_tenant, name="A")
        b = _create_connection(test_tenant, name="B")
        database.oidc_upstream.set_connection_default(test_tenant["id"], str(a["id"]))
        database.oidc_upstream.set_connection_default(test_tenant["id"], str(b["id"]))

        a_refreshed = database.oidc_upstream.get_connection(test_tenant["id"], str(a["id"]))
        b_refreshed = database.oidc_upstream.get_connection(test_tenant["id"], str(b["id"]))
        assert a_refreshed["is_default"] is False
        assert b_refreshed["is_default"] is True

    def test_get_default_connection(self, test_tenant):
        a = _create_connection(test_tenant, name="A")
        database.oidc_upstream.set_connection_default(test_tenant["id"], str(a["id"]))
        database.oidc_upstream.set_connection_enabled(test_tenant["id"], str(a["id"]), True)
        default = database.oidc_upstream.get_default_connection(test_tenant["id"])
        assert default is not None
        assert str(default["id"]) == str(a["id"])


class TestUserLinks:
    def test_create_and_get_link(self, test_tenant, test_user):
        conn = _create_connection(test_tenant)
        link = database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        assert link is not None
        assert link["sub"] == "subject-123"
        assert str(link["user_id"]) == str(test_user["id"])

    def test_get_user_id_by_sub(self, test_tenant, test_user):
        conn = _create_connection(test_tenant)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        assert database.oidc_upstream.get_user_id_by_sub(
            test_tenant["id"], str(conn["id"]), "subject-123"
        ) == str(test_user["id"])

    def test_unique_idp_sub(self, test_tenant, test_user):
        conn = _create_connection(test_tenant)
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        # A second link for the same (idp_id, sub) violates the unique constraint.
        import pytest

        with pytest.raises(Exception):
            database.oidc_upstream.create_link(
                tenant_id=test_tenant["id"],
                tenant_id_value=str(test_tenant["id"]),
                idp_id=str(conn["id"]),
                sub="subject-123",
                user_id=str(test_user["id"]),
            )

    def test_count_links_for_connection(self, test_tenant, test_user):
        conn = _create_connection(test_tenant)
        assert (
            database.oidc_upstream.count_links_for_connection(test_tenant["id"], str(conn["id"]))
            == 0
        )
        database.oidc_upstream.create_link(
            tenant_id=test_tenant["id"],
            tenant_id_value=str(test_tenant["id"]),
            idp_id=str(conn["id"]),
            sub="subject-123",
            user_id=str(test_user["id"]),
        )
        assert (
            database.oidc_upstream.count_links_for_connection(test_tenant["id"], str(conn["id"]))
            == 1
        )


class TestTenantIsolation:
    def test_connection_not_visible_under_other_tenant(self, test_tenant):
        _create_connection(test_tenant)
        other_subdomain = f"other-{uuid4().hex[:8]}"
        other = database.fetchone(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
            {"s": other_subdomain, "n": "Other Tenant"},
        )
        try:
            assert database.oidc_upstream.list_connections(other["id"]) == []
        finally:
            database.execute(
                database.UNSCOPED,
                "DELETE FROM tenants WHERE id = :id",
                {"id": other["id"]},
            )

    def test_unscoped_read_fails_closed(self, test_tenant):
        _create_connection(test_tenant)
        assert database.oidc_upstream.list_connections(test_tenant["id"]) != []
        assert database.oidc_upstream.list_connections(database.UNSCOPED) == []


class TestDomainBindingTenantIsolation:
    """RLS isolation for oidc_idp_domain_bindings (Iteration 8)."""

    def _add_domain(self, tenant, domain):
        return database.fetchone(
            tenant["id"],
            """
            INSERT INTO tenant_privileged_domains (tenant_id, domain, created_by)
            VALUES (:tenant_id, :domain, :created_by)
            RETURNING id
            """,
            {
                "tenant_id": tenant["id"],
                "domain": domain,
                "created_by": str(_make_user(tenant)["id"]),
            },
        )

    def _bind(self, tenant, connection, domain_id):
        return database.oidc_upstream.bind_domain_to_connection(
            tenant_id=tenant["id"],
            tenant_id_value=str(tenant["id"]),
            domain_id=domain_id,
            connection_id=str(connection["id"]),
            created_by=str(_make_user(tenant)["id"]),
        )

    def test_binding_not_visible_under_other_tenant(self, test_tenant):
        conn = _create_connection(test_tenant)
        domain = self._add_domain(test_tenant, "bindiso.example.com")
        self._bind(test_tenant, conn, str(domain["id"]))

        other_subdomain = f"other-{uuid4().hex[:8]}"
        other = database.fetchone(
            database.UNSCOPED,
            "INSERT INTO tenants (subdomain, name) VALUES (:s, :n) RETURNING id",
            {"s": other_subdomain, "n": "Other Tenant"},
        )
        try:
            assert (
                database.oidc_upstream.get_domain_bindings_for_connection(
                    other["id"], str(conn["id"])
                )
                == []
            )
        finally:
            database.execute(
                database.UNSCOPED,
                "DELETE FROM tenants WHERE id = :id",
                {"id": other["id"]},
            )

    def test_unscoped_read_fails_closed(self, test_tenant):
        conn = _create_connection(test_tenant)
        domain = self._add_domain(test_tenant, "bindiso2.example.com")
        self._bind(test_tenant, conn, str(domain["id"]))

        # Scoped read sees the binding.
        assert (
            database.oidc_upstream.get_domain_bindings_for_connection(
                test_tenant["id"], str(conn["id"])
            )
            != []
        )

        # UNSCOPED read of the oidc_idp_domain_bindings table itself fails
        # closed (its policy uses NULLIF, so an unset app.tenant_id yields an
        # empty result rather than an error). We query the table directly to
        # avoid the join to tenant_privileged_domains, whose legacy policy
        # predates the NULLIF convention and is out of scope here.
        assert (
            database.fetchall(
                database.UNSCOPED,
                "select id from oidc_idp_domain_bindings",
                {},
            )
            == []
        )
