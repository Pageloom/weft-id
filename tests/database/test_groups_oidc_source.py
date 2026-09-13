"""Integration tests for OIDC-sourced IdP groups against the real schema.

Covers the ``source="oidc"`` path through database.groups.idp, the
per-source unique-name indexes, the single-source CHECK, the FK cascade,
and the read queries that surface the connection name as ``idp_name``.
"""

from uuid import uuid4

import database
import psycopg.errors
import pytest


def _connection(tenant, user, name="Acme OIDC"):
    return database.oidc_upstream.create_connection(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        name=name,
        provider_type="generic",
        issuer=f"https://{uuid4().hex[:8]}.example.com",
        created_by=str(user["id"]),
    )


def _oidc_group(tenant, conn, name):
    row = database.groups.create_idp_group(
        tenant_id=tenant["id"],
        tenant_id_value=str(tenant["id"]),
        idp_id=str(conn["id"]),
        name=name,
        source="oidc",
    )
    assert row is not None
    return str(row["id"])


class TestSourceResolution:
    def test_unknown_source_rejected(self, test_tenant):
        with pytest.raises(ValueError, match="Unknown IdP group source"):
            database.groups.get_groups_by_idp(test_tenant["id"], str(uuid4()), source="ldap")


class TestCreateAndLookup:
    def test_create_sets_oidc_connection_id_and_idp_type(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        gid = _oidc_group(test_tenant, conn, "engineering")

        row = database.groups.get_group_by_id(test_tenant["id"], gid)
        assert row is not None
        assert row["group_type"] == "idp"
        assert row["idp_id"] is None
        assert str(row["oidc_connection_id"]) == str(conn["id"])
        assert row["idp_name"] == "Acme OIDC"

    def test_create_writes_self_lineage(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        gid = _oidc_group(test_tenant, conn, "engineering")
        row = database.fetchone(
            test_tenant["id"],
            "select depth from group_lineage where ancestor_id = :g and descendant_id = :g",
            {"g": gid},
        )
        assert row is not None and row["depth"] == 0

    def test_lookup_by_name_is_source_scoped(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        gid = _oidc_group(test_tenant, conn, "engineering")

        found = database.groups.get_group_by_idp_and_name(
            test_tenant["id"], str(conn["id"]), "engineering", "oidc"
        )
        assert found is not None and str(found["id"]) == gid
        assert str(found["oidc_connection_id"]) == str(conn["id"])

        # The SAML lookup with the same id finds nothing.
        assert (
            database.groups.get_group_by_idp_and_name(
                test_tenant["id"], str(conn["id"]), "engineering", "saml"
            )
            is None
        )

    def test_base_group_id_matches_connection_name(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user, name="Acme OIDC")
        _oidc_group(test_tenant, conn, "engineering")
        tid, cid = test_tenant["id"], str(conn["id"])
        assert database.groups.get_idp_base_group_id(tid, cid, "oidc") is None

        base = _oidc_group(test_tenant, conn, "Acme OIDC")
        assert database.groups.get_idp_base_group_id(tid, cid, "oidc") == base

    def test_get_groups_by_idp_and_delete(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        _oidc_group(test_tenant, conn, "a")
        _oidc_group(test_tenant, conn, "b")

        rows = database.groups.get_groups_by_idp(test_tenant["id"], str(conn["id"]), "oidc")
        assert [r["name"] for r in rows] == ["a", "b"]

        deleted = database.groups.delete_groups_by_idp(test_tenant["id"], str(conn["id"]), "oidc")
        assert deleted == 2
        assert database.groups.get_groups_by_idp(test_tenant["id"], str(conn["id"]), "oidc") == []

    def test_invalidate_by_source(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        gid = _oidc_group(test_tenant, conn, "a")
        tid, cid = test_tenant["id"], str(conn["id"])
        assert database.groups.invalidate_groups_by_idp(tid, cid, "oidc") == 1
        row = database.groups.get_group_by_id(test_tenant["id"], gid)
        assert row is not None and row["is_valid"] is False

    def test_user_idp_group_ids_by_source(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        gid = _oidc_group(test_tenant, conn, "a")
        weftid = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=str(test_tenant["id"]), name="manual"
        )
        uid = str(test_user["id"])
        database.groups.bulk_add_user_to_groups(
            test_tenant["id"], str(test_tenant["id"]), uid, [gid, str(weftid["id"])]
        )

        tid, cid = test_tenant["id"], str(conn["id"])
        assert database.groups.get_user_idp_group_ids(tid, uid, cid, "oidc") == [gid]
        assert database.groups.get_user_idp_group_ids(tid, uid, cid, "saml") == []


class TestConstraints:
    def test_same_name_allowed_across_connections(self, test_tenant, test_user):
        a = _connection(test_tenant, test_user, name="A")
        b = _connection(test_tenant, test_user, name="B")
        _oidc_group(test_tenant, a, "engineering")
        _oidc_group(test_tenant, b, "engineering")  # no conflict

    def test_same_name_within_connection_rejected(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        _oidc_group(test_tenant, conn, "engineering")
        with pytest.raises(psycopg.errors.UniqueViolation):
            _oidc_group(test_tenant, conn, "engineering")

    def test_weftid_group_may_share_name_with_oidc_group(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        _oidc_group(test_tenant, conn, "engineering")
        row = database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=str(test_tenant["id"]), name="engineering"
        )
        assert row is not None

    def test_weftid_names_still_unique(self, test_tenant):
        database.groups.create_group(
            tenant_id=test_tenant["id"], tenant_id_value=str(test_tenant["id"]), name="dup"
        )
        with pytest.raises(psycopg.errors.UniqueViolation):
            database.groups.create_group(
                tenant_id=test_tenant["id"], tenant_id_value=str(test_tenant["id"]), name="dup"
            )

    def test_single_source_check(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        idp = database.fetchone(
            test_tenant["id"],
            """
            insert into saml_identity_providers (
                tenant_id, name, provider_type, entity_id, sso_url,
                certificate_pem, sp_entity_id, created_by
            ) values (
                :tenant_id, 'SAML IdP', 'generic', :entity_id, 'https://idp.example.com/sso',
                'cert-placeholder', 'https://sp.example.com', :created_by
            )
            returning id
            """,
            {
                "tenant_id": str(test_tenant["id"]),
                "entity_id": f"urn:{uuid4()}",
                "created_by": str(test_user["id"]),
            },
        )
        assert idp is not None
        with pytest.raises(psycopg.errors.CheckViolation):
            database.execute(
                test_tenant["id"],
                """
                insert into groups (tenant_id, name, group_type, idp_id, oidc_connection_id)
                values (:tenant_id, 'both', 'idp', :idp_id, :conn_id)
                """,
                {
                    "tenant_id": str(test_tenant["id"]),
                    "idp_id": str(idp["id"]),
                    "conn_id": str(conn["id"]),
                },
            )

    def test_connection_delete_cascades_to_groups(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user)
        gid = _oidc_group(test_tenant, conn, "engineering")
        database.oidc_upstream.delete_connection(test_tenant["id"], str(conn["id"]))
        assert database.groups.get_group_by_id(test_tenant["id"], gid) is None


class TestReadQueriesSurfaceConnectionName:
    def test_list_groups_idp_name(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user, name="Acme OIDC")
        _oidc_group(test_tenant, conn, "engineering")
        rows = database.groups.list_groups(test_tenant["id"], search="engineering")
        assert len(rows) == 1
        assert rows[0]["idp_name"] == "Acme OIDC"
        assert str(rows[0]["oidc_connection_id"]) == str(conn["id"])

    def test_graph_marks_oidc_base_group_as_umbrella(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user, name="Acme OIDC")
        base = _oidc_group(test_tenant, conn, "Acme OIDC")
        child = _oidc_group(test_tenant, conn, "engineering")
        graph = database.groups.list_all_groups_for_graph(test_tenant["id"])
        by_id = {str(g["id"]): g for g in graph["groups"]}
        assert by_id[base]["is_umbrella"] is True
        assert by_id[child]["is_umbrella"] is False

    def test_effective_memberships_idp_name(self, test_tenant, test_user):
        conn = _connection(test_tenant, test_user, name="Acme OIDC")
        gid = _oidc_group(test_tenant, conn, "engineering")
        uid = str(test_user["id"])
        tid = test_tenant["id"]
        database.groups.bulk_add_user_to_groups(tid, str(tid), uid, [gid])
        rows = database.groups.get_effective_memberships(tid, uid)
        match = [r for r in rows if str(r["id"]) == gid]
        assert match and match[0]["idp_name"] == "Acme OIDC"
        assert str(match[0]["oidc_connection_id"]) == str(conn["id"])
