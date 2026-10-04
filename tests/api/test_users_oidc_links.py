"""Tests for the per-user OIDC link API and the email-linking trust rule API."""

from unittest.mock import patch

import pytest


@pytest.fixture
def super_admin_header(test_tenant, normal_oauth2_client, test_super_admin_user):
    import database

    _, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
    )
    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
        parent_token_id=refresh_token_id,
    )
    return {"Authorization": f"Bearer {access_token}"}


def _connection(test_tenant, created_by, name, **overrides):
    import database

    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=name,
        provider_type=overrides.pop("provider_type", "generic"),
        issuer="https://idp.example.com",
        created_by=str(created_by["id"]),
        **overrides,
    )


def _link(test_tenant, connection, user, sub):
    import database

    database.oidc_upstream.create_link(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        idp_id=str(connection["id"]),
        sub=sub,
        user_id=str(user["id"]),
    )


class TestListUserOidcLinks:
    def test_lists_links(
        self,
        client,
        test_tenant,
        test_tenant_host,
        super_admin_header,
        test_super_admin_user,
        test_user,
    ):
        a = _connection(test_tenant, test_super_admin_user, "Google login", provider_type="google")
        b = _connection(test_tenant, test_super_admin_user, "Other", is_enabled=True)
        _link(test_tenant, a, test_user, "g-sub")
        _link(test_tenant, b, test_user, "o-sub")

        response = client.get(
            f"/api/v1/users/{test_user['id']}/oidc-links",
            headers={"Host": test_tenant_host, **super_admin_header},
        )
        assert response.status_code == 200
        items = response.json()["items"]
        by_id = {i["connection_id"]: i for i in items}
        assert set(by_id) == {str(a["id"]), str(b["id"])}
        google = by_id[str(a["id"])]
        assert google["connection_name"] == "Google login"
        assert google["provider_label"] == "Google"
        assert google["provider_type"] == "google"
        assert google["connection_enabled"] is False
        assert google["sub"] == "g-sub"
        assert google["last_used_at"] is None
        assert "created_at" in google

    def test_empty(self, client, test_tenant_host, super_admin_header, test_user):
        response = client.get(
            f"/api/v1/users/{test_user['id']}/oidc-links",
            headers={"Host": test_tenant_host, **super_admin_header},
        )
        assert response.status_code == 200
        assert response.json() == {"items": []}

    def test_unknown_user(self, client, test_tenant_host, super_admin_header):
        response = client.get(
            "/api/v1/users/not-a-uuid/oidc-links",
            headers={"Host": test_tenant_host, **super_admin_header},
        )
        assert response.status_code == 404

    def test_admin_forbidden(
        self, client, test_tenant_host, oauth2_admin_authorization_header, test_user
    ):
        response = client.get(
            f"/api/v1/users/{test_user['id']}/oidc-links",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        )
        assert response.status_code == 403


class TestUnlinkUserOidcLink:
    def test_unlink_one_of_two(
        self,
        client,
        test_tenant,
        test_tenant_host,
        super_admin_header,
        test_super_admin_user,
        test_user,
    ):
        import database

        a = _connection(test_tenant, test_super_admin_user, "A")
        b = _connection(test_tenant, test_super_admin_user, "B")
        _link(test_tenant, a, test_user, "a-sub")
        _link(test_tenant, b, test_user, "b-sub")

        response = client.delete(
            f"/api/v1/users/{test_user['id']}/oidc-links/{a['id']}",
            headers={"Host": test_tenant_host, **super_admin_header},
        )
        assert response.status_code == 204

        rows = database.oidc_upstream.list_links_for_user(test_tenant["id"], str(test_user["id"]))
        assert [str(r["idp_id"]) for r in rows] == [str(b["id"])]
        user = database.users.get_user_by_id(test_tenant["id"], str(test_user["id"]))
        assert user["is_inactivated"] is False

    def test_unlink_last_deactivates(
        self,
        client,
        test_tenant,
        test_tenant_host,
        super_admin_header,
        test_super_admin_user,
        test_user,
    ):
        import database

        conn = _connection(test_tenant, test_super_admin_user, "Only")
        _link(test_tenant, conn, test_user, "only-sub")

        with patch("services.oidc_upstream.links.end_user_oidc_sessions"):
            response = client.delete(
                f"/api/v1/users/{test_user['id']}/oidc-links/{conn['id']}",
                headers={"Host": test_tenant_host, **super_admin_header},
            )
        assert response.status_code == 204
        user = database.users.get_user_by_id(test_tenant["id"], str(test_user["id"]))
        assert user["is_inactivated"] is True

    def test_not_linked(
        self,
        client,
        test_tenant,
        test_tenant_host,
        super_admin_header,
        test_super_admin_user,
        test_user,
    ):
        conn = _connection(test_tenant, test_super_admin_user, "Unlinked")
        response = client.delete(
            f"/api/v1/users/{test_user['id']}/oidc-links/{conn['id']}",
            headers={"Host": test_tenant_host, **super_admin_header},
        )
        assert response.status_code == 404

    def test_admin_forbidden(
        self,
        client,
        test_tenant,
        test_tenant_host,
        oauth2_admin_authorization_header,
        test_super_admin_user,
        test_user,
    ):
        conn = _connection(test_tenant, test_super_admin_user, "X")
        _link(test_tenant, conn, test_user, "x-sub")
        response = client.delete(
            f"/api/v1/users/{test_user['id']}/oidc-links/{conn['id']}",
            headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        )
        assert response.status_code == 403


class TestEmailLinkingTrustApi:
    def test_create_microsoft_with_email_linking_rejected(
        self, client, test_tenant_host, super_admin_header
    ):
        response = client.post(
            "/api/v1/oidc-upstream/connections",
            headers={"Host": test_tenant_host, **super_admin_header},
            json={"name": "MSA", "provider_type": "microsoft", "allow_email_linking": True},
        )
        assert response.status_code == 400

    def test_update_microsoft_with_email_linking_rejected(
        self, client, test_tenant_host, super_admin_header
    ):
        created = client.post(
            "/api/v1/oidc-upstream/connections",
            headers={"Host": test_tenant_host, **super_admin_header},
            json={"name": "MSA", "provider_type": "microsoft"},
        )
        assert created.status_code == 201
        assert created.json()["email_linking_trusted"] is False

        response = client.patch(
            f"/api/v1/oidc-upstream/connections/{created.json()['id']}",
            headers={"Host": test_tenant_host, **super_admin_header},
            json={"allow_email_linking": True},
        )
        assert response.status_code == 400

    def test_trusted_provider_flag(self, client, test_tenant_host, super_admin_header):
        created = client.post(
            "/api/v1/oidc-upstream/connections",
            headers={"Host": test_tenant_host, **super_admin_header},
            json={"name": "Google", "provider_type": "google", "allow_email_linking": True},
        )
        assert created.status_code == 201
        assert created.json()["email_linking_trusted"] is True
        assert created.json()["allow_email_linking"] is True
