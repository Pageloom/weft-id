"""Admin web UI for the per-client tenant token introspection permission
(/applications/oauth/{id}/introspection, /applications/service-accounts/{id}/introspection).
Real database; auth via override_auth."""

import database
from main import app

from tests.helpers.client import TestClient


def _flag(test_tenant, oauth_client) -> bool:
    row = database.oauth2.get_client_by_client_id(test_tenant["id"], oauth_client["client_id"])
    return row["can_introspect_tenant_tokens"]


class TestAppIntrospectionToggle:
    def test_admin_allows_and_limits(
        self, test_tenant, test_admin_user, override_auth, normal_oauth2_client
    ):
        override_auth(test_admin_user, level="admin")
        client = TestClient(app)
        url = f"/applications/oauth/{normal_oauth2_client['client_id']}/introspection"

        response = client.post(url, data={"enabled": "true"}, follow_redirects=False)

        assert response.status_code == 303
        assert response.headers["location"].endswith("?success=introspection_updated")
        assert _flag(test_tenant, normal_oauth2_client) is True

        client.post(url, data={"enabled": "false"}, follow_redirects=False)
        assert _flag(test_tenant, normal_oauth2_client) is False

    def test_member_redirected(self, test_tenant, test_user, override_auth, normal_oauth2_client):
        # level="admin" gets past the router dependency to the page-access check
        override_auth(test_user, level="admin")
        client = TestClient(app)

        response = client.post(
            f"/applications/oauth/{normal_oauth2_client['client_id']}/introspection",
            data={"enabled": "true"},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/dashboard"
        assert _flag(test_tenant, normal_oauth2_client) is False

    def test_unknown_client(self, test_admin_user, override_auth):
        override_auth(test_admin_user, level="admin")
        client = TestClient(app)

        response = client.post(
            "/applications/oauth/nope/introspection",
            data={"enabled": "true"},
            follow_redirects=False,
        )

        assert response.headers["location"].endswith("?error=introspection_update_failed")

    def test_detail_page_shows_card_and_endpoints(
        self, test_admin_user, override_auth, normal_oauth2_client
    ):
        override_auth(test_admin_user, level="admin")
        client = TestClient(app)
        database.oauth2.update_client_oidc_settings(
            test_admin_user["tenant_id"], normal_oauth2_client["client_id"], oidc_enabled=True
        )

        page = client.get(f"/applications/oauth/{normal_oauth2_client['client_id']}").text

        assert "Token Introspection" in page
        assert "Allow all tokens" in page
        assert "/oauth2/introspect</code>" in page
        assert "/oauth2/revoke</code>" in page


class TestB2BIntrospectionToggle:
    def test_super_admin_allows(
        self, test_tenant, test_super_admin_user, override_auth, b2b_oauth2_client
    ):
        override_auth(test_super_admin_user, level="super_admin")
        client = TestClient(app)

        response = client.post(
            f"/applications/service-accounts/{b2b_oauth2_client['client_id']}/introspection",
            data={"enabled": "true"},
            follow_redirects=False,
        )

        assert response.headers["location"].endswith("?success=introspection_updated")
        assert _flag(test_tenant, b2b_oauth2_client) is True
        page = client.get(f"/applications/service-accounts/{b2b_oauth2_client['client_id']}").text
        assert "Limit to own tokens" in page
        assert "/oauth2/introspect</code>" in page

    def test_admin_redirected(self, test_tenant, test_admin_user, override_auth, b2b_oauth2_client):
        override_auth(test_admin_user, level="admin")
        client = TestClient(app)

        response = client.post(
            f"/applications/service-accounts/{b2b_oauth2_client['client_id']}/introspection",
            data={"enabled": "true"},
            follow_redirects=False,
        )

        assert response.headers["location"] == "/dashboard"
        assert _flag(test_tenant, b2b_oauth2_client) is False

    def test_admin_cannot_reach_b2b_through_app_route(
        self, test_tenant, test_admin_user, override_auth, b2b_oauth2_client
    ):
        """The service enforces super_admin for B2B, whichever page posts."""
        override_auth(test_admin_user, level="admin")
        client = TestClient(app)

        response = client.post(
            f"/applications/oauth/{b2b_oauth2_client['client_id']}/introspection",
            data={"enabled": "true"},
            follow_redirects=False,
        )

        assert response.headers["location"].endswith("?error=introspection_update_failed")
        assert _flag(test_tenant, b2b_oauth2_client) is False
