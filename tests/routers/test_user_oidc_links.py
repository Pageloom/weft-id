"""Tests for linked OIDC identities on the admin user profile tab.

Covers the "Linked sign-in accounts" table, the OIDC auth-method badge, the
per-link Unlink POST, and the email-linking checkbox on the connection forms.
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def setup_app_directory():
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def super_admin_session(client, test_super_admin_user, override_auth):
    # The template context reads the session user directly, not through the
    # overridden dependency.
    override_auth(test_super_admin_user, level="super_admin")
    with patch("utils.template_context.get_current_user", return_value=test_super_admin_user):
        yield client


@pytest.fixture
def admin_session(client, test_admin_user, override_auth):
    override_auth(test_admin_user, level="admin")
    with patch("utils.template_context.get_current_user", return_value=test_admin_user):
        yield client


def _connection(test_tenant, created_by, name, **overrides):
    import database

    return database.oidc_upstream.create_connection(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name=name,
        provider_type=overrides.pop("provider_type", "generic"),
        issuer=overrides.pop("issuer", "https://idp.example.com"),
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


class TestProfileTab:
    def test_lists_linked_accounts(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, test_user
    ):
        a = _connection(
            test_tenant,
            test_super_admin_user,
            "Team Google",
            provider_type="google",
            issuer="https://accounts.google.com",
            is_enabled=True,
        )
        b = _connection(test_tenant, test_super_admin_user, "Old Generic")
        _link(test_tenant, a, test_user, "google-sub-1")
        _link(test_tenant, b, test_user, "generic-sub-2")

        response = super_admin_session.get(
            f"/users/{test_user['id']}/profile", headers={"Host": test_tenant_host}
        )
        assert response.status_code == 200
        html = response.text
        assert "Linked sign-in accounts" in html
        assert "google-sub-1" in html and "generic-sub-2" in html
        assert "Team Google" in html and "Old Generic" in html
        assert f"/users/{test_user['id']}/oidc-links/{a['id']}/unlink" in html
        assert f"/users/{test_user['id']}/oidc-links/{b['id']}/unlink" in html
        assert "OIDC (" in html  # auth-method badge
        assert "Disabled" in html  # b is disabled
        assert "Never" in html  # neither link used yet
        # Two links: neither confirm warns about deactivation.
        assert "so the account is also deactivated" not in html

    def test_last_link_confirm_warns(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, test_user
    ):
        conn = _connection(test_tenant, test_super_admin_user, "Only")
        _link(test_tenant, conn, test_user, "only-sub")

        response = super_admin_session.get(
            f"/users/{test_user['id']}/profile", headers={"Host": test_tenant_host}
        )
        assert "so the account is also deactivated" in response.text

    def test_no_links_no_section(self, super_admin_session, test_tenant_host, test_user):
        response = super_admin_session.get(
            f"/users/{test_user['id']}/profile", headers={"Host": test_tenant_host}
        )
        assert response.status_code == 200
        assert "Linked sign-in accounts" not in response.text

    def test_admin_does_not_see_links(
        self, admin_session, test_tenant_host, test_tenant, test_super_admin_user, test_user
    ):
        conn = _connection(test_tenant, test_super_admin_user, "Hidden")
        _link(test_tenant, conn, test_user, "hidden-sub")

        response = admin_session.get(
            f"/users/{test_user['id']}/profile", headers={"Host": test_tenant_host}
        )
        assert response.status_code == 200
        assert "hidden-sub" not in response.text


class TestUnlinkRoute:
    def test_unlink_redirects_with_success(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, test_user
    ):
        import database

        a = _connection(test_tenant, test_super_admin_user, "A")
        b = _connection(test_tenant, test_super_admin_user, "B")
        _link(test_tenant, a, test_user, "a-sub")
        _link(test_tenant, b, test_user, "b-sub")

        response = super_admin_session.post(
            f"/users/{test_user['id']}/oidc-links/{a['id']}/unlink",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"].endswith(
            f"/users/{test_user['id']}/profile?success=oidc_link_removed"
        )
        rows = database.oidc_upstream.list_links_for_user(test_tenant["id"], str(test_user["id"]))
        assert [str(r["idp_id"]) for r in rows] == [str(b["id"])]

    def test_success_banner(self, super_admin_session, test_tenant_host, test_user):
        response = super_admin_session.get(
            f"/users/{test_user['id']}/profile?success=oidc_link_removed",
            headers={"Host": test_tenant_host},
        )
        assert "Sign-in account unlinked." in response.text

    def test_not_linked_redirects_with_error(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user, test_user
    ):
        conn = _connection(test_tenant, test_super_admin_user, "Unlinked")
        response = super_admin_session.post(
            f"/users/{test_user['id']}/oidc-links/{conn['id']}/unlink",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"].endswith("error=oidc_user_link_not_found")

        page = super_admin_session.get(
            response.headers["location"], headers={"Host": test_tenant_host}
        )
        assert "not linked to that sign-in provider" in page.text

    def test_admin_refused(
        self, admin_session, test_tenant_host, test_tenant, test_super_admin_user, test_user
    ):
        import database

        conn = _connection(test_tenant, test_super_admin_user, "Kept")
        _link(test_tenant, conn, test_user, "kept-sub")

        response = admin_session.post(
            f"/users/{test_user['id']}/oidc-links/{conn['id']}/unlink",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"].endswith("/dashboard")
        assert database.oidc_upstream.get_link_for_user_idp(
            test_tenant["id"], str(test_user["id"]), str(conn["id"])
        )


class TestEmailLinkingCheckbox:
    def test_details_tab_disables_for_untrusted(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
    ):
        conn = _connection(
            test_tenant,
            test_super_admin_user,
            "MSA",
            provider_type="microsoft",
            issuer="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
        )
        response = super_admin_session.get(
            f"/identity-providers/oidc/{conn['id']}/details", headers={"Host": test_tenant_host}
        )
        assert response.status_code == 200
        assert 'id="email-linking-unsupported"' in response.text
        assert "Not available for Microsoft (personal accounts)" in response.text

    def test_details_tab_enabled_for_trusted(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
    ):
        conn = _connection(test_tenant, test_super_admin_user, "Generic")
        response = super_admin_session.get(
            f"/identity-providers/oidc/{conn['id']}/details", headers={"Host": test_tenant_host}
        )
        assert 'id="email-linking-unsupported"' not in response.text

    def test_settings_post_for_untrusted_succeeds(
        self, super_admin_session, test_tenant_host, test_tenant, test_super_admin_user
    ):
        """The disabled checkbox is not submitted, so saving settings still works."""
        conn = _connection(
            test_tenant,
            test_super_admin_user,
            "MSA",
            provider_type="microsoft",
            issuer="https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
        )
        response = super_admin_session.post(
            f"/identity-providers/oidc/{conn['id']}/edit-settings",
            headers={"Host": test_tenant_host},
            data={"jit_provisioning": "true"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "success=settings_updated" in response.headers["location"]

    def test_new_form_carries_trust_flag(self, super_admin_session, test_tenant_host):
        response = super_admin_session.get(
            "/identity-providers/oidc/new", headers={"Host": test_tenant_host}
        )
        assert response.status_code == 200
        assert '"email_linking_trusted": false' in response.text
        assert 'id="email-linking-unsupported"' in response.text
