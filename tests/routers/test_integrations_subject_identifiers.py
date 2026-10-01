"""Web tests: the Subject Identifiers setting on the App detail page, and the
pairwise check on the App edit form (real database)."""

import database
import httpx
import pytest
from main import app
from services.oidc import subject as subject_service

from tests.helpers.client import TestClient

SECTOR = "https://sector.example/redirect_uris.json"


@pytest.fixture
def oidc_app(test_tenant, normal_oauth2_client):
    database.oauth2.update_client_oidc_settings(
        test_tenant["id"], normal_oauth2_client["client_id"], oidc_enabled=True
    )
    return normal_oauth2_client


def _post(path, data):
    return TestClient(app).post(
        path, data={**data, "csrf_token": "test-token"}, follow_redirects=False
    )


def _saved(test_tenant, client_id):
    return database.oauth2.get_client_by_client_id(test_tenant["id"], client_id)


def _serve(monkeypatch, document):
    monkeypatch.setattr(
        subject_service,
        "build_safe_client",
        lambda **_: httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=document))
        ),
    )


class TestDetailSection:
    def test_shows_public_by_default(self, test_admin_user, override_auth, oidc_app):
        override_auth(test_admin_user, level="admin")
        text = TestClient(app).get(f"/applications/oauth/{oidc_app['client_id']}").text
        assert "Subject Identifiers" in text
        assert f'action="/applications/oauth/{oidc_app["client_id"]}/subject"' in text
        assert 'value="public" checked' in text

    def test_shows_pairwise_with_sector(
        self, test_tenant, test_admin_user, override_auth, oidc_app
    ):
        database.oauth2.set_client_subject_type(
            test_tenant["id"],
            oidc_app["client_id"],
            subject_type="pairwise",
            sector_identifier_uri=SECTOR,
        )
        override_auth(test_admin_user, level="admin")
        text = TestClient(app).get(f"/applications/oauth/{oidc_app['client_id']}").text
        assert 'value="pairwise" checked' in text
        assert SECTOR in text


class TestSetSubject:
    def test_switch_to_pairwise(self, test_tenant, test_admin_user, override_auth, oidc_app):
        override_auth(test_admin_user, level="admin")
        response = _post(
            f"/applications/oauth/{oidc_app['client_id']}/subject",
            {"subject_type": "pairwise", "sector_identifier_uri": ""},
        )
        assert response.status_code == 303
        assert response.headers["location"].endswith("?success=subject_updated")
        assert _saved(test_tenant, oidc_app["client_id"])["subject_type"] == "pairwise"

    def test_sector_uri_ignored_for_public(
        self, test_tenant, test_admin_user, override_auth, oidc_app
    ):
        override_auth(test_admin_user, level="admin")
        response = _post(
            f"/applications/oauth/{oidc_app['client_id']}/subject",
            {"subject_type": "public", "sector_identifier_uri": SECTOR},
        )
        assert response.headers["location"].endswith("?success=subject_updated")
        assert _saved(test_tenant, oidc_app["client_id"])["sector_identifier_uri"] is None

    def test_bad_sector_shows_error(
        self, monkeypatch, test_tenant, test_admin_user, override_auth, oidc_app
    ):
        _serve(monkeypatch, ["https://example.com/op"])
        override_auth(test_admin_user, level="admin")
        response = _post(
            f"/applications/oauth/{oidc_app['client_id']}/subject",
            {"subject_type": "pairwise", "sector_identifier_uri": SECTOR},
        )
        assert response.headers["location"].endswith("?error=invalid_sector_identifier_uri")
        assert _saved(test_tenant, oidc_app["client_id"])["subject_type"] == "public"
        page = TestClient(app).get(response.headers["location"]).text
        assert "returns a JSON array listing every redirect URI" in page

    def test_unknown_type_shows_generic_error(self, test_admin_user, override_auth, oidc_app):
        override_auth(test_admin_user, level="admin")
        response = _post(
            f"/applications/oauth/{oidc_app['client_id']}/subject", {"subject_type": "other"}
        )
        assert response.headers["location"].endswith("?error=subject_update_failed")

    def test_member_redirected(self, test_user, override_auth, oidc_app):
        override_auth(test_user, level="user")
        response = _post(
            f"/applications/oauth/{oidc_app['client_id']}/subject", {"subject_type": "pairwise"}
        )
        assert response.status_code == 303
        assert response.headers["location"] in ("/dashboard", "/login")


class TestEditKeepsSector:
    def test_redirect_on_new_host_refused_for_pairwise_app(
        self, test_tenant, test_admin_user, override_auth, oidc_app
    ):
        database.oauth2.set_client_subject_type(
            test_tenant["id"],
            oidc_app["client_id"],
            subject_type="pairwise",
            sector_identifier_uri=None,
        )
        override_auth(test_admin_user, level="admin")
        response = _post(
            f"/applications/oauth/{oidc_app['client_id']}/edit",
            {
                "name": "Renamed",
                "redirect_uris": "http://localhost:3000/callback\nhttps://elsewhere.example/cb",
            },
        )
        assert response.headers["location"].endswith("?error=pairwise_redirect_uris")
        assert _saved(test_tenant, oidc_app["client_id"])["name"] == oidc_app["name"]

    def test_same_host_edit_allowed_for_pairwise_app(
        self, test_tenant, test_admin_user, override_auth, oidc_app
    ):
        database.oauth2.set_client_subject_type(
            test_tenant["id"],
            oidc_app["client_id"],
            subject_type="pairwise",
            sector_identifier_uri=None,
        )
        override_auth(test_admin_user, level="admin")
        response = _post(
            f"/applications/oauth/{oidc_app['client_id']}/edit",
            {"name": "Renamed", "redirect_uris": "http://localhost:3000/new"},
        )
        assert response.headers["location"].endswith("?success=updated")

    def test_public_app_may_use_any_hosts(self, test_admin_user, override_auth, oidc_app):
        override_auth(test_admin_user, level="admin")
        response = _post(
            f"/applications/oauth/{oidc_app['client_id']}/edit",
            {
                "name": "Renamed",
                "redirect_uris": "http://localhost:3000/callback\nhttps://elsewhere.example/cb",
            },
        )
        assert response.headers["location"].endswith("?success=updated")
