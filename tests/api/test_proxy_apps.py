"""Tests for the Proxy Apps REST API endpoints.

These exercise the thin API layer (auth, request/response shape, error
translation) with the service layer mocked.
"""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
from schemas.proxy_apps import (
    ProxyApp,
    ProxyAppGrant,
    ProxyAppGrantList,
    ProxyAppList,
)
from services.exceptions import ConflictError, NotFoundError, ValidationError


@pytest.fixture
def api_user():
    return {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "role": "super_admin",
        "email": "admin@test.com",
    }


@pytest.fixture
def api_host():
    import settings

    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_api_tenant(api_user):
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": api_user["tenant_id"],
            "subdomain": "test",
        }
        yield


@pytest.fixture
def pa_client(client, api_user, override_api_auth):
    override_api_auth(api_user, level="super_admin")
    return client


def _sample_app(**overrides):
    base = dict(
        id=str(uuid4()),
        protected_domain_id=str(uuid4()),
        domain="acme-corp.com",
        name="Grafana",
        external_url="https://grafana.acme-corp.com",
        description=None,
        public_paths=["/health"],
        header_config={"user": True},
        available_to_all=False,
        enabled=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        created_by_name="Test Admin",
    )
    base.update(overrides)
    return ProxyApp(**base)


def _sample_grant(group_name="Grafana Users"):
    return ProxyAppGrant(
        id=str(uuid4()),
        proxy_app_id=str(uuid4()),
        group_id=str(uuid4()),
        group_name=group_name,
        group_description=None,
        group_type="weftid",
        assigned_by=str(uuid4()),
        assigned_at=datetime.now(UTC),
    )


class TestList:
    def test_list_success(self, pa_client, api_host):
        result = ProxyAppList(items=[_sample_app()], total=1)
        with patch("services.proxy_apps.list_proxy_apps", return_value=result):
            resp = pa_client.get("/api/v1/proxy-apps", headers={"Host": api_host})
        assert resp.status_code == 200
        assert resp.json()["items"][0]["name"] == "Grafana"


class TestCreate:
    def test_create_success(self, pa_client, api_host):
        with patch("services.proxy_apps.create_proxy_app", return_value=_sample_app()):
            resp = pa_client.post(
                "/api/v1/proxy-apps",
                headers={"Host": api_host},
                json={
                    "protected_domain_id": str(uuid4()),
                    "name": "Grafana",
                    "external_url": "https://grafana.acme-corp.com",
                },
            )
        assert resp.status_code == 201
        assert resp.json()["name"] == "Grafana"

    def test_create_validation_error_returns_400(self, pa_client, api_host):
        with patch(
            "services.proxy_apps.create_proxy_app",
            side_effect=ValidationError(message="bad", code="protected_domain_not_verified"),
        ):
            resp = pa_client.post(
                "/api/v1/proxy-apps",
                headers={"Host": api_host},
                json={
                    "protected_domain_id": str(uuid4()),
                    "name": "Grafana",
                    "external_url": "https://grafana.acme-corp.com",
                },
            )
        assert resp.status_code == 400

    def test_create_missing_field_returns_422(self, pa_client, api_host):
        resp = pa_client.post(
            "/api/v1/proxy-apps",
            headers={"Host": api_host},
            json={"name": "Grafana"},
        )
        assert resp.status_code == 422


class TestGet:
    def test_get_success(self, pa_client, api_host):
        with patch("services.proxy_apps.get_proxy_app", return_value=_sample_app()):
            resp = pa_client.get(f"/api/v1/proxy-apps/{uuid4()}", headers={"Host": api_host})
        assert resp.status_code == 200

    def test_get_not_found_returns_404(self, pa_client, api_host):
        with patch(
            "services.proxy_apps.get_proxy_app",
            side_effect=NotFoundError(message="nope", code="proxy_app_not_found"),
        ):
            resp = pa_client.get(f"/api/v1/proxy-apps/{uuid4()}", headers={"Host": api_host})
        assert resp.status_code == 404


class TestUpdate:
    def test_update_success(self, pa_client, api_host):
        with patch(
            "services.proxy_apps.update_proxy_app",
            return_value=_sample_app(name="Grafana 2"),
        ):
            resp = pa_client.patch(
                f"/api/v1/proxy-apps/{uuid4()}",
                headers={"Host": api_host},
                json={"name": "Grafana 2"},
            )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Grafana 2"

    def test_update_validation_error_returns_400(self, pa_client, api_host):
        with patch(
            "services.proxy_apps.update_proxy_app",
            side_effect=ValidationError(message="bad url", code="invalid_external_url_scheme"),
        ):
            resp = pa_client.patch(
                f"/api/v1/proxy-apps/{uuid4()}",
                headers={"Host": api_host},
                json={"external_url": "http://x.acme-corp.com"},
            )
        assert resp.status_code == 400


class TestDelete:
    def test_delete_success(self, pa_client, api_host):
        with patch("services.proxy_apps.delete_proxy_app") as mock_del:
            resp = pa_client.delete(f"/api/v1/proxy-apps/{uuid4()}", headers={"Host": api_host})
        assert resp.status_code == 204
        mock_del.assert_called_once()

    def test_delete_not_found_returns_404(self, pa_client, api_host):
        with patch(
            "services.proxy_apps.delete_proxy_app",
            side_effect=NotFoundError(message="nope", code="proxy_app_not_found"),
        ):
            resp = pa_client.delete(f"/api/v1/proxy-apps/{uuid4()}", headers={"Host": api_host})
        assert resp.status_code == 404


class TestGrants:
    def test_list_grants_success(self, pa_client, api_host):
        result = ProxyAppGrantList(items=[_sample_grant()], total=1)
        with patch("services.proxy_apps.list_proxy_app_grants", return_value=result):
            resp = pa_client.get(f"/api/v1/proxy-apps/{uuid4()}/grants", headers={"Host": api_host})
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_add_grant_success(self, pa_client, api_host):
        with patch("services.proxy_apps.add_proxy_app_grant", return_value=_sample_grant()):
            resp = pa_client.post(
                f"/api/v1/proxy-apps/{uuid4()}/grants",
                headers={"Host": api_host},
                json={"group_id": str(uuid4())},
            )
        assert resp.status_code == 201
        assert resp.json()["group_name"] == "Grafana Users"

    def test_add_grant_conflict_returns_409(self, pa_client, api_host):
        with patch(
            "services.proxy_apps.add_proxy_app_grant",
            side_effect=ConflictError(message="dup", code="proxy_app_grant_exists"),
        ):
            resp = pa_client.post(
                f"/api/v1/proxy-apps/{uuid4()}/grants",
                headers={"Host": api_host},
                json={"group_id": str(uuid4())},
            )
        assert resp.status_code == 409

    def test_remove_grant_success(self, pa_client, api_host):
        with patch("services.proxy_apps.remove_proxy_app_grant") as mock_rm:
            resp = pa_client.delete(
                f"/api/v1/proxy-apps/{uuid4()}/grants/{uuid4()}", headers={"Host": api_host}
            )
        assert resp.status_code == 204
        mock_rm.assert_called_once()


class TestAuthz:
    """Every proxy-app endpoint must gate on super_admin, not plain admin.

    These override the base ``get_current_user_api`` dependency with an admin
    user, leaving the real ``require_super_admin_api`` to run and reject (403).
    The service layer is never reached, so a leak here would be a true authz bug.
    """

    @pytest.fixture
    def admin_client(self, client, api_user, api_host):
        from api_dependencies import get_current_user_api
        from dependencies import get_tenant_id_from_request
        from main import app

        admin = {**api_user, "role": "admin"}
        app.dependency_overrides[get_tenant_id_from_request] = lambda: admin["tenant_id"]
        app.dependency_overrides[get_current_user_api] = lambda: admin
        yield client
        app.dependency_overrides.clear()

    def test_list_forbidden_for_admin(self, admin_client, api_host):
        resp = admin_client.get("/api/v1/proxy-apps", headers={"Host": api_host})
        assert resp.status_code == 403

    def test_create_forbidden_for_admin(self, admin_client, api_host):
        resp = admin_client.post(
            "/api/v1/proxy-apps",
            headers={"Host": api_host},
            json={
                "protected_domain_id": str(uuid4()),
                "name": "Grafana",
                "external_url": "https://grafana.acme-corp.com",
            },
        )
        assert resp.status_code == 403

    def test_get_forbidden_for_admin(self, admin_client, api_host):
        resp = admin_client.get(f"/api/v1/proxy-apps/{uuid4()}", headers={"Host": api_host})
        assert resp.status_code == 403

    def test_update_forbidden_for_admin(self, admin_client, api_host):
        resp = admin_client.patch(
            f"/api/v1/proxy-apps/{uuid4()}",
            headers={"Host": api_host},
            json={"name": "X"},
        )
        assert resp.status_code == 403

    def test_delete_forbidden_for_admin(self, admin_client, api_host):
        resp = admin_client.delete(f"/api/v1/proxy-apps/{uuid4()}", headers={"Host": api_host})
        assert resp.status_code == 403

    def test_list_grants_forbidden_for_admin(self, admin_client, api_host):
        resp = admin_client.get(f"/api/v1/proxy-apps/{uuid4()}/grants", headers={"Host": api_host})
        assert resp.status_code == 403

    def test_add_grant_forbidden_for_admin(self, admin_client, api_host):
        resp = admin_client.post(
            f"/api/v1/proxy-apps/{uuid4()}/grants",
            headers={"Host": api_host},
            json={"group_id": str(uuid4())},
        )
        assert resp.status_code == 403

    def test_remove_grant_forbidden_for_admin(self, admin_client, api_host):
        resp = admin_client.delete(
            f"/api/v1/proxy-apps/{uuid4()}/grants/{uuid4()}", headers={"Host": api_host}
        )
        assert resp.status_code == 403
