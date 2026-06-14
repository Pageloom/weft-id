"""Tests for routers/proxy_apps.py (web admin UI for forward-auth proxy apps).

These mock the service + template layers and exercise the HTTP layer: access
gating, form parsing (public paths, header checkboxes), and redirects.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

MODULE = "routers.proxy_apps"


def _app(**overrides):
    from schemas.proxy_apps import ProxyApp

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
        created_by_name="Super Admin",
    )
    base.update(overrides)
    return ProxyApp(**base)


def _domain(status="verified"):
    from schemas.protected_domains import ProtectedDomain

    return ProtectedDomain(
        id=str(uuid4()),
        domain="acme-corp.com",
        portal_host="auth.acme-corp.com",
        verification_status=status,
        verification_token=None,
        verification_record_name="_weftid-challenge.acme-corp.com",
        verification_record_value=None,
        verified_at=datetime.now(UTC),
        enabled=True,
        created_at=datetime.now(UTC),
        created_by_name="Super Admin",
    )


def _patch_render(mocker, module=MODULE):
    mock_ctx = mocker.patch(f"{module}.get_template_context")
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl = mocker.patch(f"{module}.templates.TemplateResponse")
    mock_tmpl.return_value = HTMLResponse(content="<html>ok</html>")


# -- list ----------------------------------------------------------------------


def test_list_renders(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    from schemas.protected_domains import ProtectedDomainList
    from schemas.proxy_apps import ProxyAppList

    mocker.patch(
        f"{MODULE}.proxy_apps_service.list_proxy_apps",
        return_value=ProxyAppList(items=[_app()], total=1),
    )
    mocker.patch(
        f"{MODULE}.protected_domains_service.list_protected_domains",
        return_value=ProtectedDomainList(items=[_domain()], total=1),
    )
    _patch_render(mocker)

    client = TestClient(app)
    resp = client.get("/admin/settings/proxy-apps")
    assert resp.status_code == 200


def test_list_non_super_admin_redirects(test_admin_user, override_auth):
    # has_page_access for /admin/settings/proxy-apps requires super_admin.
    override_auth(test_admin_user, level="super_admin")
    test_admin_user["role"] = "admin"

    client = TestClient(app)
    resp = client.get("/admin/settings/proxy-apps", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard"


# -- detail --------------------------------------------------------------------


def test_detail_renders(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    from schemas.proxy_apps import ProxyAppGrantList

    a = _app()
    mocker.patch(f"{MODULE}.proxy_apps_service.get_proxy_app", return_value=a)
    mocker.patch(
        f"{MODULE}.proxy_apps_service.list_proxy_app_grants",
        return_value=ProxyAppGrantList(items=[], total=0),
    )
    mocker.patch(
        f"{MODULE}.proxy_apps_service.list_available_groups_for_proxy_app",
        return_value=[],
    )
    mocker.patch(
        f"{MODULE}.protected_domains_service.get_protected_domain",
        return_value=_domain(),
    )
    _patch_render(mocker)

    client = TestClient(app)
    resp = client.get(f"/admin/settings/proxy-apps/detail/{a.id}")
    assert resp.status_code == 200


# -- add -----------------------------------------------------------------------


def test_add_parses_form_and_redirects(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    a = _app()
    mock_create = mocker.patch(f"{MODULE}.proxy_apps_service.create_proxy_app", return_value=a)

    client = TestClient(app)
    resp = client.post(
        "/admin/settings/proxy-apps/add",
        data={
            "protected_domain_id": a.protected_domain_id,
            "name": "Grafana",
            "external_url": "https://grafana.acme-corp.com",
            "public_paths": "/health\n/public/*",
            "header_user": "on",
            "available_to_all": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/admin/settings/proxy-apps/detail/{a.id}?success=created"

    sent = mock_create.call_args.args[1]
    assert sent.public_paths == ["/health", "/public/*"]
    assert sent.header_config["user"] is True
    assert sent.header_config["email"] is False
    assert sent.available_to_all is True


# -- edit ----------------------------------------------------------------------


def test_edit_redirects(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    a = _app()
    mock_update = mocker.patch(f"{MODULE}.proxy_apps_service.update_proxy_app", return_value=a)

    client = TestClient(app)
    resp = client.post(
        f"/admin/settings/proxy-apps/detail/{a.id}/edit",
        data={
            "name": "Grafana 2",
            "external_url": "https://grafana.acme-corp.com",
            "public_paths": "/healthz",
            "header_email": "on",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "success=updated" in resp.headers["location"]

    sent = mock_update.call_args.args[2]
    assert sent.name == "Grafana 2"
    assert sent.header_config["email"] is True
    assert sent.enabled is True
    assert sent.available_to_all is False


# -- delete --------------------------------------------------------------------


def test_delete_redirects(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    mock_del = mocker.patch(f"{MODULE}.proxy_apps_service.delete_proxy_app")

    client = TestClient(app)
    resp = client.post(f"/admin/settings/proxy-apps/delete/{uuid4()}", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/settings/proxy-apps?success=deleted"
    mock_del.assert_called_once()


# -- grants --------------------------------------------------------------------


def test_add_grant_redirects(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    mock_add = mocker.patch(f"{MODULE}.proxy_apps_service.add_proxy_app_grant")
    app_id = str(uuid4())
    group_id = str(uuid4())

    client = TestClient(app)
    resp = client.post(
        f"/admin/settings/proxy-apps/detail/{app_id}/grants/add",
        data={"group_id": group_id},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "success=grant_added" in resp.headers["location"]
    mock_add.assert_called_once()


def test_remove_grant_redirects(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    mock_rm = mocker.patch(f"{MODULE}.proxy_apps_service.remove_proxy_app_grant")
    app_id = str(uuid4())
    group_id = str(uuid4())

    client = TestClient(app)
    resp = client.post(
        f"/admin/settings/proxy-apps/detail/{app_id}/grants/{group_id}/remove",
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "success=grant_removed" in resp.headers["location"]
    mock_rm.assert_called_once()
