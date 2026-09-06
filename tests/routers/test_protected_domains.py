"""Tests for routers/protected_domains.py (web admin UI for forward-auth).

These mock the service + template layers and exercise the HTTP layer: access
gating, list/detail rendering, and redirects. No router-level tests existed
for this module before the nav restructure moved it from
/admin/settings/protected-domains to /applications/forward-auth/domains --
see .claude/ITERATION_nav_restructure.md.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock
from uuid import uuid4

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

MODULE = "routers.protected_domains"


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
    return mock_tmpl


# -- list ----------------------------------------------------------------------


def test_list_renders(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    from schemas.protected_domains import ProtectedDomainList

    mocker.patch(
        f"{MODULE}.protected_domains_service.list_protected_domains",
        return_value=ProtectedDomainList(items=[_domain()], total=1),
    )
    mock_tmpl = _patch_render(mocker)

    client = TestClient(app)
    resp = client.get("/applications/forward-auth/domains")

    assert resp.status_code == 200
    assert mock_tmpl.call_args[0][1] == "protected_domains_list.html"


def test_list_non_super_admin_redirects(test_admin_user, override_auth):
    # has_page_access for /applications/forward-auth/domains requires super_admin.
    override_auth(test_admin_user, level="super_admin")

    client = TestClient(app)
    resp = client.get("/applications/forward-auth/domains", follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard"


# -- detail ----------------------------------------------------------------------


def test_detail_renders(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    domain = _domain()

    mocker.patch(
        f"{MODULE}.protected_domains_service.get_protected_domain",
        return_value=domain,
    )
    mock_tmpl = _patch_render(mocker)

    client = TestClient(app)
    resp = client.get(f"/applications/forward-auth/domains/detail/{domain.id}")

    assert resp.status_code == 200
    assert mock_tmpl.call_args[0][1] == "protected_domains_detail.html"


def test_detail_non_super_admin_redirects(test_admin_user, override_auth):
    override_auth(test_admin_user, level="super_admin")

    client = TestClient(app)
    resp = client.get(
        f"/applications/forward-auth/domains/detail/{uuid4()}", follow_redirects=False
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard"


# -- add / verify / delete -------------------------------------------------------


def test_add_domain_redirects_to_detail(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    domain = _domain(status="pending")

    mocker.patch(
        f"{MODULE}.protected_domains_service.register_protected_domain",
        return_value=domain,
    )

    client = TestClient(app)
    resp = client.post(
        "/applications/forward-auth/domains/add",
        data={
            "domain": "acme-corp.com",
            "portal_host": "auth.acme-corp.com",
            "csrf_token": "test-token",
        },
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert (
        resp.headers["location"]
        == f"/applications/forward-auth/domains/detail/{domain.id}?success=registered"
    )


def test_verify_domain_success(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    from schemas.protected_domains import ProtectedDomainVerifyResult

    domain_id = str(uuid4())
    mocker.patch(
        f"{MODULE}.protected_domains_service.verify_protected_domain",
        return_value=ProtectedDomainVerifyResult(verified=True, status="verified", message="ok"),
    )

    client = TestClient(app)
    resp = client.post(
        f"/applications/forward-auth/domains/detail/{domain_id}/verify",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert (
        resp.headers["location"]
        == f"/applications/forward-auth/domains/detail/{domain_id}?success=verified"
    )


def test_verify_domain_failure(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    from schemas.protected_domains import ProtectedDomainVerifyResult

    domain_id = str(uuid4())
    mocker.patch(
        f"{MODULE}.protected_domains_service.verify_protected_domain",
        return_value=ProtectedDomainVerifyResult(
            verified=False, status="failed", message="DNS record not found"
        ),
    )

    client = TestClient(app)
    resp = client.post(
        f"/applications/forward-auth/domains/detail/{domain_id}/verify",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert (
        resp.headers["location"]
        == f"/applications/forward-auth/domains/detail/{domain_id}?success=verify_failed"
    )


def test_delete_domain_redirects_to_list(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    mocker.patch(f"{MODULE}.protected_domains_service.delete_protected_domain")

    client = TestClient(app)
    resp = client.post(
        f"/applications/forward-auth/domains/delete/{uuid4()}",
        data={"csrf_token": "test-token"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/applications/forward-auth/domains?success=deleted"


def test_add_domain_service_error(test_super_admin_user, override_auth, mocker):
    override_auth(test_super_admin_user, level="super_admin")
    from services.exceptions import ValidationError

    mocker.patch(
        f"{MODULE}.protected_domains_service.register_protected_domain",
        side_effect=ValidationError("bad domain", code="test"),
    )
    mocker.patch(f"{MODULE}.render_error_page", return_value=HTMLResponse("err", status_code=400))

    client = TestClient(app)
    resp = client.post(
        "/applications/forward-auth/domains/add",
        data={
            "domain": "acme-corp.com",
            "portal_host": "auth.acme-corp.com",
            "csrf_token": "test-token",
        },
    )

    assert resp.status_code == 400
