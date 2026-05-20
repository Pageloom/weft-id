"""Tests for the SCIM admin UI tab on a Service Provider."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from schemas.scim_admin import (
    ScimConfig,
    ScimCredentialList,
    ScimQueueStatus,
    ScimSyncLogList,
)
from schemas.service_providers import SPConfig

ROUTER_MODULE = "routers.saml_idp.scim_admin"


@pytest.fixture
def sp_user():
    return {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "role": "super_admin",
        "email": "admin@test.com",
        "first_name": "Admin",
        "last_name": "User",
        "tz": "UTC",
        "locale": "en_US",
    }


@pytest.fixture
def sp_admin_session(client, sp_user, override_auth):
    """Authenticate as super_admin: the SCIM tab is super_admin-only (iter 7b)."""
    override_auth(sp_user, level="super_admin")
    # The router uses `require_super_admin`; the override_auth hierarchy
    # already covers it at level="super_admin".
    yield client


@pytest.fixture
def sp_host(sp_user):
    import settings

    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_tenant_lookup(sp_user):
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": sp_user["tenant_id"],
            "subdomain": "test",
        }
        yield


@pytest.fixture
def sample_sp():
    return SPConfig(
        id=str(uuid4()),
        name="My SP",
        entity_id="urn:example",
        acs_url="https://example.com/acs",
        nameid_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        trust_established=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _scim_config(sp_id):
    return ScimConfig(
        sp_id=sp_id,
        scim_enabled=False,
        scim_target_url=None,
        scim_kind="generic",
        scim_membership_mode="effective",
        scim_log_retention="3",
    )


def _empty_credentials():
    return ScimCredentialList(items=[], total=0)


def _empty_sync_log():
    return ScimSyncLogList(items=[], total=0, page=1, page_size=50)


def _queue_status(sp_id):
    return ScimQueueStatus(sp_id=sp_id, pending=0, dead_lettered=0)


def test_scim_tab_renders(sp_admin_session, sp_host, sample_sp, mocker):
    """SCIM tab renders the right template with the right context keys."""
    mock_ctx = mocker.patch(f"{ROUTER_MODULE}.get_template_context")
    mock_tmpl = mocker.patch(f"{ROUTER_MODULE}.templates.TemplateResponse")
    mock_ctx.return_value = {"request": MagicMock()}
    mock_tmpl.return_value = HTMLResponse(content="<html>scim</html>")

    with (
        patch(
            "services.service_providers.get_service_provider",
            return_value=sample_sp,
        ),
        patch(
            "services.service_providers.count_sp_group_assignments",
            return_value=0,
        ),
        patch(
            "services.scim.admin.get_scim_config",
            return_value=_scim_config(sample_sp.id),
        ),
        patch(
            "services.scim.admin.list_credentials",
            return_value=_empty_credentials(),
        ),
        patch(
            "services.scim.admin.get_queue_status",
            return_value=_queue_status(sample_sp.id),
        ),
        patch(
            "services.scim.admin.list_sync_log",
            return_value=_empty_sync_log(),
        ),
    ):
        response = sp_admin_session.get(
            f"/admin/settings/service-providers/{sample_sp.id}/scim",
            headers={"Host": sp_host},
        )

    assert response.status_code == 200
    template_name = mock_tmpl.call_args[0][1]
    assert template_name == "saml_idp_sp_tab_scim.html"
    ctx_kwargs = mock_ctx.call_args[1]
    assert ctx_kwargs["active_tab"] == "scim"
    assert "scim_config" in ctx_kwargs
    assert "credentials" in ctx_kwargs
    assert "queue_status" in ctx_kwargs
    assert "sync_log" in ctx_kwargs


def test_scim_tab_redirects_non_super_admin(client, sp_user, override_auth, sp_host):
    """Admin (non-super) is rejected by the router-level `require_super_admin` dep.

    Iteration 7b promoted the router dep from `require_admin` to
    `require_super_admin`. The test asserts the request is redirected
    (303) and not served (200). The exact location varies between
    `/dashboard` (logged-in-but-wrong-role) and `/login` (real dep
    cannot see the test's `get_current_user` override), so we accept
    both.
    """
    admin_user = {**sp_user, "role": "admin"}
    override_auth(admin_user, level="admin")
    response = client.get(
        f"/admin/settings/service-providers/{uuid4()}/scim",
        headers={"Host": sp_host},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] in ("/dashboard", "/login")


def test_scim_tab_redirects_when_sp_missing(sp_admin_session, sp_host):
    from services.exceptions import NotFoundError

    sp_id = str(uuid4())
    with patch(
        "services.service_providers.get_service_provider",
        side_effect=NotFoundError(message="missing", code="sp_not_found"),
    ):
        response = sp_admin_session.get(
            f"/admin/settings/service-providers/{sp_id}/scim",
            headers={"Host": sp_host},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "/admin/settings/service-providers" in response.headers["location"]
