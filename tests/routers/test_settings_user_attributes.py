"""Tests for the /admin/settings/user-attributes page route."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

ROUTERS_SETTINGS = "routers.settings"
SERVICES_SETTINGS = "services.settings"
UTILS_TEMPLATE = "utils.template_context"


def _config_row(key: str, category: str, **flags) -> dict:
    base = {
        "id": f"id-{key}",
        "tenant_id": "tenant-1",
        "attribute_key": key,
        "category": category,
        "enabled": False,
        "required": False,
        "mirror_from_idp": False,
        "locked_for_users": False,
        "send_to_sps_default": True,
        "updated_at": datetime.now(UTC),
    }
    base.update(flags)
    return base


def _make_seed(**overrides) -> list[dict]:
    """Build a list of all 14 attribute rows so the registry-shape assertion holds."""
    from constants.user_attributes import STANDARD_ATTRIBUTES

    rows = []
    for attr in STANDARD_ATTRIBUTES:
        overlay = overrides.get(attr.key, {})
        rows.append(_config_row(attr.key, attr.category, **overlay))
    return rows


def test_user_attributes_page_super_admin_renders(test_super_admin_user, override_auth, mocker):
    """Super admin can load the user attributes settings page."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{SERVICES_SETTINGS}.list_tenant_attribute_config",
        return_value=_make_seed(job_title={"enabled": True}),
    )
    mock_template = mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>user attributes</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/user-attributes")

    assert response.status_code == 200
    mock_template.assert_called_once()
    template_args = mock_template.call_args
    template_name = template_args.args[1]
    context = template_args.args[2]
    assert template_name == "settings_user_attributes.html"

    # Categories are grouped in registry order with category-level any_enabled.
    categories = context["categories"]
    assert [c["key"] for c in categories] == [
        "contact",
        "professional",
        "location",
        "profile",
    ]
    professional = next(c for c in categories if c["key"] == "professional")
    assert professional["any_enabled"] is True

    # Each category exposes its attributes with all five flags.
    contact = next(c for c in categories if c["key"] == "contact")
    sample = contact["attributes"][0]
    for field in (
        "key",
        "label",
        "category",
        "enabled",
        "required",
        "mirror_from_idp",
        "locked_for_users",
        "send_to_sps_default",
    ):
        assert field in sample


def test_user_attributes_page_admin_forbidden(test_admin_user, override_auth):
    """Plain admin (non-super) cannot load the user attributes page."""
    # Only override the lower auth dependency, so require_super_admin still blocks.
    from dependencies import (
        get_current_user,
        get_tenant_id_from_request,
        require_admin,
    )

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_admin_user["tenant_id"])
    app.dependency_overrides[get_current_user] = lambda: test_admin_user
    app.dependency_overrides[require_admin] = lambda: test_admin_user

    client = TestClient(app)
    response = client.get("/admin/settings/user-attributes", follow_redirects=False)
    assert response.status_code in (302, 303, 401, 403)


def test_user_attributes_page_unauthenticated_redirects_or_blocks(test_tenant_host):
    """Unauthenticated requests are blocked (redirected to login or 401)."""
    client = TestClient(app)
    response = client.get(
        "/admin/settings/user-attributes",
        headers={"Host": test_tenant_host},
        follow_redirects=False,
    )
    # Could be 302/303 redirect to login, or 401/403 if blocked outright.
    assert response.status_code in (302, 303, 401, 403)


def test_user_attributes_page_full_registry_present(test_super_admin_user, override_auth, mocker):
    """The grouped context must include all 14 standard attributes."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{SERVICES_SETTINGS}.list_tenant_attribute_config",
        return_value=_make_seed(),
    )
    mock_template = mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/admin/settings/user-attributes")
    assert response.status_code == 200

    context = mock_template.call_args.args[2]
    total_attrs = sum(len(c["attributes"]) for c in context["categories"])
    from constants.user_attributes import ATTRIBUTE_KEYS

    assert total_attrs == len(ATTRIBUTE_KEYS)


def test_user_attributes_registered_in_pages():
    """The user attributes page must appear in pages.py for navigation/access."""
    from pages import get_page_by_path, has_page_access

    page = get_page_by_path("/admin/settings/user-attributes")
    assert page is not None
    assert page.title == "User attributes"
    # Super admin can access; plain admin cannot.
    assert has_page_access("/admin/settings/user-attributes", "super_admin") is True
    assert has_page_access("/admin/settings/user-attributes", "admin") is False
