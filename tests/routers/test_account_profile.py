"""Tests for the /account/profile page rendering of standard attribute categories."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

ROUTERS_ACCOUNT = "routers.account"
SERVICES_SETTINGS = "services.settings"
SERVICES_USERS = "services.users"


def _config_row(key: str, category: str, **flags) -> dict:
    base = {
        "id": f"id-{key}",
        "tenant_id": "tenant-1",
        "attribute_key": key,
        "category": category,
        "enabled": True,
        "required": False,
        "mirror_from_idp": True,
        "locked_for_users": False,
        "send_to_sps_default": True,
        "updated_at": datetime.now(UTC),
    }
    base.update(flags)
    return base


def test_profile_page_includes_attribute_categories(test_user, override_auth, mocker):
    """The /account/profile page surfaces enabled attribute categories with values."""
    override_auth(test_user)

    mocker.patch(
        f"{SERVICES_SETTINGS}.list_tenant_attribute_config",
        return_value=[
            _config_row("job_title", "professional"),
            _config_row("phone_work", "contact", locked_for_users=True),
        ],
    )
    mocker.patch(
        f"{SERVICES_USERS}.list_user_attributes",
        return_value=[
            {"attribute_key": "job_title", "value": "Engineer", "updated_at": datetime.now(UTC)},
        ],
    )
    mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=True)

    mock_template = mocker.patch(
        f"{ROUTERS_ACCOUNT}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>profile</html>"),
    )

    client = TestClient(app)
    response = client.get("/account/profile")

    assert response.status_code == 200
    context = mock_template.call_args.args[2]

    cats = context["attribute_categories"]
    # Two enabled rows in two distinct categories.
    keys_by_cat = {c["key"]: [a["key"] for a in c["attributes"]] for c in cats}
    assert "professional" in keys_by_cat
    assert "contact" in keys_by_cat
    assert "job_title" in keys_by_cat["professional"]
    assert "phone_work" in keys_by_cat["contact"]

    # Locked flag surfaced.
    phone = next(a for c in cats for a in c["attributes"] if a["key"] == "phone_work")
    assert phone["locked"] is True
    job = next(a for c in cats for a in c["attributes"] if a["key"] == "job_title")
    assert job["locked"] is False
    assert job["value"] == "Engineer"

    assert context["can_edit_profile"] is True


def test_profile_page_can_edit_profile_false_when_disabled(test_user, override_auth, mocker):
    """can_edit_profile=False is plumbed through when the security setting is off."""
    override_auth(test_user)

    mocker.patch(
        f"{SERVICES_SETTINGS}.list_tenant_attribute_config",
        return_value=[],
    )
    mocker.patch(f"{SERVICES_USERS}.list_user_attributes", return_value=[])
    mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=False)

    mock_template = mocker.patch(
        f"{ROUTERS_ACCOUNT}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/account/profile")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["can_edit_profile"] is False
    assert context["attribute_categories"] == []


def test_update_attributes_calls_set_for_present_fields(test_user, override_auth, mocker):
    """POST /account/profile/update-attributes sets each present field via the service."""
    override_auth(test_user)

    mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=True)
    mocker.patch(
        f"{SERVICES_SETTINGS}.list_tenant_attribute_config",
        return_value=[
            _config_row("job_title", "professional"),
            _config_row("phone_work", "contact"),
            _config_row("department", "professional", enabled=False),
        ],
    )
    set_attr = mocker.patch(f"{SERVICES_USERS}.set_user_attribute")
    clear_attr = mocker.patch(f"{SERVICES_USERS}.clear_user_attribute")

    client = TestClient(app)
    response = client.post(
        "/account/profile/update-attributes",
        data={
            "csrf_token": "test-token",
            "attr_job_title": "Engineer",
            "attr_phone_work": "",
            "attr_department": "Skipped (disabled)",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=attributes_saved" in response.headers["location"]
    set_calls = [c.args[2] for c in set_attr.call_args_list]
    clear_calls = [c.args[2] for c in clear_attr.call_args_list]
    assert "job_title" in set_calls
    assert "phone_work" in clear_calls
    # Disabled attribute is silently skipped.
    assert "department" not in set_calls and "department" not in clear_calls


def test_update_attributes_skips_locked_for_member(test_user, override_auth, mocker):
    """Members never reach the service for locked-for-users attributes."""
    override_auth(test_user)

    mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=True)
    mocker.patch(
        f"{SERVICES_SETTINGS}.list_tenant_attribute_config",
        return_value=[_config_row("job_title", "professional", locked_for_users=True)],
    )
    set_attr = mocker.patch(f"{SERVICES_USERS}.set_user_attribute")
    clear_attr = mocker.patch(f"{SERVICES_USERS}.clear_user_attribute")

    client = TestClient(app)
    response = client.post(
        "/account/profile/update-attributes",
        data={"csrf_token": "test-token", "attr_job_title": "Engineer"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    set_attr.assert_not_called()
    clear_attr.assert_not_called()


def test_update_attributes_blocked_when_profile_editing_disabled(test_user, override_auth, mocker):
    """Members hit a redirect when allow_users_edit_profile=false."""
    override_auth(test_user)

    mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=False)
    list_cfg = mocker.patch(f"{SERVICES_SETTINGS}.list_tenant_attribute_config")
    set_attr = mocker.patch(f"{SERVICES_USERS}.set_user_attribute")

    client = TestClient(app)
    response = client.post(
        "/account/profile/update-attributes",
        data={"csrf_token": "test-token", "attr_job_title": "Engineer"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/account/profile"
    list_cfg.assert_not_called()
    set_attr.assert_not_called()


def test_profile_page_super_admin_always_can_edit(test_super_admin_user, override_auth, mocker):
    """Super admins bypass the can_user_edit_profile setting."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{SERVICES_SETTINGS}.list_tenant_attribute_config",
        return_value=[],
    )
    mocker.patch(f"{SERVICES_USERS}.list_user_attributes", return_value=[])
    can_edit = mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=False)

    mock_template = mocker.patch(
        f"{ROUTERS_ACCOUNT}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/account/profile")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    # Super admin: skip the security gate.
    assert context["can_edit_profile"] is True
    # The setting helper may or may not be called; the truthy result is what matters.
    _ = can_edit
