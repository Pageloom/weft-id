"""Tests for the /users/{id}/profile admin tab rendering attribute panels."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app
from schemas.api import UserDetail

USERS_DETAIL = "routers.users.detail"
SERVICES_USERS = "services.users"
SERVICES_SETTINGS = "services.settings"
DATABASE_SETTINGS = "database.settings"


def _target_user_detail() -> UserDetail:
    return UserDetail(
        id="user-123",
        email="target@example.com",
        first_name="Target",
        last_name="User",
        role="member",
        timezone=None,
        locale=None,
        mfa_enabled=False,
        mfa_method=None,
        created_at=datetime.now(UTC),
        last_login=None,
        emails=[],
        is_service_user=False,
    )


def _patch_common(mocker):
    """Patch the shared dependencies of the user detail tab."""
    mocker.patch(f"{SERVICES_USERS}.get_user", return_value=_target_user_detail())
    mocker.patch(f"{DATABASE_SETTINGS}.list_privileged_domains", return_value=[])
    from schemas.groups import EffectiveMembershipList

    mocker.patch(
        f"{USERS_DETAIL}.groups_service.get_effective_memberships",
        return_value=EffectiveMembershipList(items=[]),
    )
    mock_sp = mocker.patch(f"{USERS_DETAIL}.sp_service")
    mock_sp.get_user_accessible_apps_admin.return_value = type("R", (), {"total": 0, "items": []})()
    mocker.patch(f"{USERS_DETAIL}.webauthn_service.admin_list_credentials", return_value=[])


def test_user_detail_profile_passes_attribute_categories(test_admin_user, mocker, override_auth):
    """Admin profile tab passes attribute_categories built from the helper."""
    override_auth(test_admin_user, level="admin")
    _patch_common(mocker)

    fake_groups = [
        {
            "key": "professional",
            "label": "Professional",
            "attributes": [
                {
                    "key": "job_title",
                    "label": "Job title",
                    "category": "professional",
                    "value_type": "string",
                    "max_length": 255,
                    "value": "Engineer",
                    "required": False,
                    "locked": True,
                    "mirror_from_idp": True,
                },
            ],
        },
    ]
    mocker.patch(
        f"{USERS_DETAIL}.build_attribute_groups_for_admin",
        return_value=fake_groups,
    )
    mocker.patch(f"{USERS_DETAIL}.build_idp_attribute_panel", return_value=[])

    mock_template = mocker.patch(
        f"{USERS_DETAIL}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/users/user-123/profile")

    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["attribute_categories"] == fake_groups
    assert context["idp_attribute_groups"] == []


def test_user_detail_profile_idp_panel_rendered_when_rows_exist(
    test_admin_user, mocker, override_auth
):
    """When IdP-mirror rows exist, idp_attribute_groups is non-empty in context."""
    override_auth(test_admin_user, level="admin")
    _patch_common(mocker)

    mocker.patch(f"{USERS_DETAIL}.build_attribute_groups_for_admin", return_value=[])
    fake_idp_groups = [
        {
            "idp_id": "idp-1",
            "idp_name": "Okta",
            "attributes": [
                {
                    "attribute_key": "job_title",
                    "value": "Engineer",
                    "updated_at": datetime.now(UTC),
                    "mirrored_into_profile": True,
                },
            ],
        },
    ]
    mocker.patch(
        f"{USERS_DETAIL}.build_idp_attribute_panel",
        return_value=fake_idp_groups,
    )

    mock_template = mocker.patch(
        f"{USERS_DETAIL}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/users/user-123/profile")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["idp_attribute_groups"] == fake_idp_groups


def test_admin_update_attributes_calls_set_and_clear(test_admin_user, mocker, override_auth):
    """POST /users/{id}/update-attributes routes each present field to set or clear."""
    override_auth(test_admin_user, level="admin")

    def _cfg(key, **flags):
        base = {
            "id": f"id-{key}",
            "tenant_id": "tenant-1",
            "attribute_key": key,
            "category": "professional",
            "enabled": True,
            "required": False,
            "mirror_from_idp": True,
            "locked_for_users": False,
            "send_to_sps_default": True,
            "updated_at": datetime.now(UTC),
        }
        base.update(flags)
        return base

    mocker.patch(
        f"{SERVICES_SETTINGS}.list_tenant_attribute_config",
        return_value=[
            _cfg("job_title"),
            _cfg("department"),
            _cfg("phone_work", enabled=False),
        ],
    )
    set_attr = mocker.patch(f"{SERVICES_USERS}.set_user_attribute")
    clear_attr = mocker.patch(f"{SERVICES_USERS}.clear_user_attribute")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-attributes",
        data={
            "csrf_token": "test-token",
            "attr_job_title": "Director",
            "attr_department": "",
            "attr_phone_work": "ignored",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "/users/user-123/profile" in response.headers["location"]
    assert "success=attributes_saved" in response.headers["location"]

    set_keys = [c.args[2] for c in set_attr.call_args_list]
    clear_keys = [c.args[2] for c in clear_attr.call_args_list]
    assert "job_title" in set_keys
    assert "department" in clear_keys
    # Disabled config row is silently skipped even though admin posted it.
    assert "phone_work" not in set_keys and "phone_work" not in clear_keys


def test_admin_update_attributes_member_blocked(test_user, mocker, override_auth):
    """Plain members cannot reach the admin bulk-update endpoint."""
    override_auth(test_user)
    mocker.patch(f"{SERVICES_SETTINGS}.list_tenant_attribute_config")
    set_attr = mocker.patch(f"{SERVICES_USERS}.set_user_attribute")

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-attributes",
        data={"csrf_token": "test-token", "attr_job_title": "x"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    set_attr.assert_not_called()


def test_user_detail_profile_skips_idp_panel_when_empty(test_admin_user, mocker, override_auth):
    """When the IdP-panel helper returns [], the context surface is empty."""
    override_auth(test_admin_user, level="admin")
    _patch_common(mocker)

    mocker.patch(f"{USERS_DETAIL}.build_attribute_groups_for_admin", return_value=[])
    mocker.patch(f"{USERS_DETAIL}.build_idp_attribute_panel", return_value=[])

    mock_template = mocker.patch(
        f"{USERS_DETAIL}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/users/user-123/profile")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["idp_attribute_groups"] == []
