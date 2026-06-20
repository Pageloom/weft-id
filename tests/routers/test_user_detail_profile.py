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
    """POST /users/{id}/update-attributes routes the form into the helper.

    The router translates ``attr_<key>`` form fields into the helper's
    ``{key: raw}`` dict with ``enforce_user_lock=False`` (admin path).
    Per-key dispatch is covered in
    ``tests/services/test_apply_attribute_form_updates.py``.
    """
    override_auth(test_admin_user, level="admin")

    apply_helper = mocker.patch(
        f"{SERVICES_USERS}.apply_attribute_form_updates",
        return_value={
            "error_code": None,
            "set_keys": ["job_title"],
            "cleared_keys": ["department"],
            "skipped_locked_keys": [],
        },
    )

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

    apply_helper.assert_called_once()
    target_user_id = apply_helper.call_args.args[1]
    form_data = apply_helper.call_args.args[2]
    assert target_user_id == "user-123"
    assert form_data == {
        "job_title": "Director",
        "department": "",
        "phone_work": "ignored",
    }
    # Admin path -> locks are bypassed.
    assert apply_helper.call_args.kwargs == {"enforce_user_lock": False}


def test_admin_update_attributes_emits_user_profile_updated_event(
    test_tenant, test_super_admin_user, test_admin_user, test_user, mocker, override_auth
):
    """Integration: the admin update-attributes route emits user_profile_updated.

    Exercises the full route -> apply_attribute_form_updates -> set_user_attribute
    -> log_event chain with no service mock, pinning that an admin edit produces
    an audit event with ``cause=admin_edit`` and a per-key change action.
    """
    from services.settings import attributes as attributes_settings

    tenant_id = test_tenant["id"]
    super_admin = {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": tenant_id,
        "role": "super_admin",
    }

    # Enable job_title so the admin edit is accepted and persisted.
    attributes_settings.seed_tenant_attribute_config(tenant_id)
    attributes_settings.update_tenant_attribute_config(
        super_admin,
        "job_title",
        enabled=True,
        required=False,
        mirror_from_idp=False,
        locked_for_users=False,
        send_to_sps_default=False,
    )

    override_auth(test_admin_user, level="admin")
    log_spy = mocker.patch("services.users.attributes.log_event")

    client = TestClient(app)
    response = client.post(
        f"/users/{test_user['id']}/update-attributes",
        data={"csrf_token": "test-token", "attr_job_title": "Director"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert f"/users/{test_user['id']}/profile" in response.headers["location"]
    assert "success=attributes_saved" in response.headers["location"]

    profile_events = [
        c for c in log_spy.call_args_list if c.kwargs.get("event_type") == "user_profile_updated"
    ]
    assert len(profile_events) == 1
    meta = profile_events[0].kwargs["metadata"]
    assert meta["cause"] == "admin_edit"
    assert meta["changes"] == {"job_title": "added"}


def test_admin_update_attributes_user_not_found_redirects_to_list(
    test_admin_user, mocker, override_auth
):
    """When the helper reports user_not_found, the admin bulk-update endpoint
    303-redirects to the users list with ``?error=user_not_found`` (not back
    to the (now-missing) profile page)."""
    override_auth(test_admin_user, level="admin")

    apply_helper = mocker.patch(
        f"{SERVICES_USERS}.apply_attribute_form_updates",
        return_value={
            "error_code": "user_not_found",
            "set_keys": [],
            "cleared_keys": [],
            "skipped_locked_keys": [],
        },
    )

    client = TestClient(app)
    response = client.post(
        "/users/user-123/update-attributes",
        data={"csrf_token": "test-token", "attr_job_title": "x"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/users/list?error=user_not_found"
    apply_helper.assert_called_once()


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


def test_user_detail_profile_surfaces_success_banner_context(
    test_admin_user, mocker, override_auth
):
    """?success=attributes_saved is plumbed into the template context."""
    override_auth(test_admin_user, level="admin")
    _patch_common(mocker)
    mocker.patch(f"{USERS_DETAIL}.build_attribute_groups_for_admin", return_value=[])
    mocker.patch(f"{USERS_DETAIL}.build_idp_attribute_panel", return_value=[])

    mock_template = mocker.patch(
        f"{USERS_DETAIL}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/users/user-123/profile?success=attributes_saved")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["success"] == "attributes_saved"
    assert context["error"] is None
    assert context["invalid_attribute_label"] is None


def test_user_detail_profile_surfaces_invalid_attribute_label(
    test_admin_user, mocker, override_auth
):
    """?error=invalid_<key> resolves to the registry's friendly name in context."""
    override_auth(test_admin_user, level="admin")
    _patch_common(mocker)
    mocker.patch(f"{USERS_DETAIL}.build_attribute_groups_for_admin", return_value=[])
    mocker.patch(f"{USERS_DETAIL}.build_idp_attribute_panel", return_value=[])

    mock_template = mocker.patch(
        f"{USERS_DETAIL}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/users/user-123/profile?error=invalid_phone_work")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["error"] == "invalid_phone_work"
    assert context["invalid_attribute_label"] == "phoneWork"


def test_user_detail_profile_unknown_invalid_key_falls_back(test_admin_user, mocker, override_auth):
    """invalid_<unknown-key> still passes through error but with no friendly label."""
    override_auth(test_admin_user, level="admin")
    _patch_common(mocker)
    mocker.patch(f"{USERS_DETAIL}.build_attribute_groups_for_admin", return_value=[])
    mocker.patch(f"{USERS_DETAIL}.build_idp_attribute_panel", return_value=[])

    mock_template = mocker.patch(
        f"{USERS_DETAIL}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/users/user-123/profile?error=invalid_made_up_key")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["error"] == "invalid_made_up_key"
    assert context["invalid_attribute_label"] is None
