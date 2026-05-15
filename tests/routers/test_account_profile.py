"""Tests for the /account/profile page rendering of standard attribute categories."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

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


def test_profile_page_surfaces_success_banner_context(test_user, override_auth, mocker):
    """?success=attributes_saved is plumbed into the template context."""
    override_auth(test_user)
    mocker.patch(f"{SERVICES_SETTINGS}.list_tenant_attribute_config", return_value=[])
    mocker.patch(f"{SERVICES_USERS}.list_user_attributes", return_value=[])
    mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=True)

    mock_template = mocker.patch(
        f"{ROUTERS_ACCOUNT}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/account/profile?success=attributes_saved")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["success"] == "attributes_saved"
    assert context["error"] is None
    assert context["invalid_attribute_label"] is None


def test_profile_page_surfaces_invalid_attribute_label(test_user, override_auth, mocker):
    """?error=invalid_<key> resolves to the registry's friendly name in context."""
    override_auth(test_user)
    mocker.patch(f"{SERVICES_SETTINGS}.list_tenant_attribute_config", return_value=[])
    mocker.patch(f"{SERVICES_USERS}.list_user_attributes", return_value=[])
    mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=True)

    mock_template = mocker.patch(
        f"{ROUTERS_ACCOUNT}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/account/profile?error=invalid_job_title")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["error"] == "invalid_job_title"
    assert context["invalid_attribute_label"] == "jobTitle"


def test_profile_page_unknown_invalid_key_falls_back(test_user, override_auth, mocker):
    """invalid_<unknown-key> still passes through error but with no friendly label."""
    override_auth(test_user)
    mocker.patch(f"{SERVICES_SETTINGS}.list_tenant_attribute_config", return_value=[])
    mocker.patch(f"{SERVICES_USERS}.list_user_attributes", return_value=[])
    mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=True)

    mock_template = mocker.patch(
        f"{ROUTERS_ACCOUNT}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/account/profile?error=invalid_does_not_exist")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["error"] == "invalid_does_not_exist"
    assert context["invalid_attribute_label"] is None


def test_profile_page_save_failed_passes_through(test_user, override_auth, mocker):
    """?error=save_failed surfaces but no friendly label."""
    override_auth(test_user)
    mocker.patch(f"{SERVICES_SETTINGS}.list_tenant_attribute_config", return_value=[])
    mocker.patch(f"{SERVICES_USERS}.list_user_attributes", return_value=[])
    mocker.patch(f"{SERVICES_SETTINGS}.can_user_edit_profile", return_value=True)

    mock_template = mocker.patch(
        f"{ROUTERS_ACCOUNT}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>ok</html>"),
    )

    client = TestClient(app)
    response = client.get("/account/profile?error=save_failed")
    assert response.status_code == 200
    context = mock_template.call_args.args[2]
    assert context["error"] == "save_failed"
    assert context["invalid_attribute_label"] is None


# ============================================================================
# Route-level integration: NO service-layer mocking
# ----------------------------------------------------------------------------
# These tests intentionally let the request reach the real
# ``users_service.set_user_attribute`` / ``clear_user_attribute`` so that
# router-to-service plumbing bugs (e.g. the UUID-vs-str regression that hid
# behind a mocked service layer) are caught at the route boundary.
# ============================================================================


def test_update_attributes_self_edit_member_returns_303_not_403(test_user, override_auth):
    """A non-admin updating their OWN attributes must succeed with 303 + flash.

    Regression coverage: ``user["id"]`` is a ``UUID`` while
    ``requesting_user["id"]`` is a ``str``. The service-layer self-edit
    check compares those values; passing a raw UUID makes the service
    treat the request as "non-admin acting on someone else" and emit
    ``ForbiddenError``. The router must coerce to ``str`` so the policy
    check sees self.
    """
    from services.settings.attributes import seed_tenant_attribute_config
    from services.users import set_user_attribute

    # Hardening assertions: this regression test is load-bearing only if the
    # fixture still produces a non-admin user with a raw-UUID id. An admin
    # would bypass the self-edit check entirely (so a 303 would be vacuous),
    # and a str-typed id would mask the UUID-vs-str comparison bug. If the
    # fixture ever changes shape, fail loudly here rather than silently
    # degrade into a green test that no longer pins the behaviour.
    assert test_user["role"] == "member", (
        "Regression test requires a non-admin fixture; admin would bypass the "
        "self-edit policy check that hides the bug."
    )
    assert isinstance(test_user["id"], UUID), (
        "Regression test requires a raw UUID id; a str-typed id would let the "
        "buggy router code pass without the str() coercion under test."
    )

    override_auth(test_user)

    # Seed the tenant_attribute_config table (test_tenant fixture creates
    # the tenant directly, bypassing the seed helper).
    tenant_id = str(test_user["tenant_id"])
    seed_tenant_attribute_config(tenant_id)

    # Enable job_title so the form field is processed by the loop.
    requesting_user = {"id": str(test_user["id"]), "tenant_id": tenant_id, "role": "super_admin"}
    from services.settings.attributes import update_tenant_attribute_config

    update_tenant_attribute_config(
        requesting_user,
        "job_title",
        enabled=True,
        required=False,
        mirror_from_idp=False,
        locked_for_users=False,
        send_to_sps_default=True,
    )

    client = TestClient(app)
    response = client.post(
        "/account/profile/update-attributes",
        data={"attr_job_title": "Engineer"},
        follow_redirects=False,
    )

    # Must be a 303 success redirect with the saved flash, NOT a 403 or
    # an error redirect.
    assert response.status_code == 303
    assert response.headers["location"] == "/account/profile?success=attributes_saved"

    # The value actually landed in user_attributes (real service was called).
    self_requesting_user = {
        "id": str(test_user["id"]),
        "tenant_id": tenant_id,
        "role": "member",
    }
    # Use the service to confirm the row exists.
    from services.users import get_user_attribute

    stored = get_user_attribute(self_requesting_user, str(test_user["id"]), "job_title")
    assert stored is not None
    assert stored["value"] == "Engineer"

    # Sanity check the service still rejects a UUID-vs-str mismatch when a
    # non-admin targets a different user. This guards the assertion above
    # against accidental authorization-bypass regressions: the service is
    # still doing the self check, the router just stringifies first.
    import pytest
    from services.exceptions import ForbiddenError

    other_id = "00000000-0000-0000-0000-000000000001"
    with pytest.raises(ForbiddenError):
        set_user_attribute(self_requesting_user, other_id, "job_title", "x")
