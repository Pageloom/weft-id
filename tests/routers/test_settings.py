"""Tests for routers/settings.py and routers/settings_branding.py endpoints.

Narrowed to Branding and About as part of the nav restructure -- Security
tests moved to tests/routers/test_security.py (see
.claude/ITERATION_nav_restructure.md, Iteration 4).
"""

from unittest.mock import Mock

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

# Module path constants for cleaner patch targets
ROUTERS_SETTINGS = "routers.settings"
ROUTERS_SETTINGS_BRANDING = "routers.settings_branding"
UTILS_TEMPLATE = "utils.template_context"
UTILS_ERRORS = "utils.service_errors"


def test_settings_index_redirects_to_first_child(test_admin_user, override_auth, mocker):
    """Test settings index redirects to first accessible child page."""
    override_auth(test_admin_user, level="admin")

    mock_first_child = mocker.patch(f"{ROUTERS_SETTINGS}.get_first_accessible_child")
    mock_first_child.return_value = "/settings/branding/global"

    client = TestClient(app)
    response = client.get("/settings/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/settings/branding/global"


# =============================================================================
# Settings Index Fallback Test
# =============================================================================


def test_settings_index_fallback_to_dashboard(override_auth, mocker):
    """Test settings index falls back to dashboard when no children are accessible.

    This tests the fallback path (line 47) when get_first_accessible_child returns None.
    We need a user with a role that has NO accessible admin children.
    """
    # Create a mock user with a role that has no accessible admin pages
    mock_user = {
        "id": "test-id",
        "tenant_id": "test-tenant",
        "role": "nonexistent_role",  # Role with no access
        "first_name": "Test",
        "last_name": "User",
    }

    override_auth(mock_user, level="admin")

    mocker.patch(f"{ROUTERS_SETTINGS}.get_first_accessible_child", return_value=None)

    client = TestClient(app)
    response = client.get("/settings/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


# =============================================================================
# Branding Route Tests
# =============================================================================


def _mock_branding_settings():
    """Create a mock BrandingSettings response."""
    from schemas.branding import BrandingSettings, GroupAvatarStyle, LogoMode

    return BrandingSettings(
        logo_mode=LogoMode.MANDALA,
        use_logo_as_favicon=False,
        tenant_name=None,
        show_title_in_nav=True,
        has_logo_light=False,
        has_logo_dark=False,
        group_avatar_style=GroupAvatarStyle.ACRONYM,
    )


def test_branding_redirect(test_admin_user, override_auth):
    """Test /branding redirects to /branding/global."""
    override_auth(test_admin_user, level="admin")

    client = TestClient(app)
    response = client.get("/settings/branding", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/settings/branding/global"


def test_branding_global_page(test_admin_user, override_auth, mocker):
    """Test branding global settings page renders."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>branding</html>"),
    )

    client = TestClient(app)
    response = client.get("/settings/branding/global")

    assert response.status_code == 200


def test_branding_global_service_error(test_admin_user, override_auth, mocker):
    """Test branding global page shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.get_branding_settings",
        side_effect=ServiceError(message="DB error"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.get("/settings/branding/global")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_branding_groups_page(test_admin_user, override_auth, mocker):
    """Test branding groups settings page renders."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>groups branding</html>"),
    )

    client = TestClient(app)
    response = client.get("/settings/branding/groups")

    assert response.status_code == 200


def test_branding_groups_service_error(test_admin_user, override_auth, mocker):
    """Test branding groups page shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.get_branding_settings",
        side_effect=ServiceError(message="DB error"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.get("/settings/branding/groups")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_upload_branding_logo_success(test_admin_user, override_auth, mocker):
    """Test uploading a branding logo redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.upload_logo",
        return_value=_mock_branding_settings(),
    )

    client = TestClient(app)
    response = client.post(
        "/settings/branding/global/upload/light",
        files={"file": ("logo.png", b"fake-png-data", "image/png")},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=logo_uploaded" in response.headers["location"]


def test_upload_branding_logo_service_error(test_admin_user, override_auth, mocker):
    """Test uploading a branding logo shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.upload_logo",
        side_effect=ServiceError(message="Invalid image"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/settings/branding/global/upload/light",
        files={"file": ("logo.png", b"bad", "image/png")},
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_delete_branding_logo_success(test_admin_user, override_auth, mocker):
    """Test deleting a branding logo redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.delete_logo",
        return_value=_mock_branding_settings(),
    )

    client = TestClient(app)
    response = client.post(
        "/settings/branding/global/delete/dark",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=logo_deleted" in response.headers["location"]


def test_delete_branding_logo_service_error(test_admin_user, override_auth, mocker):
    """Test deleting a branding logo shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.delete_logo",
        side_effect=ServiceError(message="Logo not found"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=404)

    client = TestClient(app)
    response = client.post(
        "/settings/branding/global/delete/light",
        follow_redirects=False,
    )

    assert response.status_code == 404
    mock_error.assert_called_once()


def test_update_branding_settings_success(test_admin_user, override_auth, mocker):
    """Test updating branding settings redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.update_branding_settings",
        return_value=_mock_branding_settings(),
    )

    client = TestClient(app)
    response = client.post(
        "/settings/branding/global/settings",
        data={
            "logo_mode": "custom",
            "use_logo_as_favicon": "true",
            "tenant_name": "My Site",
            "show_title_in_nav": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=settings_updated" in response.headers["location"]


def test_update_branding_settings_invalid_logo_mode(test_admin_user, override_auth, mocker):
    """Test updating branding with invalid logo_mode shows error."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/settings/branding/global/settings",
        data={
            "logo_mode": "invalid_mode",
            "tenant_name": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_update_branding_settings_get_current_error(test_admin_user, override_auth, mocker):
    """Test updating branding settings fails when fetching current settings fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.get_branding_settings",
        side_effect=ServiceError(message="DB error"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/settings/branding/global/settings",
        data={"logo_mode": "mandala"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_update_branding_settings_update_service_error(test_admin_user, override_auth, mocker):
    """Test updating branding settings fails when update service call fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.get_branding_settings",
        return_value=_mock_branding_settings(),
    )
    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.update_branding_settings",
        side_effect=ServiceError(message="Update failed"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/settings/branding/global/settings",
        data={
            "logo_mode": "mandala",
            "tenant_name": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_upload_group_logo_success(test_admin_user, override_auth, mocker):
    """Test uploading a group logo redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.branding_service.upload_group_logo")

    client = TestClient(app)
    response = client.post(
        "/settings/branding/groups/upload/group-123",
        files={"file": ("logo.png", b"fake-png", "image/png")},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=logo_uploaded" in response.headers["location"]


def test_upload_group_logo_service_error(test_admin_user, override_auth, mocker):
    """Test uploading a group logo shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.upload_group_logo",
        side_effect=ServiceError(message="Invalid image"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/settings/branding/groups/upload/group-123",
        files={"file": ("logo.png", b"bad", "image/png")},
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_delete_group_logo_success(test_admin_user, override_auth, mocker):
    """Test deleting a group logo redirects with success."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.branding_service.delete_group_logo")

    client = TestClient(app)
    response = client.post(
        "/settings/branding/groups/delete/group-123",
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=logo_deleted" in response.headers["location"]


def test_delete_group_logo_service_error(test_admin_user, override_auth, mocker):
    """Test deleting a group logo shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_admin_user, level="admin")

    mocker.patch(
        f"{ROUTERS_SETTINGS_BRANDING}.branding_service.delete_group_logo",
        side_effect=ServiceError(message="Group not found"),
    )
    mock_error = mocker.patch(f"{ROUTERS_SETTINGS_BRANDING}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=404)

    client = TestClient(app)
    response = client.post(
        "/settings/branding/groups/delete/group-123",
        follow_redirects=False,
    )

    assert response.status_code == 404
    mock_error.assert_called_once()


# =============================================================================
# About Page
# =============================================================================


def test_about_page_accessible_by_admin(test_admin_user, override_auth, mocker):
    """Admin can access the about page."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>about</html>"),
    )
    mocker.patch(f"{ROUTERS_SETTINGS}.track_activity")

    client = TestClient(app)
    response = client.get("/settings/about")

    assert response.status_code == 200


def test_about_page_accessible_by_super_admin(test_super_admin_user, override_auth, mocker):
    """Super admin can access the about page."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>about</html>"),
    )
    mocker.patch(f"{ROUTERS_SETTINGS}.track_activity")

    client = TestClient(app)
    response = client.get("/settings/about")

    assert response.status_code == 200


def test_about_page_passes_version_to_template(test_admin_user, override_auth, mocker):
    """About page passes version to template context."""
    override_auth(test_admin_user, level="admin")

    mock_context = mocker.patch(
        f"{ROUTERS_SETTINGS}.get_template_context", return_value={"request": Mock()}
    )
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>about</html>"),
    )
    mocker.patch(f"{ROUTERS_SETTINGS}.track_activity")

    client = TestClient(app)
    client.get("/settings/about")

    mock_context.assert_called_once()
    call_kwargs = mock_context.call_args.kwargs
    assert "version" in call_kwargs
    assert isinstance(call_kwargs["version"], str)


def test_about_page_tracks_activity(test_admin_user, override_auth, mocker):
    """About page tracks user activity."""
    override_auth(test_admin_user, level="admin")

    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SETTINGS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>about</html>"),
    )
    mock_track = mocker.patch(f"{ROUTERS_SETTINGS}.track_activity")

    client = TestClient(app)
    client.get("/settings/about")

    mock_track.assert_called_once_with(
        str(test_admin_user["tenant_id"]),
        str(test_admin_user["id"]),
    )


def test_about_page_forbidden_for_regular_user(test_user, override_auth, mocker):
    """Regular user cannot access the about page."""
    override_auth(test_user, level="user")

    client = TestClient(app)
    response = client.get("/settings/about", follow_redirects=False)

    # Admin-required routes redirect non-admins
    assert response.status_code in (303, 403)
