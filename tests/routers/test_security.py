"""Tests for routers/security.py endpoints.

Promoted from /admin/settings/security to /security as part of the nav
restructure (see .claude/ITERATION_nav_restructure.md, Iteration 4). Split
out of tests/routers/test_settings.py.
"""

from unittest.mock import Mock

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app

# Module path constants for cleaner patch targets
ROUTERS_SECURITY = "routers.security"
DB_SECURITY = "database.security"
UTILS_TEMPLATE = "utils.template_context"
UTILS_ERRORS = "utils.service_errors"


def test_tenant_security_redirects_to_sessions(test_super_admin_user, override_auth):
    """Test /security/ redirects to /security/sessions (the first accessible child)."""
    override_auth(test_super_admin_user, level="super_admin")

    client = TestClient(app)
    response = client.get("/security/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/security/sessions"


def test_tenant_security_sessions_page(test_super_admin_user, override_auth, mocker):
    """Test tenant security sessions tab page."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{DB_SECURITY}.get_security_settings")
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SECURITY}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security sessions</html>"),
    )

    mock_get.return_value = {
        "session_timeout_seconds": 1800,
        "persistent_sessions": False,
        "allow_users_edit_profile": True,
    }

    client = TestClient(app)
    response = client.get("/security/sessions")

    assert response.status_code == 200
    mock_get.assert_called_once_with(str(test_super_admin_user["tenant_id"]))


def test_tenant_security_certificates_page(test_super_admin_user, override_auth, mocker):
    """Test tenant security certificates tab page."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SECURITY}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security certificates</html>"),
    )

    client = TestClient(app)
    response = client.get("/security/certificates")

    assert response.status_code == 200


def test_tenant_security_permissions_page(test_super_admin_user, override_auth, mocker):
    """Test tenant security permissions tab page."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SECURITY}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security permissions</html>"),
    )

    client = TestClient(app)
    response = client.get("/security/permissions")

    assert response.status_code == 200


def test_tenant_security_sessions_page_no_settings(test_super_admin_user, override_auth, mocker):
    """Test tenant security sessions page when no settings exist (defaults)."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SECURITY}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>security</html>"),
    )

    client = TestClient(app)
    response = client.get("/security/sessions")

    assert response.status_code == 200


def test_update_tenant_security_sessions(test_super_admin_user, override_auth, mocker):
    """Test updating tenant session security settings."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/security/sessions/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=1" in response.headers["location"]
    mock_update.assert_called_once()


def test_update_tenant_security_sessions_no_timeout(test_super_admin_user, override_auth, mocker):
    """Test updating sessions with no timeout (indefinite)."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/security/sessions/update",
        data={
            "session_timeout": "",  # Empty = indefinite
            "persistent_sessions": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    # timeout_seconds should be None
    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["timeout_seconds"] is None


def test_update_tenant_security_sessions_invalid_timeout_shows_error_page(
    test_super_admin_user, override_auth, mocker
):
    """Test updating sessions with invalid timeout shows error page."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_template = mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(
            content="<html>Invalid Input: timeout must be positive</html>", status_code=400
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/security/sessions/update",
        data={
            "session_timeout": "0",  # Zero is invalid
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    # Route validates timeout and returns error page
    assert response.status_code == 400
    mock_template.assert_called_once()


def test_update_tenant_security_permissions(test_super_admin_user, override_auth, mocker):
    """Test updating tenant permission security settings."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/security/permissions/update",
        data={
            "allow_users_edit_profile": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=1" in response.headers["location"]
    mock_update.assert_called_once()


def test_security_tab_form_action_urls_are_correct():
    """Test that each security tab template form posts to the correct URL.

    Regression test for bug where form posted to wrong URL causing 404.
    """
    import os

    templates_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "templates")

    # Sessions tab
    with open(os.path.join(templates_dir, "settings_security_tab_sessions.html")) as f:
        content = f.read()
    assert 'action="/security/sessions/update"' in content

    # Certificates tab
    with open(os.path.join(templates_dir, "settings_security_tab_certificates.html")) as f:
        content = f.read()
    assert 'action="/security/certificates/update"' in content

    # Permissions tab
    with open(os.path.join(templates_dir, "settings_security_tab_permissions.html")) as f:
        content = f.read()
    assert 'action="/security/permissions/update"' in content


# =============================================================================
# Security Settings Error Handling Tests
# =============================================================================


def test_admin_security_sessions_service_error(test_super_admin_user, override_auth, mocker):
    """Test security sessions page shows error when service fails."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_get = mocker.patch(f"{ROUTERS_SECURITY}.settings_service.get_security_settings")
    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")

    mock_get.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.get("/security/sessions")

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_update_security_non_numeric_timeout_error(test_super_admin_user, override_auth, mocker):
    """Test updating sessions with non-numeric timeout shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/security/sessions/update",
        data={
            "session_timeout": "not-a-number",  # Non-numeric
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_update_security_non_numeric_inactivity_error(test_super_admin_user, override_auth, mocker):
    """Test updating sessions with non-numeric inactivity threshold shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/security/sessions/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
            "inactivity_threshold": "not-a-number",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_update_security_sessions_service_error(test_super_admin_user, override_auth, mocker):
    """Test updating sessions with service error shows error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_update = mocker.patch(f"{ROUTERS_SECURITY}.settings_service.update_security_settings")
    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")

    mock_update.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/security/sessions/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


# =============================================================================
# Certificate Lifetime Route Tests
# =============================================================================


def test_update_tenant_security_with_certificate_lifetime(
    test_super_admin_user, override_auth, mocker
):
    """Test updating certificates with certificate lifetime form field."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/security/certificates/update",
        data={
            "certificate_lifetime": "3",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=1" in response.headers["location"]
    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["max_certificate_lifetime_years"] == 3


def test_update_tenant_security_empty_certificate_lifetime(
    test_super_admin_user, override_auth, mocker
):
    """Test that empty certificate lifetime keeps the default."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/security/certificates/update",
        data={
            "certificate_lifetime": "",  # Empty = keep default
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    mock_update.assert_called_once()
    # Certificate lifetime should be the default (10) since not provided
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["max_certificate_lifetime_years"] == 10


def test_update_tenant_security_non_numeric_certificate_lifetime_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating certificates with non-numeric certificate lifetime shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/security/certificates/update",
        data={
            "certificate_lifetime": "not-a-number",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_security_certificates_template_has_certificate_lifetime_field():
    """Test that the certificates tab template includes certificate lifetime dropdown."""
    import os

    template_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "app",
        "templates",
        "settings_security_tab_certificates.html",
    )
    with open(template_path) as f:
        template_content = f.read()

    assert 'name="certificate_lifetime"' in template_content
    assert "Validity period" in template_content


# =============================================================================
# Certificate Rotation Window Route Tests
# =============================================================================


def test_update_tenant_security_with_rotation_window(test_super_admin_user, override_auth, mocker):
    """Test updating certificates with rotation window form field."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/security/certificates/update",
        data={
            "rotation_window": "30",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "success=1" in response.headers["location"]
    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["certificate_rotation_window_days"] == 30


def test_update_tenant_security_empty_rotation_window(test_super_admin_user, override_auth, mocker):
    """Test that empty rotation window keeps the default."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/security/certificates/update",
        data={
            "rotation_window": "",  # Empty = keep default
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    mock_update.assert_called_once()
    call_kwargs = mock_update.call_args.kwargs
    assert call_kwargs["certificate_rotation_window_days"] == 90


def test_update_tenant_security_invalid_rotation_window_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating certificates with invalid rotation window shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/security/certificates/update",
        data={
            "rotation_window": "45",  # Invalid: not in [14, 30, 60, 90]
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_security_certificates_template_has_rotation_window_field():
    """Test that the certificates tab template includes rotation window dropdown."""
    import os

    template_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "app",
        "templates",
        "settings_security_tab_certificates.html",
    )
    with open(template_path) as f:
        template_content = f.read()

    assert 'name="rotation_window"' in template_content
    assert "Rotation window" in template_content


# =============================================================================
# Inactivity Threshold Validation Tests
# =============================================================================


def test_update_security_negative_inactivity_threshold_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating sessions with negative inactivity threshold shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/security/sessions/update",
        data={
            "session_timeout": "",
            "persistent_sessions": "",
            "inactivity_threshold": "-5",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


def test_update_security_zero_inactivity_threshold_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating sessions with zero inactivity threshold shows error."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/security/sessions/update",
        data={
            "session_timeout": "",
            "persistent_sessions": "",
            "inactivity_threshold": "0",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


# =============================================================================
# Certificate Lifetime Invalid Numeric Value Test
# =============================================================================


def test_update_security_invalid_certificate_lifetime_value_error(
    test_super_admin_user, override_auth, mocker
):
    """Test updating certificates with numeric but disallowed certificate lifetime (e.g. 4)."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{UTILS_ERRORS}.templates.TemplateResponse",
        return_value=HTMLResponse(content="Error", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/security/certificates/update",
        data={
            "certificate_lifetime": "4",  # Valid int, but not in [1,2,3,5,10]
        },
        follow_redirects=False,
    )

    assert response.status_code == 400


# =============================================================================
# Security Settings PydanticValidationError Test
# =============================================================================


def test_update_security_pydantic_validation_error(test_super_admin_user, override_auth, mocker):
    """Test PydanticValidationError during schema construction shows error page."""
    from pydantic import BaseModel
    from pydantic import ValidationError as PydanticValidationError

    override_auth(test_super_admin_user, level="super_admin")

    # Create a real PydanticValidationError to use as side_effect
    class _Dummy(BaseModel):
        x: int

    saved_err = None
    try:
        _Dummy(x="bad")  # type: ignore[arg-type]
    except PydanticValidationError as e:
        saved_err = e

    assert saved_err is not None

    mocker.patch(
        f"{ROUTERS_SECURITY}.TenantSecuritySettingsUpdate",
        side_effect=saved_err,
    )
    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/security/sessions/update",
        data={
            "session_timeout": "3600",
            "persistent_sessions": "true",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


# =============================================================================
# Passwords Tab Tests
# =============================================================================


def test_tenant_security_passwords_page(test_super_admin_user, override_auth, mocker):
    """Test passwords security settings tab renders."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{DB_SECURITY}.get_security_settings",
        return_value={
            "session_timeout_seconds": None,
            "persistent_sessions": True,
            "allow_users_edit_profile": True,
            "inactivity_threshold_days": None,
            "max_certificate_lifetime_years": 10,
            "certificate_rotation_window_days": 90,
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        },
    )
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mocker.patch(
        f"{ROUTERS_SECURITY}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>passwords</html>"),
    )

    client = TestClient(app)
    response = client.get("/security/passwords")

    assert response.status_code == 200


def test_update_tenant_security_passwords(test_super_admin_user, override_auth, mocker):
    """Test updating password policy settings."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(
        f"{DB_SECURITY}.get_security_settings",
        return_value={
            "session_timeout_seconds": None,
            "persistent_sessions": True,
            "allow_users_edit_profile": True,
            "inactivity_threshold_days": None,
            "max_certificate_lifetime_years": 10,
            "certificate_rotation_window_days": 90,
            "minimum_password_length": 14,
            "minimum_zxcvbn_score": 3,
        },
    )
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings", return_value=1)
    mocker.patch("services.event_log.log_event")

    client = TestClient(app)
    response = client.post(
        "/security/passwords/update",
        data={
            "minimum_password_length": "16",
            "minimum_zxcvbn_score": "4",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/security/passwords?success=1"
    mock_update.assert_called_once()


def test_update_passwords_invalid_length_error(test_super_admin_user, override_auth, mocker):
    """Test that invalid password length value shows error page."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/security/passwords/update",
        data={
            "minimum_password_length": "15",
            "minimum_zxcvbn_score": "3",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_update_passwords_invalid_score_error(test_super_admin_user, override_auth, mocker):
    """Test that invalid zxcvbn score value shows error page."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/security/passwords/update",
        data={
            "minimum_password_length": "14",
            "minimum_zxcvbn_score": "2",
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


# =============================================================================
# Password/Certificate/Permissions PydanticValidation and ServiceError Tests
# =============================================================================


def test_update_passwords_service_error(test_super_admin_user, override_auth, mocker):
    """Test updating password settings with service error shows error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_update = mocker.patch(f"{ROUTERS_SECURITY}.settings_service.update_security_settings")
    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")

    mock_update.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/security/passwords/update",
        data={"minimum_password_length": "14", "minimum_zxcvbn_score": "3"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_update_passwords_pydantic_validation_error(test_super_admin_user, override_auth, mocker):
    """Test PydanticValidationError during password settings schema shows error page."""
    from pydantic import BaseModel
    from pydantic import ValidationError as PydanticValidationError

    override_auth(test_super_admin_user, level="super_admin")

    class _Dummy(BaseModel):
        x: int

    saved_err = None
    try:
        _Dummy(x="bad")  # type: ignore[arg-type]
    except PydanticValidationError as e:
        saved_err = e

    assert saved_err is not None

    mocker.patch(f"{ROUTERS_SECURITY}.TenantSecuritySettingsUpdate", side_effect=saved_err)
    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/security/passwords/update",
        data={"minimum_password_length": "14", "minimum_zxcvbn_score": "3"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_update_certificates_service_error(test_super_admin_user, override_auth, mocker):
    """Test updating certificate settings with service error shows error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_update = mocker.patch(f"{ROUTERS_SECURITY}.settings_service.update_security_settings")
    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")

    mock_update.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/security/certificates/update",
        data={"certificate_lifetime": "3"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_update_certificates_pydantic_validation_error(
    test_super_admin_user, override_auth, mocker
):
    """Test PydanticValidationError during certificate settings schema shows error page."""
    from pydantic import BaseModel
    from pydantic import ValidationError as PydanticValidationError

    override_auth(test_super_admin_user, level="super_admin")

    class _Dummy(BaseModel):
        x: int

    saved_err = None
    try:
        _Dummy(x="bad")  # type: ignore[arg-type]
    except PydanticValidationError as e:
        saved_err = e

    assert saved_err is not None

    mocker.patch(f"{ROUTERS_SECURITY}.TenantSecuritySettingsUpdate", side_effect=saved_err)
    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/security/certificates/update",
        data={"certificate_lifetime": "3"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_update_permissions_service_error(test_super_admin_user, override_auth, mocker):
    """Test updating permission settings with service error shows error page."""
    from services.exceptions import ServiceError

    override_auth(test_super_admin_user, level="super_admin")

    mock_update = mocker.patch(f"{ROUTERS_SECURITY}.settings_service.update_security_settings")
    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")

    mock_update.side_effect = ServiceError(message="Database error")
    mock_error.return_value = HTMLResponse(content="Error", status_code=500)

    client = TestClient(app)
    response = client.post(
        "/security/permissions/update",
        data={"allow_users_edit_profile": "true"},
        follow_redirects=False,
    )

    assert response.status_code == 500
    mock_error.assert_called_once()


def test_update_permissions_pydantic_validation_error(test_super_admin_user, override_auth, mocker):
    """Test PydanticValidationError during permission settings schema shows error page."""
    from pydantic import BaseModel
    from pydantic import ValidationError as PydanticValidationError

    override_auth(test_super_admin_user, level="super_admin")

    class _Dummy(BaseModel):
        x: int

    saved_err = None
    try:
        _Dummy(x="bad")  # type: ignore[arg-type]
    except PydanticValidationError as e:
        saved_err = e

    assert saved_err is not None

    mocker.patch(f"{ROUTERS_SECURITY}.TenantSecuritySettingsUpdate", side_effect=saved_err)
    mock_error = mocker.patch(f"{ROUTERS_SECURITY}.render_error_page")
    mock_error.return_value = HTMLResponse(content="Error", status_code=400)

    client = TestClient(app)
    response = client.post(
        "/security/permissions/update",
        data={"allow_users_edit_profile": "true"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


def test_tenant_security_authentication_page(test_super_admin_user, override_auth, mocker):
    """GET /security/authentication renders the authentication tab."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mocker.patch(f"{UTILS_TEMPLATE}.get_template_context", return_value={"request": Mock()})
    mock_template = mocker.patch(
        f"{ROUTERS_SECURITY}.templates.TemplateResponse",
        return_value=HTMLResponse(content="<html>auth</html>"),
    )

    client = TestClient(app)
    response = client.get("/security/authentication")

    assert response.status_code == 200
    assert mock_template.call_args[0][1] == "settings_security_tab_authentication.html"


def test_update_tenant_security_authentication_enhanced(
    test_super_admin_user, override_auth, mocker
):
    """POST accepts required_auth_strength=enhanced and redirects with success."""
    override_auth(test_super_admin_user, level="super_admin")

    mocker.patch(f"{DB_SECURITY}.get_security_settings", return_value=None)
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)
    response = client.post(
        "/security/authentication/update",
        data={"required_auth_strength": "enhanced"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/security/authentication?success=1"
    mock_update.assert_called_once()
    # The resolved required_auth_strength must be passed to the DB layer
    kwargs = mock_update.call_args.kwargs
    assert kwargs["required_auth_strength"] == "enhanced"


def test_update_tenant_security_authentication_invalid_value(
    test_super_admin_user, override_auth, mocker
):
    """Invalid required_auth_strength value renders the validation error page."""
    override_auth(test_super_admin_user, level="super_admin")

    mock_error = mocker.patch(
        f"{ROUTERS_SECURITY}.render_error_page",
        return_value=HTMLResponse(content="<html>error</html>", status_code=400),
    )

    client = TestClient(app)
    response = client.post(
        "/security/authentication/update",
        data={"required_auth_strength": "bogus"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    mock_error.assert_called_once()


# =============================================================================
# Router-Level Permission Tests
# =============================================================================


def test_security_routes_require_super_admin_not_just_admin(test_admin_user, override_auth, mocker):
    """A plain admin (not super_admin) is rejected by every /security/* route.

    Regression test for the Iteration 4 simplification that moved the
    per-route `Depends(require_super_admin)` (used by the old
    /admin/settings-prefixed router) to a single router-level dependency in
    routers/security.py. This is the only HTTP-layer gate on this router (no
    has_page_access() backstop exists in routers/security.py), so it must
    actually reject a plain admin, not just a super_admin-and-up nav check.

    require_super_admin is a router-layer *authentication* dependency in this
    codebase (see app/dependencies.py): it redirects rather than raising a
    403. The exact location varies between `/dashboard`
    (logged-in-but-wrong-role) and `/login` (the real dependency cannot see
    the test's `get_current_user` override at the "admin" level -- see
    test_identity_providers.py::test_bind_domain_to_oidc_connection_requires_super_admin
    for the same precedent), so both are accepted.
    """
    override_auth(test_admin_user, level="admin")

    mock_get = mocker.patch(f"{DB_SECURITY}.get_security_settings")
    mock_update = mocker.patch(f"{DB_SECURITY}.update_security_settings")

    client = TestClient(app)

    for path in (
        "/security/",
        "/security/sessions",
        "/security/certificates",
        "/security/passwords",
        "/security/permissions",
        "/security/authentication",
    ):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303, path
        assert response.headers["location"] in ("/dashboard", "/login"), path

    for path in (
        "/security/sessions/update",
        "/security/certificates/update",
        "/security/passwords/update",
        "/security/permissions/update",
        "/security/authentication/update",
    ):
        response = client.post(path, data={}, follow_redirects=False)
        assert response.status_code == 303, path
        assert response.headers["location"] in ("/dashboard", "/login"), path

    mock_get.assert_not_called()
    mock_update.assert_not_called()
