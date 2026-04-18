"""Tests for routers.auth.enhanced_enrollment (pre-auth TOTP enrollment).

The enrollment flow is gated by session key `pending_enhanced_enrollment_user_id`.
Accesses without that key redirect to /login. On successful TOTP verification
the user is fully signed in and redirected to /dashboard.
"""

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app


def test_enroll_page_redirects_without_pending_session(test_tenant):
    """GET /login/enroll-enhanced-auth redirects to /login without a pending session key."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.get("/login/enroll-enhanced-auth", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_enroll_post_redirects_without_pending_session(test_tenant):
    """POST /login/enroll-enhanced-auth redirects to /login without a pending session key."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth",
        data={"code": "123456"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_enroll_page_renders_totp_setup_when_pending(test_tenant, mocker):
    """GET renders the TOTP setup template when a pending user is in session."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value={"id": user_id, "role": "member", "mfa_method": "email"},
    )

    class _Setup:
        uri = "otpauth://totp/foo?secret=BASE32SECRET"
        secret = "BASE32 SECRET"

    mocker.patch("routers.auth.enhanced_enrollment.mfa_service.setup_totp", return_value=_Setup())
    mocker.patch(
        "routers.auth.enhanced_enrollment.generate_qr_code_base64",
        return_value="data:image/png;base64,xx",
    )
    mock_template = mocker.patch("routers.auth.enhanced_enrollment.templates.TemplateResponse")
    mock_template.return_value = HTMLResponse(content="<html>enroll</html>")

    client = TestClient(app)
    response = client.get("/login/enroll-enhanced-auth")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert mock_template.call_args[0][1] == "enroll_enhanced_auth.html"
    ctx = mock_template.call_args[0][2]
    assert ctx["secret"] == "BASE32 SECRET"
    assert ctx["uri"].startswith("otpauth://")


def test_enroll_post_invalid_code_redirects_with_error(test_tenant, mocker):
    """POST with an invalid TOTP code re-renders the enroll page with error=invalid_code."""
    from dependencies import get_tenant_id_from_request
    from services.exceptions import ValidationError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value={"id": user_id, "role": "member", "mfa_method": "email"},
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.mfa_service.verify_totp_and_enable",
        side_effect=ValidationError(message="bad code", code="invalid_totp_code"),
    )

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth",
        data={"code": "000000"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "/login/enroll-enhanced-auth" in response.headers["location"]
    assert "error=invalid_code" in response.headers["location"]


def test_enroll_post_valid_code_completes_login(test_tenant, mocker):
    """POST with a valid TOTP code finalizes the session and redirects to /dashboard."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value={"id": user_id, "role": "member", "mfa_method": "email"},
    )
    # Service sets mfa_method=totp internally; we simulate it succeeding.
    mocker.patch("routers.auth.enhanced_enrollment.mfa_service.verify_totp_and_enable")
    mocker.patch("routers.auth.enhanced_enrollment.log_event")

    # Stub out the completion helper so we don't need full DB/session setup.
    from fastapi.responses import RedirectResponse

    mocker.patch(
        "routers.auth.enhanced_enrollment.complete_authenticated_login",
        return_value=RedirectResponse(url="/dashboard", status_code=303),
    )

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth",
        data={"code": "123456"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_enroll_post_valid_code_emits_enhanced_enrolled_event(test_tenant, mocker):
    """POST with valid TOTP code logs user_enhanced_auth_enrolled with method=totp."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value={"id": user_id, "role": "member", "mfa_method": "email"},
    )
    mocker.patch("routers.auth.enhanced_enrollment.mfa_service.verify_totp_and_enable")
    mock_log = mocker.patch("routers.auth.enhanced_enrollment.log_event")

    from fastapi.responses import RedirectResponse

    mocker.patch(
        "routers.auth.enhanced_enrollment.complete_authenticated_login",
        return_value=RedirectResponse(url="/dashboard", status_code=303),
    )

    client = TestClient(app)
    client.post(
        "/login/enroll-enhanced-auth",
        data={"code": "123456"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    # Verify the dedicated enrollment-complete event was emitted with method=totp
    assert mock_log.called
    kwargs = mock_log.call_args.kwargs
    assert kwargs["event_type"] == "user_enhanced_auth_enrolled"
    assert kwargs["metadata"] == {"method": "totp"}
    assert kwargs["artifact_type"] == "user"
    assert kwargs["artifact_id"] == user_id


def test_enroll_post_invalid_code_preserves_gate_key(test_tenant, mocker):
    """An invalid TOTP code must NOT clear the pending enrollment gate key.

    Users should remain in the enrollment funnel so they can retry without
    being bounced back to /login.
    """
    from dependencies import get_tenant_id_from_request
    from services.exceptions import ValidationError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data: dict = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value={"id": user_id, "role": "member", "mfa_method": "email"},
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.mfa_service.verify_totp_and_enable",
        side_effect=ValidationError(message="bad code", code="invalid_totp_code"),
    )

    client = TestClient(app)
    client.post(
        "/login/enroll-enhanced-auth",
        data={"code": "000000"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    # The gate key must remain present so a retry GET/POST stays in the funnel.
    assert session_data.get("pending_enhanced_enrollment_user_id") == user_id


def test_enroll_page_get_does_not_clear_gate_key(test_tenant, mocker):
    """Refreshing the enrollment page (GET) must keep the gate key intact."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
    session_data: dict = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value={"id": user_id, "role": "member", "mfa_method": "email"},
    )

    class _Setup:
        uri = "otpauth://totp/foo?secret=BASE32SECRET"
        secret = "BASE32 SECRET"

    mocker.patch("routers.auth.enhanced_enrollment.mfa_service.setup_totp", return_value=_Setup())
    mocker.patch(
        "routers.auth.enhanced_enrollment.generate_qr_code_base64",
        return_value="data:image/png;base64,xx",
    )
    mock_template = mocker.patch("routers.auth.enhanced_enrollment.templates.TemplateResponse")
    mock_template.return_value = HTMLResponse(content="<html>enroll</html>")

    client = TestClient(app)
    client.get("/login/enroll-enhanced-auth")

    app.dependency_overrides.clear()

    # Gate key must still be present after a GET render (refresh should not invalidate).
    assert session_data.get("pending_enhanced_enrollment_user_id") == user_id


def test_enroll_page_missing_user_clears_gate_and_redirects(test_tenant, mocker):
    """If the pending user cannot be found, the gate key is cleared and we redirect."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "ghost-user-id"
    session_data: dict = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value=None,
    )

    client = TestClient(app)
    response = client.get("/login/enroll-enhanced-auth", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "pending_enhanced_enrollment_user_id" not in session_data


def test_enroll_page_totp_already_active_falls_through_to_completion(test_tenant, mocker):
    """A user whose mfa_method is already 'totp' but still has the gate key set
    should be completed via the shared login helper instead of staying stuck.

    Covers the fallback branch where `setup_totp` raises `ValidationError`
    (TOTP already active) and `get_pending_totp_setup` returns None.
    """
    from dependencies import get_tenant_id_from_request
    from services.exceptions import ValidationError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "already-totp-user"
    session_data: dict = {
        "pending_enhanced_enrollment_user_id": user_id,
        "pending_mfa_user_id": user_id,
        "pending_mfa_method": "email",
    }
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value={"id": user_id, "role": "member", "mfa_method": "totp"},
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.mfa_service.setup_totp",
        side_effect=ValidationError(message="totp already active", code="totp_already_active"),
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.mfa_service.get_pending_totp_setup",
        return_value=None,
    )

    from fastapi.responses import RedirectResponse

    mock_complete = mocker.patch(
        "routers.auth.enhanced_enrollment.complete_authenticated_login",
        return_value=RedirectResponse(url="/dashboard", status_code=303),
    )

    client = TestClient(app)
    response = client.get("/login/enroll-enhanced-auth", follow_redirects=False)

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    # The gate key must be cleared since the user is now completing login.
    assert "pending_enhanced_enrollment_user_id" not in session_data
    assert "pending_mfa_user_id" not in session_data
    # Login completion was invoked with mfa_method=totp.
    mock_complete.assert_called_once()
    assert mock_complete.call_args.kwargs["mfa_method"] == "totp"


def test_enroll_post_missing_user_clears_gate_and_redirects(test_tenant, mocker):
    """POST with a pending user_id that no longer resolves clears the gate and redirects."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "ghost-user-id"
    session_data: dict = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value=None,
    )

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth",
        data={"code": "123456"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert "pending_enhanced_enrollment_user_id" not in session_data


def test_enroll_page_pending_setup_falls_back_when_setup_fails(test_tenant, mocker):
    """When setup_totp raises but a pending setup exists, render with that pending secret."""
    from dependencies import get_tenant_id_from_request
    from services.exceptions import ValidationError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "pending-totp-user"
    session_data: dict = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value={"id": user_id, "role": "member", "mfa_method": "email"},
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.mfa_service.setup_totp",
        side_effect=ValidationError(message="in progress", code="already_pending"),
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.mfa_service.get_pending_totp_setup",
        return_value=("EXISTING SECRET", "otpauth://totp/foo?secret=EXISTINGSECRET"),
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.generate_qr_code_base64",
        return_value="data:image/png;base64,xx",
    )
    mock_template = mocker.patch("routers.auth.enhanced_enrollment.templates.TemplateResponse")
    mock_template.return_value = HTMLResponse(content="<html>enroll</html>")

    client = TestClient(app)
    response = client.get("/login/enroll-enhanced-auth")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    ctx = mock_template.call_args[0][2]
    assert ctx["secret"] == "EXISTING SECRET"
    assert ctx["uri"].endswith("EXISTINGSECRET")
    # Gate key must remain (user is still being prompted to verify).
    assert session_data.get("pending_enhanced_enrollment_user_id") == user_id
