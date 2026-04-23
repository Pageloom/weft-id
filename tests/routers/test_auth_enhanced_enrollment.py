"""Tests for routers.auth.enhanced_enrollment (pre-auth TOTP or passkey enrollment).

The enrollment flow is gated by session key `pending_enhanced_enrollment_user_id`.
Accesses without that key redirect to /login. On successful TOTP verification
the user is fully signed in and redirected to /dashboard. The parallel passkey
registration endpoints accept JSON and return either JSON error envelopes or a
``{"redirect_url": ..., "backup_codes": ...}`` success payload.
"""

from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app
from schemas.webauthn import (
    BeginRegistrationResponse,
    CompleteRegistrationResponse,
    PasskeyResponse,
)


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


# ---------------------------------------------------------------------------
# GET page: both TOTP and passkey options rendered
# ---------------------------------------------------------------------------


def test_get_renders_both_totp_and_passkey_options(test_tenant, mocker):
    """The enrollment page must offer both the TOTP setup and a passkey option."""
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

    client = TestClient(app)
    response = client.get("/login/enroll-enhanced-auth")

    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.text
    # Passkey card is present.
    assert "Register a passkey" in body
    assert 'id="register-passkey-btn"' in body
    # TOTP card is present (QR image + code input + submit).
    assert "Continue with TOTP" in body
    assert 'id="code"' in body
    # Both endpoint URLs are wired into the page data block.
    assert "/login/enroll-enhanced-auth/passkey/begin" in body
    assert "/login/enroll-enhanced-auth/passkey/complete" in body


# ---------------------------------------------------------------------------
# POST /login/enroll-enhanced-auth/passkey/begin
# ---------------------------------------------------------------------------


def test_passkey_begin_without_gate_returns_403(test_tenant):
    """Begin without the enrollment gate session key is rejected."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth/passkey/begin",
        json={},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json() == {"error": "no_pending_enrollment"}


def test_passkey_begin_missing_user_clears_gate(test_tenant, mocker):
    """If the pending user_id does not resolve, the gate is cleared and we 403."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    session_data: dict = {"pending_enhanced_enrollment_user_id": "ghost-user"}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.users_service.get_user_by_id_raw",
        return_value=None,
    )

    client = TestClient(app)
    response = client.post("/login/enroll-enhanced-auth/passkey/begin", json={})

    app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json() == {"error": "no_pending_enrollment"}
    assert "pending_enhanced_enrollment_user_id" not in session_data


def test_passkey_begin_returns_options(test_tenant, mocker):
    """With the gate set, begin returns the options envelope as JSON."""
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

    options_dict = {
        "rp": {"id": "tenant.example", "name": "Tenant"},
        "user": {"id": "abc", "name": "user@example.com", "displayName": "User"},
        "challenge": "Y2hhbGxlbmdl",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "excludeCredentials": [],
    }
    mocker.patch(
        "routers.auth.enhanced_enrollment.webauthn_service.begin_registration",
        return_value=BeginRegistrationResponse(public_key=options_dict),
    )

    client = TestClient(app)
    response = client.post("/login/enroll-enhanced-auth/passkey/begin", json={})

    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert "publicKey" in body
    assert body["publicKey"]["challenge"] == "Y2hhbGxlbmdl"
    # The gate key must remain set so the complete call can proceed.
    assert session_data.get("pending_enhanced_enrollment_user_id") == user_id


def test_passkey_begin_translates_validation_error(test_tenant, mocker):
    """A service ValidationError becomes a 400 with ``{"error": <code>}``."""
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
        "routers.auth.enhanced_enrollment.webauthn_service.begin_registration",
        side_effect=ValidationError(message="bad", code="user_not_found"),
    )

    client = TestClient(app)
    response = client.post("/login/enroll-enhanced-auth/passkey/begin", json={})

    app.dependency_overrides.clear()

    assert response.status_code == 400
    assert response.json() == {"error": "user_not_found"}


# ---------------------------------------------------------------------------
# POST /login/enroll-enhanced-auth/passkey/complete
# ---------------------------------------------------------------------------


def _passkey_response() -> PasskeyResponse:
    return PasskeyResponse(
        id="11111111-1111-1111-1111-111111111111",
        name="Test Passkey",
        transports=["internal"],
        backup_eligible=False,
        backup_state=False,
        created_at="2026-01-01T00:00:00+00:00",
        last_used_at=None,
    )


def _valid_complete_body() -> dict:
    return {
        "name": "Test Passkey",
        "response": {
            "id": "abc",
            "rawId": "YWJj",
            "type": "public-key",
            "clientExtensionResults": {},
            "response": {
                "clientDataJSON": "Y2xpZW50",
                "attestationObject": "YXR0ZXN0",
                "transports": ["internal"],
            },
        },
    }


def test_passkey_complete_without_gate_returns_403(test_tenant):
    """Complete without the enrollment gate session key is rejected."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth/passkey/complete",
        json=_valid_complete_body(),
    )

    app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json() == {"error": "no_pending_enrollment"}


def test_passkey_complete_with_invalid_response_returns_400(test_tenant, mocker):
    """A service ValidationError becomes a 400 with the stable code."""
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
        "routers.auth.enhanced_enrollment.webauthn_service.complete_registration",
        side_effect=ValidationError(message="bad", code="registration_verification_failed"),
    )

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth/passkey/complete",
        json=_valid_complete_body(),
    )

    app.dependency_overrides.clear()

    assert response.status_code == 400
    assert response.json() == {"error": "registration_verification_failed"}


def test_passkey_complete_success_completes_login(test_tenant, mocker):
    """Happy path: emits the enrollment event, clears the gate, completes login."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import RedirectResponse

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "test-user-id"
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
        return_value={"id": user_id, "role": "member", "mfa_method": "email"},
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.webauthn_service.complete_registration",
        return_value=CompleteRegistrationResponse(
            credential=_passkey_response(),
            backup_codes=["a-a-a-a", "b-b-b-b"],
        ),
    )
    mock_log = mocker.patch("routers.auth.enhanced_enrollment.log_event")
    mock_complete = mocker.patch(
        "routers.auth.enhanced_enrollment.complete_authenticated_login",
        return_value=RedirectResponse(url="/dashboard", status_code=303),
    )

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth/passkey/complete",
        json=_valid_complete_body(),
    )

    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["redirect_url"] == "/dashboard"
    assert body["backup_codes"] == ["a-a-a-a", "b-b-b-b"]

    # Enrollment-complete event emitted with method=passkey.
    mock_log.assert_called_once()
    kwargs = mock_log.call_args.kwargs
    assert kwargs["event_type"] == "user_enhanced_auth_enrolled"
    assert kwargs["metadata"] == {"method": "passkey"}
    assert kwargs["artifact_type"] == "user"
    assert kwargs["artifact_id"] == user_id

    # All three session gate keys cleared.
    assert "pending_enhanced_enrollment_user_id" not in session_data
    assert "pending_mfa_user_id" not in session_data
    assert "pending_mfa_method" not in session_data

    # Completion helper invoked with mfa_method=passkey.
    mock_complete.assert_called_once()
    assert mock_complete.call_args.kwargs["mfa_method"] == "passkey"


def test_passkey_complete_no_backup_codes_path(test_tenant, mocker):
    """If the service returns backup_codes=None, the response still carries a redirect."""
    from dependencies import get_tenant_id_from_request
    from fastapi.responses import RedirectResponse

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
        "routers.auth.enhanced_enrollment.webauthn_service.complete_registration",
        return_value=CompleteRegistrationResponse(
            credential=_passkey_response(),
            backup_codes=None,
        ),
    )
    mocker.patch("routers.auth.enhanced_enrollment.log_event")
    mocker.patch(
        "routers.auth.enhanced_enrollment.complete_authenticated_login",
        return_value=RedirectResponse(url="/dashboard", status_code=303),
    )

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth/passkey/complete",
        json=_valid_complete_body(),
    )

    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["redirect_url"] == "/dashboard"
    assert body["backup_codes"] is None


# ---------------------------------------------------------------------------
# Rate limit tests
# ---------------------------------------------------------------------------


def test_enroll_totp_verify_rate_limited_redirects(test_tenant, mocker):
    """POST /login/enroll-enhanced-auth returns 303 with error=too_many_attempts when rate limited."""
    from dependencies import get_tenant_id_from_request
    from services.exceptions import RateLimitError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "rate-limit-user"
    session_data: dict = {"pending_enhanced_enrollment_user_id": user_id}
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )
    mocker.patch(
        "routers.auth.enhanced_enrollment.ratelimit.prevent",
        side_effect=RateLimitError(message="rate limited", limit=5, timespan=300, retry_after=300),
    )

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth",
        data={"code": "123456"},
        follow_redirects=False,
    )

    app.dependency_overrides.clear()

    assert response.status_code == 303
    assert "too_many_attempts" in response.headers["location"]


def test_enroll_passkey_begin_rate_limited_returns_429(test_tenant, mocker):
    """POST /login/enroll-enhanced-auth/passkey/begin returns 429 when rate limited."""
    from dependencies import get_tenant_id_from_request
    from services.exceptions import RateLimitError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "rate-limit-user"
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
        "routers.auth.enhanced_enrollment.ratelimit.prevent",
        side_effect=RateLimitError(message="rate limited", limit=10, timespan=300, retry_after=300),
    )

    client = TestClient(app)
    response = client.post("/login/enroll-enhanced-auth/passkey/begin", json={})

    app.dependency_overrides.clear()

    assert response.status_code == 429
    assert response.json() == {"error": "too_many_requests"}


def test_enroll_passkey_complete_rate_limited_returns_429(test_tenant, mocker):
    """POST /login/enroll-enhanced-auth/passkey/complete returns 429 when rate limited."""
    from dependencies import get_tenant_id_from_request
    from services.exceptions import RateLimitError

    app.dependency_overrides[get_tenant_id_from_request] = lambda: test_tenant["id"]

    user_id = "rate-limit-user"
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
        "routers.auth.enhanced_enrollment.ratelimit.prevent",
        side_effect=RateLimitError(message="rate limited", limit=10, timespan=300, retry_after=300),
    )

    client = TestClient(app)
    response = client.post(
        "/login/enroll-enhanced-auth/passkey/complete",
        json=_valid_complete_body(),
    )

    app.dependency_overrides.clear()

    assert response.status_code == 429
    assert response.json() == {"error": "too_many_requests"}
