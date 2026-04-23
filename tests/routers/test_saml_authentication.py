"""Tests for routers/saml/authentication.py - SAML ACS and login error paths.

Covers metadata endpoints, login initiation, and ACS error handling
for both per-IdP and legacy (issuer-based) flows.
"""

import os
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient
from main import app
from services.exceptions import NotFoundError, ServiceError, ValidationError


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def tenant_id(test_tenant):
    """Shorthand for test_tenant['id']."""
    return test_tenant["id"]


@pytest.fixture
def tenant_client(test_tenant, test_tenant_host):
    """Client with tenant_id override."""
    from dependencies import get_tenant_id_from_request

    app.dependency_overrides[get_tenant_id_from_request] = lambda: str(test_tenant["id"])
    client = TestClient(app)
    yield client
    # cleared by autouse fixture


# =============================================================================
# Per-IdP SP Metadata Tests
# =============================================================================


def test_per_idp_sp_metadata_invalid_uuid(tenant_client):
    """Test per-IdP metadata returns 404 for invalid UUID."""
    response = tenant_client.get("/saml/metadata/not-a-uuid")
    assert response.status_code == 404


@patch("routers.saml.authentication.saml_service.get_idp_sp_metadata_xml")
def test_per_idp_sp_metadata_not_found(mock_get, tenant_client):
    """Test per-IdP metadata returns 404 when SP cert not configured."""
    idp_id = str(uuid4())
    mock_get.side_effect = NotFoundError("Not configured")

    response = tenant_client.get(f"/saml/metadata/{idp_id}")
    assert response.status_code == 404
    assert "not configured" in response.text.lower()


@patch("routers.saml.authentication.saml_service.get_idp_sp_metadata_xml")
def test_per_idp_sp_metadata_success(mock_get, tenant_client):
    """Test per-IdP metadata returns XML content."""
    idp_id = str(uuid4())
    mock_get.return_value = "<EntityDescriptor>...</EntityDescriptor>"

    response = tenant_client.get(f"/saml/metadata/{idp_id}")
    assert response.status_code == 200
    assert "application/xml" in response.headers["content-type"]


# =============================================================================
# Public Trust Page Tests
# =============================================================================


def test_public_trust_page_invalid_uuid(tenant_client):
    """Test public trust page returns 404 for invalid UUID."""
    response = tenant_client.get("/pub/idp/not-a-uuid")
    assert response.status_code == 404


@patch("routers.saml.authentication.saml_service.get_public_trust_info")
def test_public_trust_page_not_found(mock_get, tenant_client):
    """Test public trust page returns 404 when IdP not found."""
    idp_id = str(uuid4())
    mock_get.side_effect = NotFoundError("IdP not found")

    response = tenant_client.get(f"/pub/idp/{idp_id}")
    assert response.status_code == 404


@patch("routers.saml.authentication.get_branding_for_template")
@patch("routers.saml.authentication.saml_service.get_idp_sp_metadata_xml")
@patch("routers.saml.authentication.saml_service.get_public_trust_info")
@patch("routers.saml.authentication.templates.TemplateResponse")
def test_public_trust_page_metadata_exception_silenced(
    mock_template,
    mock_trust,
    mock_metadata,
    mock_branding,
    tenant_client,
):
    """Test public trust page silences metadata exceptions."""
    idp_id = str(uuid4())
    mock_trust.return_value = {"entity_id": "test", "acs_url": "test"}
    mock_metadata.side_effect = ServiceError("Metadata error")
    mock_branding.return_value = {"site_title": "Test"}
    mock_template.return_value = HTMLResponse(content="<html>trust</html>")

    response = tenant_client.get(f"/pub/idp/{idp_id}")
    assert response.status_code == 200


# =============================================================================
# SAML Login Tests
# =============================================================================


@patch("routers.saml.authentication.saml_service.build_authn_request")
def test_saml_login_success(mock_build, tenant_client):
    """Test SAML login redirects to IdP."""
    idp_id = str(uuid4())
    mock_build.return_value = ("https://idp.example.com/sso?SAMLRequest=...", "req-123")

    response = tenant_client.get(f"/saml/login/{idp_id}", follow_redirects=False)
    assert response.status_code == 303
    assert "idp.example.com" in response.headers["location"]


@patch("routers.saml.authentication.templates.TemplateResponse")
@patch("routers.saml.authentication.saml_service.build_authn_request")
def test_saml_login_not_found(mock_build, mock_template, tenant_client):
    """Test SAML login with unknown IdP shows error page."""
    idp_id = str(uuid4())
    mock_build.side_effect = NotFoundError("IdP not found")
    mock_template.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.get(f"/saml/login/{idp_id}")
    assert response.status_code == 200
    # Verify error_type in template context
    context = mock_template.call_args[0][2]
    assert context["error_type"] == "idp_not_found"


@patch("routers.saml.authentication.templates.TemplateResponse")
@patch("routers.saml.authentication.saml_service.build_authn_request")
def test_saml_login_service_error(mock_build, mock_template, tenant_client):
    """Test SAML login with service error shows config error page."""
    idp_id = str(uuid4())
    mock_build.side_effect = ServiceError("SAML misconfiguration")
    mock_template.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.get(f"/saml/login/{idp_id}")
    assert response.status_code == 200
    context = mock_template.call_args[0][2]
    assert context["error_type"] == "configuration_error"


# =============================================================================
# Per-IdP ACS Error Handlers
# =============================================================================


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_validation_error_signature(
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test ACS maps signature validation errors to auth_failed (no oracle signal)."""
    mock_process.side_effect = ValidationError("Invalid signature on response")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "auth_failed"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_validation_error_expired(
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test ACS handles expired response error."""
    mock_process.side_effect = ValidationError("Response has expired")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "expired"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_validation_error_generic(
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test ACS maps generic validation errors to auth_failed (no oracle signal)."""
    mock_process.side_effect = ValidationError("Missing required attribute")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "auth_failed"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_user_not_found(
    mock_process,
    mock_auth,
    mock_debug,
    tenant_client,
):
    """Test ACS handles user not found error."""
    mock_process.return_value = MagicMock()
    mock_auth.side_effect = NotFoundError(
        message="User not found",
        code="user_not_found",
        details={"email": "unknown@example.com"},
    )
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "user_not_found"
    assert call_kwargs["error_detail"] == "unknown@example.com"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_idp_not_found(
    mock_process,
    mock_auth,
    mock_debug,
    tenant_client,
):
    """Test ACS handles IdP not found error (non-user code)."""
    mock_process.return_value = MagicMock()
    mock_auth.side_effect = NotFoundError(
        message="IdP not found",
        code="idp_not_found",
    )
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "idp_not_found"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_service_error(
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test ACS handles generic service error."""
    mock_process.side_effect = ServiceError("Configuration problem")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "configuration_error"


# =============================================================================
# Per-IdP ACS Success Paths
# =============================================================================


@patch("routers.saml.authentication.users_service.update_last_login")
@patch("routers.saml.authentication.regenerate_session")
@patch("routers.saml.authentication.settings_service.get_session_settings")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_success_no_mfa(
    mock_process,
    mock_auth,
    mock_settings,
    mock_regen,
    mock_login,
    tenant_client,
):
    """Test ACS success without MFA requirement."""
    mock_result = MagicMock()
    mock_result.requires_mfa = False
    mock_result.idp_id = str(uuid4())
    mock_result.attributes.name_id = "user@example.com"
    mock_result.name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    mock_result.session_index = "session-123"
    mock_result.slo_url = None
    mock_process.return_value = mock_result

    user_id = str(uuid4())
    mock_auth.return_value = {"id": user_id, "mfa_method": None}
    mock_settings.return_value = None

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    mock_regen.assert_called_once()
    mock_login.assert_called_once()


@patch("routers.saml.authentication.send_mfa_code_email")
@patch("routers.saml.authentication.create_email_otp")
@patch("routers.saml.authentication.emails_service.get_primary_email")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_mfa_email_required(
    mock_process,
    mock_auth,
    mock_email,
    mock_otp,
    mock_send,
    tenant_client,
):
    """Test ACS redirects to MFA verify when email MFA required."""
    mock_result = MagicMock()
    mock_result.requires_mfa = True
    mock_process.return_value = mock_result

    user_id = str(uuid4())
    mock_auth.return_value = {"id": user_id, "mfa_method": "email"}
    mock_email.return_value = "user@example.com"
    mock_otp.return_value = "123456"

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify"
    mock_send.assert_called_once_with("user@example.com", "123456", tenant_id=ANY)


@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_mfa_totp_required(
    mock_process,
    mock_auth,
    tenant_client,
):
    """Test ACS redirects to MFA verify when TOTP MFA required (no email sent)."""
    mock_result = MagicMock()
    mock_result.requires_mfa = True
    mock_process.return_value = mock_result

    user_id = str(uuid4())
    mock_auth.return_value = {"id": user_id, "mfa_method": "totp"}

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify"


@patch("routers.saml.authentication.send_mfa_code_email")
@patch("routers.saml.authentication.create_email_otp")
@patch("routers.saml.authentication.emails_service.get_primary_email")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_mfa_enforced_when_user_has_no_mfa_method(
    mock_process,
    mock_auth,
    mock_email,
    mock_otp,
    mock_send,
    tenant_client,
):
    """MFA enforced even when user has no mfa_method (defaults to email OTP)."""
    mock_result = MagicMock()
    mock_result.requires_mfa = True
    mock_process.return_value = mock_result

    user_id = str(uuid4())
    mock_auth.return_value = {"id": user_id, "mfa_method": None}
    mock_email.return_value = "user@example.com"
    mock_otp.return_value = "111222"

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify"
    mock_send.assert_called_once_with("user@example.com", "111222", tenant_id=ANY)


# =============================================================================
# Legacy ACS (Issuer-Based) Error Handlers
# =============================================================================


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_no_issuer(
    mock_extract,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS handles missing issuer."""
    mock_extract.return_value = None
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "invalid_response"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_issuer_not_found(
    mock_extract,
    mock_get,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS handles unknown issuer."""
    mock_extract.return_value = "https://unknown-idp.example.com"
    mock_get.side_effect = NotFoundError("IdP not found")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "idp_not_found"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_idp_disabled(
    mock_extract,
    mock_get,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS handles disabled IdP service error."""
    mock_extract.return_value = "https://idp.example.com"
    mock_get.side_effect = ServiceError("IdP is disabled")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "idp_disabled"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_service_error_disabled(
    mock_extract,
    mock_get,
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS service error with 'disabled' in message."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp
    mock_process.side_effect = ServiceError("IdP is disabled for this tenant")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "idp_disabled"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_service_error_generic(
    mock_extract,
    mock_get,
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS generic service error."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp
    mock_process.side_effect = ServiceError("Certificate mismatch")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "configuration_error"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_user_not_found(
    mock_extract,
    mock_get,
    mock_process,
    mock_auth,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS user not found."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp
    mock_process.return_value = MagicMock()
    mock_auth.side_effect = NotFoundError(
        message="User not found",
        code="user_not_found",
        details={"email": "missing@example.com"},
    )
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "user_not_found"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_idp_mismatch(
    mock_extract,
    mock_get,
    mock_process,
    mock_debug,
    tenant_client,
    mocker,
):
    """Test legacy ACS IdP mismatch detection."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id-from-issuer"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp

    # Simulate a stored session with a different IdP
    session_data = {
        "saml_request_id": "req-123",
        "saml_idp_id": "different-idp-id",
    }
    mocker.patch(
        "starlette.requests.Request.session",
        new_callable=lambda: property(lambda self: session_data),
    )

    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "invalid_response"
    assert "mismatch" in call_kwargs["error_detail"].lower()


# =============================================================================
# Legacy ACS Success Paths
# =============================================================================


@patch("routers.saml.authentication.users_service.update_last_login")
@patch("routers.saml.authentication.regenerate_session")
@patch("routers.saml.authentication.settings_service.get_session_settings")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_success(
    mock_extract,
    mock_get,
    mock_process,
    mock_auth,
    mock_settings,
    mock_regen,
    mock_login,
    tenant_client,
):
    """Test legacy ACS success completes login."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp

    mock_result = MagicMock()
    mock_result.requires_mfa = False
    mock_result.idp_id = "idp-id"
    mock_result.attributes.name_id = "user@example.com"
    mock_result.name_id_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    mock_result.session_index = "session-123"
    mock_result.slo_url = None
    mock_process.return_value = mock_result

    user_id = str(uuid4())
    mock_auth.return_value = {"id": user_id, "mfa_method": None}
    mock_settings.return_value = {"persistent_sessions": False}

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    mock_regen.assert_called_once()
    mock_login.assert_called_once()


@patch("routers.saml.authentication.users_service.update_last_login")
@patch("routers.saml.authentication.regenerate_session")
@patch("routers.saml.authentication.settings_service.get_session_settings")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_with_session_timeout(
    mock_extract,
    mock_get,
    mock_process,
    mock_auth,
    mock_settings,
    mock_regen,
    mock_login,
    tenant_client,
):
    """Test legacy ACS with custom session timeout."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp

    mock_result = MagicMock()
    mock_result.requires_mfa = False
    mock_result.idp_id = "idp-id"
    mock_result.attributes.name_id = "user@example.com"
    mock_result.name_id_format = "emailAddress"
    mock_result.session_index = "session-123"
    mock_result.slo_url = None
    mock_process.return_value = mock_result

    user_id = str(uuid4())
    mock_auth.return_value = {"id": user_id, "mfa_method": None}
    mock_settings.return_value = {
        "persistent_sessions": True,
        "session_timeout_seconds": 3600,
    }

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/app"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    # Verify session timeout was passed
    regen_call = mock_regen.call_args
    assert regen_call[0][2] == 3600  # max_age


# =============================================================================
# Rate Limiting
# =============================================================================


@patch("routers.saml.authentication.ratelimit")
def test_per_idp_acs_rate_limited(mock_ratelimit, tenant_client):
    """Test per-IdP ACS returns 429 when rate limit exceeded."""
    from services.exceptions import RateLimitError

    mock_ratelimit.prevent.side_effect = RateLimitError(
        message="Too many requests", limit=20, timespan=300, retry_after=300
    )

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 429
    assert "too many" in response.text.lower()


@patch("routers.saml.authentication.ratelimit")
def test_legacy_acs_rate_limited(mock_ratelimit, tenant_client):
    """Test legacy ACS returns 429 when rate limit exceeded."""
    from services.exceptions import RateLimitError

    mock_ratelimit.prevent.side_effect = RateLimitError(
        message="Too many requests", limit=20, timespan=300, retry_after=300
    )

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 429
    assert "too many" in response.text.lower()


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.ratelimit")
def test_per_idp_acs_rate_limit_not_triggered(
    mock_ratelimit, mock_process, mock_debug, tenant_client
):
    """Test per-IdP ACS proceeds normally when under rate limit."""
    mock_ratelimit.prevent.return_value = 1  # Under limit
    mock_process.side_effect = ValidationError("Missing attribute")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    mock_ratelimit.prevent.assert_called_once()
    call_args = mock_ratelimit.prevent.call_args
    assert "tenant:{tenant_id}" in call_args[0][0]
    assert "tenant_id" in call_args[1]


@patch("routers.saml.authentication.ratelimit")
def test_acs_test_flow_bypasses_rate_limit(mock_ratelimit, tenant_client):
    """Test flow (RelayState __test__:) is not subject to rate limiting."""
    from unittest.mock import patch as _patch

    with _patch("routers.saml.authentication._handle_saml_test_response") as mock_handle:
        mock_handle.return_value = HTMLResponse(content="<html>test result</html>")
        response = tenant_client.post(
            f"/saml/acs/{uuid4()}",
            data={"SAMLResponse": "base64data", "RelayState": "__test__:some-idp-id"},
        )

    assert response.status_code == 200
    mock_ratelimit.prevent.assert_not_called()


# =============================================================================
# CBC Padding Oracle Mitigation: error_detail NOT leaked to browser
# =============================================================================


def test_store_saml_debug_does_not_leak_error_detail(tenant_client):
    """Verify store_saml_debug_and_respond stores error_detail but does NOT pass it to template.

    This is the CBC padding oracle mitigation: detailed error messages (which
    could distinguish decryption failures from other errors) are stored for
    admin review but never rendered in the user-facing error page.
    """
    from routers.saml._helpers import store_saml_debug_and_respond

    with (
        patch("routers.saml._helpers.saml_service.store_saml_debug_entry") as mock_store,
        patch("routers.saml._helpers.templates.TemplateResponse") as mock_template,
    ):
        mock_template.return_value = HTMLResponse(content="<html>error</html>")
        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"
        mock_request.headers = {"user-agent": "test-agent"}

        store_saml_debug_and_respond(
            request=mock_request,
            tenant_id="tenant-123",
            error_type="auth_failed",
            error_detail="Padding is invalid and cannot be removed",
            saml_response_b64="base64data",
            idp_id="idp-123",
        )

        # error_detail IS stored in debug entry for admin review
        store_kwargs = mock_store.call_args[1]
        assert store_kwargs["error_detail"] == "Padding is invalid and cannot be removed"

        # error_detail is NOT in the template context (oracle mitigation)
        template_context = mock_template.call_args[0][2]
        assert "error_detail" not in template_context
        assert template_context["error_type"] == "auth_failed"


def test_saml_login_error_includes_error_detail_in_template(tenant_client):
    """Login initiation errors DO include error_detail (not ACS, no oracle risk).

    Login errors are from building the AuthnRequest, not from processing
    encrypted SAML responses, so there is no padding oracle concern.
    """
    idp_id = str(uuid4())

    with (
        patch(
            "routers.saml.authentication.saml_service.build_authn_request",
            side_effect=NotFoundError("IdP config-xyz not found"),
        ),
        patch("routers.saml.authentication.templates.TemplateResponse") as mock_template,
    ):
        mock_template.return_value = HTMLResponse(content="<html>error</html>")
        tenant_client.get(f"/saml/login/{idp_id}")

        context = mock_template.call_args[0][2]
        assert "error_detail" in context
        assert context["error_detail"] == "IdP config-xyz not found"


# =============================================================================
# Per-IdP ACS: missing_attribute error type
# =============================================================================


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_missing_email_attribute(
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test ACS maps saml_missing_email code to missing_attribute error type."""
    mock_process.side_effect = ValidationError(
        "Email attribute not found in SAML assertion",
        code="saml_missing_email",
    )
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "missing_attribute"


# =============================================================================
# Per-IdP ACS: session settings branches
# =============================================================================


@patch("routers.saml.authentication.users_service.update_last_login")
@patch("routers.saml.authentication.regenerate_session")
@patch("routers.saml.authentication.settings_service.get_session_settings")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_non_persistent_session(
    mock_process,
    mock_auth,
    mock_settings,
    mock_regen,
    mock_login,
    tenant_client,
):
    """Test ACS with non-persistent sessions sets max_age to None."""
    mock_result = MagicMock()
    mock_result.requires_mfa = False
    mock_result.idp_id = str(uuid4())
    mock_result.attributes.name_id = "user@example.com"
    mock_result.name_id_format = "emailAddress"
    mock_result.session_index = "session-123"
    mock_result.slo_url = None
    mock_process.return_value = mock_result

    mock_auth.return_value = {"id": str(uuid4()), "mfa_method": None}
    mock_settings.return_value = {"persistent_sessions": False}

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    regen_call = mock_regen.call_args
    assert regen_call[0][2] is None  # max_age is None for non-persistent


@patch("routers.saml.authentication.users_service.update_last_login")
@patch("routers.saml.authentication.regenerate_session")
@patch("routers.saml.authentication.settings_service.get_session_settings")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_custom_session_timeout(
    mock_process,
    mock_auth,
    mock_settings,
    mock_regen,
    mock_login,
    tenant_client,
):
    """Test ACS with custom session timeout passes it as max_age."""
    mock_result = MagicMock()
    mock_result.requires_mfa = False
    mock_result.idp_id = str(uuid4())
    mock_result.attributes.name_id = "user@example.com"
    mock_result.name_id_format = "emailAddress"
    mock_result.session_index = "session-123"
    mock_result.slo_url = None
    mock_process.return_value = mock_result

    mock_auth.return_value = {"id": str(uuid4()), "mfa_method": None}
    mock_settings.return_value = {"persistent_sessions": True, "session_timeout_seconds": 7200}

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    regen_call = mock_regen.call_args
    assert regen_call[0][2] == 7200


# =============================================================================
# Per-IdP ACS: pending SSO context preservation
# =============================================================================


@patch("routers.saml.authentication.users_service.update_last_login")
@patch("routers.saml.authentication.regenerate_session")
@patch("routers.saml.authentication.settings_service.get_session_settings")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
def test_per_idp_acs_preserves_pending_sso(
    mock_process,
    mock_auth,
    mock_settings,
    mock_regen,
    mock_login,
    tenant_client,
    mocker,
):
    """Test ACS preserves pending SSO context through session regeneration."""
    mock_result = MagicMock()
    mock_result.requires_mfa = False
    mock_result.idp_id = str(uuid4())
    mock_result.attributes.name_id = "user@example.com"
    mock_result.name_id_format = "emailAddress"
    mock_result.session_index = "session-123"
    mock_result.slo_url = None
    mock_process.return_value = mock_result

    mock_auth.return_value = {"id": str(uuid4()), "mfa_method": None}
    mock_settings.return_value = None

    # Mock the pending SSO helpers (local imports from routers.saml_idp._helpers)
    mock_extract = mocker.patch(
        "routers.saml_idp._helpers.extract_pending_sso",
        return_value={"pending_sp_entity_id": "https://sp.example.com"},
    )
    mocker.patch(
        "routers.saml_idp._helpers.get_post_auth_redirect",
        return_value="/saml/idp/consent",
    )

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/saml/idp/consent"
    mock_extract.assert_called_once()
    # Verify pending SSO data was included in session regeneration
    regen_kwargs = mock_regen.call_args[1]
    assert "pending_sp_entity_id" in regen_kwargs["additional_data"]


# =============================================================================
# Legacy ACS: missing_attribute and expired error types
# =============================================================================


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_missing_email_attribute(
    mock_extract,
    mock_get,
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS maps saml_missing_email to missing_attribute."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp
    mock_process.side_effect = ValidationError(
        "Email attribute not found",
        code="saml_missing_email",
    )
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "missing_attribute"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_generic_validation_error(
    mock_extract,
    mock_get,
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS maps generic validation errors to auth_failed."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp
    mock_process.side_effect = ValidationError("Invalid signature on response")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "auth_failed"


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_expired_response(
    mock_extract,
    mock_get,
    mock_process,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS maps expired response to 'expired' error type."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp
    mock_process.side_effect = ValidationError("Response has expired")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "expired"


# =============================================================================
# Legacy ACS: non-user NotFoundError (idp_not_found from authenticate_via_saml)
# =============================================================================


@patch("routers.saml.authentication.store_saml_debug_and_respond")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_non_user_not_found_error(
    mock_extract,
    mock_get,
    mock_process,
    mock_auth,
    mock_debug,
    tenant_client,
):
    """Test legacy ACS maps non-user NotFoundError to idp_not_found."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp
    mock_process.return_value = MagicMock()
    mock_auth.side_effect = NotFoundError(
        message="IdP configuration not found",
        code="idp_not_found",
    )
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "idp_not_found"


# =============================================================================
# Legacy ACS: MFA email flow
# =============================================================================


@patch("routers.saml.authentication.send_mfa_code_email")
@patch("routers.saml.authentication.create_email_otp")
@patch("routers.saml.authentication.emails_service.get_primary_email")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_mfa_email_required(
    mock_extract,
    mock_get,
    mock_process,
    mock_auth,
    mock_email,
    mock_otp,
    mock_send,
    tenant_client,
):
    """Test legacy ACS redirects to MFA verify and sends email OTP."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp

    mock_result = MagicMock()
    mock_result.requires_mfa = True
    mock_process.return_value = mock_result

    user_id = str(uuid4())
    mock_auth.return_value = {"id": user_id, "mfa_method": "email"}
    mock_email.return_value = "user@example.com"
    mock_otp.return_value = "654321"

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify"
    mock_send.assert_called_once_with("user@example.com", "654321", tenant_id=ANY)


@patch("routers.saml.authentication.send_mfa_code_email")
@patch("routers.saml.authentication.create_email_otp")
@patch("routers.saml.authentication.emails_service.get_primary_email")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_mfa_enforced_when_user_has_no_mfa_method(
    mock_extract,
    mock_get,
    mock_process,
    mock_auth,
    mock_email,
    mock_otp,
    mock_send,
    tenant_client,
):
    """Legacy ACS enforces MFA even when user has no mfa_method configured."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp

    mock_result = MagicMock()
    mock_result.requires_mfa = True
    mock_process.return_value = mock_result

    user_id = str(uuid4())
    mock_auth.return_value = {"id": user_id, "mfa_method": None}
    mock_email.return_value = "user@example.com"
    mock_otp.return_value = "333444"

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/mfa/verify"
    mock_send.assert_called_once_with("user@example.com", "333444", tenant_id=ANY)


# =============================================================================
# Legacy ACS: default session settings (None -> 30 day max_age)
# =============================================================================


@patch("routers.saml.authentication.users_service.update_last_login")
@patch("routers.saml.authentication.regenerate_session")
@patch("routers.saml.authentication.settings_service.get_session_settings")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_default_session_30_days(
    mock_extract,
    mock_get,
    mock_process,
    mock_auth,
    mock_settings,
    mock_regen,
    mock_login,
    tenant_client,
):
    """Test legacy ACS uses 30-day max_age when no session settings configured."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp

    mock_result = MagicMock()
    mock_result.requires_mfa = False
    mock_result.idp_id = "idp-id"
    mock_result.attributes.name_id = "user@example.com"
    mock_result.name_id_format = "emailAddress"
    mock_result.session_index = "session-123"
    mock_result.slo_url = None
    mock_process.return_value = mock_result

    mock_auth.return_value = {"id": str(uuid4()), "mfa_method": None}
    mock_settings.return_value = None  # No settings -> defaults

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    regen_call = mock_regen.call_args
    assert regen_call[0][2] == 30 * 24 * 3600  # 30 days


# =============================================================================
# Legacy ACS: pending SSO context preservation
# =============================================================================


@patch("routers.saml.authentication.users_service.update_last_login")
@patch("routers.saml.authentication.regenerate_session")
@patch("routers.saml.authentication.settings_service.get_session_settings")
@patch("routers.saml.authentication.saml_service.authenticate_via_saml")
@patch("routers.saml.authentication.saml_service.process_saml_response")
@patch("routers.saml.authentication.saml_service.get_idp_by_issuer")
@patch("routers.saml.authentication.extract_issuer_from_response")
def test_legacy_acs_preserves_pending_sso(
    mock_extract,
    mock_get,
    mock_process,
    mock_auth,
    mock_settings,
    mock_regen,
    mock_login,
    tenant_client,
    mocker,
):
    """Test legacy ACS preserves pending SSO context through session regeneration."""
    mock_extract.return_value = "https://idp.example.com"
    mock_idp = MagicMock()
    mock_idp.id = "idp-id"
    mock_idp.name = "Test IdP"
    mock_get.return_value = mock_idp

    mock_result = MagicMock()
    mock_result.requires_mfa = False
    mock_result.idp_id = "idp-id"
    mock_result.attributes.name_id = "user@example.com"
    mock_result.name_id_format = "emailAddress"
    mock_result.session_index = "session-123"
    mock_result.slo_url = None
    mock_process.return_value = mock_result

    mock_auth.return_value = {"id": str(uuid4()), "mfa_method": None}
    mock_settings.return_value = None

    mock_pending = mocker.patch(
        "routers.saml_idp._helpers.extract_pending_sso",
        return_value={"pending_sp_entity_id": "https://downstream.example.com"},
    )
    mocker.patch(
        "routers.saml_idp._helpers.get_post_auth_redirect",
        return_value="/saml/idp/consent",
    )

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/saml/idp/consent"
    mock_pending.assert_called_once()
    regen_kwargs = mock_regen.call_args[1]
    assert "pending_sp_entity_id" in regen_kwargs["additional_data"]


# =============================================================================
# Test flow handler
# =============================================================================


@patch("routers.saml.authentication.templates.TemplateResponse")
@patch("routers.saml.authentication.saml_service.get_idp_for_saml_login")
@patch("routers.saml.authentication.saml_service.process_saml_test_response")
@patch("routers.saml.authentication.ratelimit")
def test_per_idp_acs_test_flow_invokes_handler(
    mock_ratelimit,
    mock_test_response,
    mock_get_idp,
    mock_template,
    tenant_client,
):
    """Test that __test__: RelayState triggers the test flow handler."""
    idp_id = str(uuid4())
    mock_test_response.return_value = {"status": "success", "attributes": {}}
    mock_idp = MagicMock()
    mock_idp.name = "Test IdP"
    mock_get_idp.return_value = mock_idp
    mock_template.return_value = HTMLResponse(content="<html>test result</html>")

    response = tenant_client.post(
        f"/saml/acs/{idp_id}",
        data={"SAMLResponse": "base64data", "RelayState": f"__test__:{idp_id}"},
    )
    assert response.status_code == 200
    mock_test_response.assert_called_once()
    # Rate limiting should not be invoked for test flows
    mock_ratelimit.prevent.assert_not_called()


@patch("routers.saml.authentication.templates.TemplateResponse")
@patch("routers.saml.authentication.saml_service.get_idp_for_saml_login")
@patch("routers.saml.authentication.saml_service.process_saml_test_response")
@patch("routers.saml.authentication.ratelimit")
def test_legacy_acs_test_flow_invokes_handler(
    mock_ratelimit,
    mock_test_response,
    mock_get_idp,
    mock_template,
    tenant_client,
):
    """Test that legacy ACS __test__: RelayState triggers the test flow handler."""
    idp_id = str(uuid4())
    mock_test_response.return_value = {"status": "success", "attributes": {}}
    mock_idp = MagicMock()
    mock_idp.name = "Test IdP"
    mock_get_idp.return_value = mock_idp
    mock_template.return_value = HTMLResponse(content="<html>test result</html>")

    response = tenant_client.post(
        "/saml/acs",
        data={"SAMLResponse": "base64data", "RelayState": f"__test__:{idp_id}"},
    )
    assert response.status_code == 200
    mock_test_response.assert_called_once()
    mock_ratelimit.prevent.assert_not_called()


@patch("routers.saml.authentication.templates.TemplateResponse")
@patch("routers.saml.authentication.saml_service.get_idp_for_saml_login")
@patch("routers.saml.authentication.saml_service.process_saml_test_response")
@patch("routers.saml.authentication.ratelimit")
def test_test_flow_idp_name_fallback(
    mock_ratelimit,
    mock_test_response,
    mock_get_idp,
    mock_template,
    tenant_client,
):
    """Test flow falls back to 'Unknown IdP' when IdP lookup fails."""
    idp_id = str(uuid4())
    mock_test_response.return_value = {"status": "success"}
    mock_get_idp.side_effect = ServiceError("IdP not found")
    mock_template.return_value = HTMLResponse(content="<html>test result</html>")

    response = tenant_client.post(
        f"/saml/acs/{idp_id}",
        data={"SAMLResponse": "base64data", "RelayState": f"__test__:{idp_id}"},
    )
    assert response.status_code == 200
    # Template should receive "Unknown IdP" as fallback name
    call_args = mock_template.call_args
    ctx = call_args[0][2] if len(call_args[0]) > 2 else call_args[1]
    assert ctx.get("idp_name") == "Unknown IdP"
