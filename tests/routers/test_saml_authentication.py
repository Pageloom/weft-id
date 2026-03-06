"""Tests for routers/saml/authentication.py - SAML ACS and login error paths.

Covers metadata endpoints, login initiation, and ACS error handling
for both per-IdP and legacy (issuer-based) flows.
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
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
    """Test ACS handles signature validation error."""
    mock_process.side_effect = ValidationError("Invalid signature on response")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    # Check error_type is signature_error
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "signature_error"


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
    """Test ACS handles generic validation error."""
    mock_process.side_effect = ValidationError("Missing required attribute")
    mock_debug.return_value = HTMLResponse(content="<html>error</html>")

    response = tenant_client.post(
        f"/saml/acs/{uuid4()}",
        data={"SAMLResponse": "base64data", "RelayState": "/dashboard"},
    )
    assert response.status_code == 200
    call_kwargs = mock_debug.call_args[1]
    assert call_kwargs["error_type"] == "invalid_response"


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
    mock_send.assert_called_once_with("user@example.com", "123456")


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
