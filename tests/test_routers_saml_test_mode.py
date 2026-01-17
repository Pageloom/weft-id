"""SAML test mode tests.

Tests the admin connection testing feature that allows super admins
to test SAML IdP configuration without creating actual sessions.
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from starlette.responses import HTMLResponse


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def test_idp(test_tenant, test_super_admin_user, fast_sp_certificate):
    """Create a test SAML IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Test IdP",
        provider_type="okta",
        entity_id="https://test.example.com/entity",
        sso_url="https://test.example.com/sso",
        certificate_pem="""-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1
ZZK9p7a2W3F8V3fVT3Z7m7bZa5W3WwJGfGQ7Pt6aQcBK9TN9bvG3a5mV6K9CQGZV
8Qm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3
F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5
Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Y
n3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
ADsT4qF3dPQ8QfQq9Y7q8f5Y5L3F8K9cQm7Yn3a5Y5L3F8K9cQm7Yn3a5Y5L3F8K
-----END CERTIFICATE-----""",
        is_enabled=True,
    )

    idp = saml_service.create_identity_provider(
        requesting_user,
        data,
        "https://test.example.com",
    )

    return idp


def test_acs_test_mode_success(client, test_tenant_host, test_idp):
    """Test POST ACS in test mode shows assertion details."""
    with patch("routers.saml.saml_service.process_saml_test_response") as mock_process:
        with patch("routers.saml.saml_service.get_idp_for_saml_login") as mock_get_idp:
            with patch("routers.saml.templates.TemplateResponse") as mock_template:
                # Mock successful test result
                from schemas.saml import SAMLTestResult

                mock_process.return_value = SAMLTestResult(
                    success=True,
                    name_id="test@example.com",
                    attributes={"email": ["test@example.com"]},
                )

                # Mock IdP lookup
                idp_mock = MagicMock()
                idp_mock.name = "Test IdP"
                mock_get_idp.return_value = idp_mock

                # Mock template response
                mock_template.return_value = HTMLResponse(
                    content="<html>Test success</html>",
                    status_code=200,
                )

                response = client.post(
                    "/saml/acs",
                    headers={"Host": test_tenant_host},
                    data={
                        "SAMLResponse": "fake-base64-response",
                        "RelayState": f"__test__:{test_idp.id}",
                    },
                )

                assert response.status_code == 200
                assert mock_process.called
                assert mock_template.called
                # Should render test result template
                call_args = mock_template.call_args[0]
                assert "saml_test_result.html" in str(call_args)


def test_acs_test_mode_missing_test_context(client, test_tenant_host, test_idp):
    """Test POST ACS test mode when test context missing from session."""
    with patch("routers.saml.saml_service.process_saml_test_response") as mock_process:
        with patch("routers.saml.saml_service.get_idp_for_saml_login") as mock_get_idp:
            with patch("routers.saml.templates.TemplateResponse") as mock_template:
                # Mock process being called without stored request_id (None)
                from schemas.saml import SAMLTestResult

                mock_process.return_value = SAMLTestResult(
                    success=True,
                    name_id="test@example.com",
                )

                idp_mock = MagicMock()
                idp_mock.name = "Test IdP"
                mock_get_idp.return_value = idp_mock

                mock_template.return_value = HTMLResponse(
                    content="<html>Test result</html>",
                    status_code=200,
                )

                response = client.post(
                    "/saml/acs",
                    headers={"Host": test_tenant_host},
                    data={
                        "SAMLResponse": "fake-base64-response",
                        "RelayState": f"__test__:{test_idp.id}",
                    },
                )

                # Should still process (passes None as expected_request_id)
                assert response.status_code == 200
                assert mock_process.called
                # Verify None was passed for request_id
                call_kwargs = mock_process.call_args[1]
                assert "request_id" in call_kwargs


def test_acs_test_mode_idp_not_found_during_processing(
    client, test_tenant_host
):
    """Test POST ACS test mode when IdP lookup fails."""
    fake_idp_id = str(uuid4())

    with patch("routers.saml.saml_service.process_saml_test_response") as mock_process:
        with patch("routers.saml.saml_service.get_idp_for_saml_login") as mock_get_idp:
            with patch("routers.saml.templates.TemplateResponse") as mock_template:
                from services.exceptions import ServiceError

                # Mock process succeeding but IdP lookup failing
                from schemas.saml import SAMLTestResult

                mock_process.return_value = SAMLTestResult(
                    success=True,
                    name_id="test@example.com",
                )

                mock_get_idp.side_effect = ServiceError("IdP not found")

                mock_template.return_value = HTMLResponse(
                    content="<html>Unknown IdP</html>",
                    status_code=200,
                )

                response = client.post(
                    "/saml/acs",
                    headers={"Host": test_tenant_host},
                    data={
                        "SAMLResponse": "fake-base64-response",
                        "RelayState": f"__test__:{fake_idp_id}",
                    },
                )

                assert response.status_code == 200
                assert mock_template.called
                # Should still render with "Unknown IdP" name
                call_args = mock_template.call_args[0]
                context = call_args[2]
                assert context.get("idp_name") == "Unknown IdP"


def test_acs_test_mode_doesnt_create_session(client, test_tenant_host, test_idp):
    """Test that test mode doesn't create actual user sessions."""
    with patch("routers.saml.saml_service.process_saml_test_response") as mock_process:
        with patch("routers.saml.saml_service.get_idp_for_saml_login") as mock_get_idp:
            with patch("routers.saml.templates.TemplateResponse") as mock_template:
                with patch("routers.saml.regenerate_session") as mock_regen:
                    from schemas.saml import SAMLTestResult

                    mock_process.return_value = SAMLTestResult(
                        success=True,
                        name_id="test@example.com",
                    )

                    idp_mock = MagicMock()
                    idp_mock.name = "Test IdP"
                    mock_get_idp.return_value = idp_mock

                    mock_template.return_value = HTMLResponse(
                        content="<html>Test result</html>",
                        status_code=200,
                    )

                    response = client.post(
                        "/saml/acs",
                        headers={"Host": test_tenant_host},
                        data={
                            "SAMLResponse": "fake-base64-response",
                            "RelayState": f"__test__:{test_idp.id}",
                        },
                    )

                    assert response.status_code == 200
                    # Critical: regenerate_session should NOT be called in test mode
                    assert not mock_regen.called
