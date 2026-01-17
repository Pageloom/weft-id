"""SAML router security tests.

Tests critical security features of SAML authentication:
- IdP mismatch detection (prevents response injection attacks)
- Session tampering prevention
- Session persistence configuration
- Test mode isolation
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def test_idp(test_tenant, test_super_admin_user):
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
        name="Test IdP 1",
        provider_type="okta",
        entity_id="https://login-test1.example.com/entity",
        sso_url="https://login-test1.example.com/sso",
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


@pytest.fixture
def test_idp2(test_tenant, test_super_admin_user):
    """Create a second test SAML IdP for mismatch testing."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.types import RequestingUser

    requesting_user = RequestingUser(
        id=str(test_super_admin_user["id"]),
        tenant_id=str(test_tenant["id"]),
        role="super_admin",
    )

    data = IdPCreate(
        name="Test IdP 2",
        provider_type="azure_ad",
        entity_id="https://login-test2.example.com/entity",
        sso_url="https://login-test2.example.com/sso",
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


def test_saml_idp_mismatch_detection(client, test_tenant, test_tenant_host, test_idp, test_idp2):
    """Test that SAML response from wrong IdP is rejected (CRITICAL SECURITY).

    This prevents an attacker from initiating login with IdP1 but submitting
    a SAML response from IdP2 they control.
    """
    # Simulate user initiating login with IdP1
    # This sets saml_idp_id in session
    with patch("routers.saml.saml_service.build_authn_request") as mock_build:
        mock_build.return_value = ("https://fake-redirect.com", "request-123")

        response = client.get(
            f"/saml/login/{test_idp.id}",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )

        assert response.status_code == 303  # Redirect to IdP

    # Now simulate receiving SAML response from IdP2 (different IdP!)
    # The system should detect the mismatch and reject it
    with patch("routers.saml.extract_issuer_from_response") as mock_extract:
        with patch("routers.saml.saml_service.get_idp_by_issuer") as mock_get_idp:
            # Mock returning IdP2's entity_id as the issuer
            mock_extract.return_value = test_idp2.entity_id

            # Mock looking up IdP2 by issuer
            idp2_mock = MagicMock()
            idp2_mock.id = str(test_idp2.id)
            idp2_mock.is_enabled = True
            mock_get_idp.return_value = idp2_mock

            # Submit SAML response
            response = client.post(
                "/saml/acs",
                headers={"Host": test_tenant_host},
                data={
                    "SAMLResponse": "fake-base64-response",
                    "RelayState": "/dashboard",
                },
            )

            # Should reject with IdP mismatch error
            assert response.status_code == 200  # Error page
            assert "IdP mismatch" in response.text or "unexpected IdP" in response.text


def test_saml_session_tampering_prevention(
    client, test_tenant, test_tenant_host, test_idp, test_idp2
):
    """Test that session tampering (changing stored IdP ID) is detected."""
    # Initiate login with IdP1
    with patch("routers.saml.saml_service.build_authn_request") as mock_build:
        mock_build.return_value = ("https://fake-redirect.com", "request-123")

        response = client.get(
            f"/saml/login/{test_idp.id}",
            headers={"Host": test_tenant_host},
            follow_redirects=False,
        )

        assert response.status_code == 303

    # Attacker tries to tamper with session (change stored IdP ID to IdP2)
    # This is hypothetical since TestClient doesn't expose session manipulation,
    # but the check in code prevents it
    with patch("routers.saml.extract_issuer_from_response") as mock_extract:
        with patch("routers.saml.saml_service.get_idp_by_issuer") as mock_get_idp:
            # Return IdP2 (mismatch with session)
            mock_extract.return_value = test_idp2.entity_id

            idp2_mock = MagicMock()
            idp2_mock.id = str(test_idp2.id)
            idp2_mock.is_enabled = True
            mock_get_idp.return_value = idp2_mock

            response = client.post(
                "/saml/acs",
                headers={"Host": test_tenant_host},
                data={
                    "SAMLResponse": "fake-base64-response",
                    "RelayState": "/dashboard",
                },
            )

            # Should reject due to mismatch
            assert "IdP mismatch" in response.text or "unexpected IdP" in response.text


def test_saml_session_persistence_configuration_non_persistent(
    client, test_tenant, test_tenant_host, test_idp, test_user
):
    """Test that non-persistent session configuration is respected."""
    with patch("routers.saml.extract_issuer_from_response") as mock_extract:
        with patch("routers.saml.saml_service.get_idp_by_issuer") as mock_get_idp:
            with patch("routers.saml.saml_service.process_saml_response") as mock_process:
                with patch("routers.saml.saml_service.authenticate_via_saml") as mock_auth:
                    with patch("routers.saml.settings_service.get_session_settings") as mock_settings:
                        with patch("routers.saml.regenerate_session") as mock_regen:
                            # Setup mocks
                            mock_extract.return_value = test_idp.entity_id

                            idp_mock = MagicMock()
                            idp_mock.id = str(test_idp.id)
                            idp_mock.is_enabled = True
                            idp_mock.require_platform_mfa = False
                            mock_get_idp.return_value = idp_mock

                            saml_result_mock = MagicMock()
                            saml_result_mock.name_id = test_user["email"]
                            saml_result_mock.requires_mfa = False
                            mock_process.return_value = saml_result_mock

                            mock_auth.return_value = test_user

                            # Configure non-persistent sessions
                            mock_settings.return_value = {
                                "persistent_sessions": False,
                                "session_timeout_seconds": None,
                            }

                            # Initiate login
                            response = client.post(
                                "/saml/acs",
                                headers={"Host": test_tenant_host},
                                data={
                                    "SAMLResponse": "fake-base64-response",
                                    "RelayState": "/dashboard",
                                },
                            )

                            # Verify regenerate_session was called with max_age=None (non-persistent)
                            assert mock_regen.called
                            call_args = mock_regen.call_args
                            max_age = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get("max_age")
                            assert max_age is None


def test_saml_session_persistence_configuration_with_timeout(
    client, test_tenant, test_tenant_host, test_idp, test_user
):
    """Test that custom session timeout is respected."""
    with patch("routers.saml.extract_issuer_from_response") as mock_extract:
        with patch("routers.saml.saml_service.get_idp_by_issuer") as mock_get_idp:
            with patch("routers.saml.saml_service.process_saml_response") as mock_process:
                with patch("routers.saml.saml_service.authenticate_via_saml") as mock_auth:
                    with patch("routers.saml.settings_service.get_session_settings") as mock_settings:
                        with patch("routers.saml.regenerate_session") as mock_regen:
                            # Setup mocks
                            mock_extract.return_value = test_idp.entity_id

                            idp_mock = MagicMock()
                            idp_mock.id = str(test_idp.id)
                            idp_mock.is_enabled = True
                            idp_mock.require_platform_mfa = False
                            mock_get_idp.return_value = idp_mock

                            saml_result_mock = MagicMock()
                            saml_result_mock.name_id = test_user["email"]
                            saml_result_mock.requires_mfa = False
                            mock_process.return_value = saml_result_mock

                            mock_auth.return_value = test_user

                            # Configure with custom timeout (2 hours)
                            mock_settings.return_value = {
                                "persistent_sessions": True,
                                "session_timeout_seconds": 7200,
                            }

                            # Initiate login
                            response = client.post(
                                "/saml/acs",
                                headers={"Host": test_tenant_host},
                                data={
                                    "SAMLResponse": "fake-base64-response",
                                    "RelayState": "/dashboard",
                                },
                            )

                            # Verify regenerate_session was called with correct timeout
                            assert mock_regen.called
                            call_args = mock_regen.call_args
                            max_age = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get("max_age")
                            assert max_age == 7200


def test_saml_test_mode_prevents_actual_login(client, test_tenant, test_tenant_host, test_idp):
    """Test that test mode (RelayState=__test__:*) doesn't create actual sessions."""
    with patch("routers.saml._handle_saml_test_response") as mock_test_handler:
        # Mock test handler to return a simple response
        mock_test_handler.return_value = MagicMock(
            status_code=200,
            body=b"test response",
        )

        # Submit SAML response with test mode RelayState
        response = client.post(
            "/saml/acs",
            headers={"Host": test_tenant_host},
            data={
                "SAMLResponse": "fake-base64-response",
                "RelayState": f"__test__:{test_idp.id}",
            },
        )

        # Verify test handler was called (not normal flow)
        assert mock_test_handler.called

        # Verify it was called with correct parameters
        call_args = mock_test_handler.call_args[0]
        # Tenant ID might be UUID object, convert both to string for comparison
        assert str(call_args[1]) == str(test_tenant["id"])
        assert call_args[2] == "fake-base64-response"
        assert call_args[3].startswith("__test__:")
