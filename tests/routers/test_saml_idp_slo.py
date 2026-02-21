"""Tests for SAML IdP SLO router endpoints."""

import base64
import zlib
from unittest.mock import patch
from uuid import uuid4

import pytest
import settings

# ============================================================================
# Test Fixtures
# ============================================================================

SLO_SERVICE = "services.service_providers.slo.process_sp_logout_request"

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"


@pytest.fixture
def slo_host():
    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_tenant_lookup():
    tenant_id = str(uuid4())
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": tenant_id,
            "subdomain": "test",
        }
        yield tenant_id


def _make_logout_request_xml(
    issuer: str = "https://sp.example.com",
    request_id: str = "_req_slo_123",
) -> str:
    return (
        f'<samlp:LogoutRequest xmlns:samlp="{_SAMLP_NS}"'
        f' xmlns:saml="{_SAML_NS}"'
        f' ID="{request_id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
        f"user@example.com</saml:NameID>"
        f"<samlp:SessionIndex>_session_abc</samlp:SessionIndex>"
        f"</samlp:LogoutRequest>"
    )


def _encode_redirect(xml: str) -> str:
    compressed = zlib.compress(xml.encode("utf-8"))[2:-4]
    return base64.b64encode(compressed).decode("utf-8")


def _encode_post(xml: str) -> str:
    return base64.b64encode(xml.encode("utf-8")).decode("utf-8")


# ============================================================================
# SLO GET (HTTP-Redirect binding)
# ============================================================================


class TestSLORedirectBinding:
    def test_valid_request_returns_auto_submit_form(self, client, slo_host):
        xml = _make_logout_request_xml()
        saml_request = _encode_redirect(xml)

        with patch(
            SLO_SERVICE,
            return_value=("base64-logout-response", "https://sp.example.com/slo"),
        ):
            response = client.get(
                "/saml/idp/slo",
                params={"SAMLRequest": saml_request},
                headers={"Host": slo_host},
            )

        assert response.status_code == 200
        assert "base64-logout-response" in response.text
        assert "https://sp.example.com/slo" in response.text
        assert "SAMLResponse" in response.text

    def test_missing_saml_request_redirects_to_login(self, client, slo_host):
        response = client.get(
            "/saml/idp/slo",
            headers={"Host": slo_host},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_invalid_request_redirects_to_login(self, client, slo_host):
        bad = base64.b64encode(b"not xml").decode()
        response = client.get(
            "/saml/idp/slo",
            params={"SAMLRequest": bad},
            headers={"Host": slo_host},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_service_error_redirects_to_login(self, client, slo_host):
        xml = _make_logout_request_xml()
        saml_request = _encode_redirect(xml)

        with patch(
            SLO_SERVICE,
            side_effect=Exception("SP not found"),
        ):
            response = client.get(
                "/saml/idp/slo",
                params={"SAMLRequest": saml_request},
                headers={"Host": slo_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_relay_state_is_forwarded(self, client, slo_host):
        xml = _make_logout_request_xml()
        saml_request = _encode_redirect(xml)

        with patch(
            SLO_SERVICE,
            return_value=("base64-logout-response", "https://sp.example.com/slo"),
        ):
            response = client.get(
                "/saml/idp/slo",
                params={"SAMLRequest": saml_request, "RelayState": "https://app.com/start"},
                headers={"Host": slo_host},
            )

        assert response.status_code == 200
        assert "https://app.com/start" in response.text
        assert "RelayState" in response.text


# ============================================================================
# SLO POST (HTTP-POST binding)
# ============================================================================


class TestSLOPostBinding:
    def test_valid_request_returns_auto_submit_form(self, client, slo_host):
        xml = _make_logout_request_xml()
        saml_request = _encode_post(xml)

        with patch(
            SLO_SERVICE,
            return_value=("base64-logout-response", "https://sp.example.com/slo"),
        ):
            response = client.post(
                "/saml/idp/slo",
                data={"SAMLRequest": saml_request},
                headers={"Host": slo_host},
            )

        assert response.status_code == 200
        assert "base64-logout-response" in response.text
        assert "https://sp.example.com/slo" in response.text

    def test_missing_saml_request_redirects_to_login(self, client, slo_host):
        response = client.post(
            "/saml/idp/slo",
            data={},
            headers={"Host": slo_host},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_with_relay_state(self, client, slo_host):
        xml = _make_logout_request_xml()
        saml_request = _encode_post(xml)

        with patch(
            SLO_SERVICE,
            return_value=("base64-logout-response", "https://sp.example.com/slo"),
        ):
            response = client.post(
                "/saml/idp/slo",
                data={"SAMLRequest": saml_request, "RelayState": "some-state"},
                headers={"Host": slo_host},
            )

        assert response.status_code == 200
        assert "some-state" in response.text


# ============================================================================
# CSRF Exemption
# ============================================================================


class TestSLOCSRFExemption:
    def test_slo_post_is_csrf_exempt(self, client, slo_host):
        """POST to /saml/idp/slo should not require CSRF token (SAML protocol)."""
        xml = _make_logout_request_xml()
        saml_request = _encode_post(xml)

        with patch(
            SLO_SERVICE,
            return_value=("base64-logout-response", "https://sp.example.com/slo"),
        ):
            response = client.post(
                "/saml/idp/slo",
                data={"SAMLRequest": saml_request},
                headers={"Host": slo_host},
            )

        # Should get 200 (success), not 403 (CSRF failure)
        assert response.status_code == 200


# ============================================================================
# Session Clearing
# ============================================================================


class TestSLOSessionClearing:
    def test_session_is_cleared_on_slo(self, client, slo_host):
        """SLO should clear the user's session."""
        xml = _make_logout_request_xml()
        saml_request = _encode_post(xml)

        mock_session = {
            "user_id": str(uuid4()),
            "session_start": 1234567890,
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                SLO_SERVICE,
                return_value=("base64-logout-response", "https://sp.example.com/slo"),
            ),
        ):
            response = client.post(
                "/saml/idp/slo",
                data={"SAMLRequest": saml_request},
                headers={"Host": slo_host},
            )

        assert response.status_code == 200
        # Session should have been cleared
        assert "user_id" not in mock_session
