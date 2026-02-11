"""Tests for SAML IdP SSO router (sso.py)."""

import base64
import zlib
from unittest.mock import patch
from uuid import uuid4

import pytest
import settings
from schemas.service_providers import SPConfig

# ============================================================================
# Test Fixtures
# ============================================================================

ROUTER_MODULE = "routers.saml_idp.sso"


@pytest.fixture
def sso_user():
    """Authenticated user for SSO tests."""
    tenant_id = str(uuid4())
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "role": "user",
        "email": "alice@test.com",
        "first_name": "Alice",
        "last_name": "Smith",
        "tz": "UTC",
        "locale": "en_US",
    }


@pytest.fixture
def sso_host():
    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_tenant_lookup(sso_user):
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": sso_user["tenant_id"],
            "subdomain": "test",
        }
        yield


def _make_authn_request_xml(
    issuer: str = "https://sp.example.com",
    request_id: str = "_req123",
) -> str:
    return (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{request_id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        f"</samlp:AuthnRequest>"
    )


def _encode_redirect(xml: str) -> str:
    """Encode as HTTP-Redirect binding (deflate + base64)."""
    compressed = zlib.compress(xml.encode("utf-8"))[2:-4]
    return base64.b64encode(compressed).decode("utf-8")


def _encode_post(xml: str) -> str:
    """Encode as HTTP-POST binding (base64 only)."""
    return base64.b64encode(xml.encode("utf-8")).decode("utf-8")


def _sample_sp_config(**overrides) -> SPConfig:
    from datetime import UTC, datetime

    defaults = {
        "id": str(uuid4()),
        "name": "Test SP",
        "entity_id": "https://sp.example.com",
        "acs_url": "https://sp.example.com/acs",
        "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    return SPConfig(**defaults)


# ============================================================================
# SSO Endpoint - Redirect Binding
# ============================================================================


class TestSSORedirectBinding:
    def test_valid_request_without_session_redirects_to_login(self, client, sso_host):
        xml = _make_authn_request_xml()
        saml_request = _encode_redirect(xml)

        with patch(
            "services.service_providers.get_sp_by_entity_id",
            return_value=_sample_sp_config(),
        ):
            response = client.get(
                "/saml/idp/sso",
                params={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_unknown_sp_returns_error(self, client, sso_host):
        xml = _make_authn_request_xml(issuer="https://unknown.com")
        saml_request = _encode_redirect(xml)

        with patch(
            "services.service_providers.get_sp_by_entity_id",
            return_value=None,
        ):
            response = client.get(
                "/saml/idp/sso",
                params={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Unknown Application" in response.text

    def test_malformed_request_returns_error(self, client, sso_host):
        # Valid base64 but not valid deflated XML
        bad = base64.b64encode(b"not xml").decode()
        response = client.get(
            "/saml/idp/sso",
            params={"SAMLRequest": bad},
            headers={"Host": sso_host},
        )
        assert response.status_code == 400
        assert "Invalid Request" in response.text or "invalid_request" in response.text

    def test_missing_saml_request_returns_error(self, client, sso_host):
        response = client.get(
            "/saml/idp/sso",
            headers={"Host": sso_host},
        )
        assert response.status_code == 400

    def test_stores_sso_context_in_session(self, client, sso_host):
        """Verify that SSO context is stored in session before redirect."""
        xml = _make_authn_request_xml(issuer="https://sp.example.com")
        saml_request = _encode_redirect(xml)
        sp = _sample_sp_config(name="My App")

        with patch(
            "services.service_providers.get_sp_by_entity_id",
            return_value=sp,
        ):
            response = client.get(
                "/saml/idp/sso",
                params={"SAMLRequest": saml_request, "RelayState": "https://app.com/start"},
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        # Session is stored in signed cookie - we verify behavior via the redirect
        assert "/login" in response.headers["location"]

    def test_authenticated_user_redirects_to_consent(self, client, sso_user, sso_host):
        """User with active session should be redirected to consent."""
        xml = _make_authn_request_xml()
        saml_request = _encode_redirect(xml)

        mock_session = {
            "user_id": sso_user["id"],
            "session_start": 1234567890,
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_sp_by_entity_id", return_value=_sample_sp_config()
            ),
        ):
            response = client.get(
                "/saml/idp/sso",
                params={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "/saml/idp/consent" in response.headers["location"]


# ============================================================================
# SSO Endpoint - POST Binding
# ============================================================================


class TestSSOPostBinding:
    def test_valid_post_redirects_to_login(self, client, sso_host):
        xml = _make_authn_request_xml()
        saml_request = _encode_post(xml)

        with patch(
            "services.service_providers.get_sp_by_entity_id",
            return_value=_sample_sp_config(),
        ):
            response = client.post(
                "/saml/idp/sso",
                data={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_missing_saml_request_returns_error(self, client, sso_host):
        response = client.post(
            "/saml/idp/sso",
            data={},
            headers={"Host": sso_host},
        )
        assert response.status_code == 400

    def test_unknown_sp_returns_error(self, client, sso_host):
        xml = _make_authn_request_xml(issuer="https://evil.com")
        saml_request = _encode_post(xml)

        with patch(
            "services.service_providers.get_sp_by_entity_id",
            return_value=None,
        ):
            response = client.post(
                "/saml/idp/sso",
                data={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Unknown Application" in response.text


# ============================================================================
# Consent Page
# ============================================================================


class TestConsentPage:
    def test_consent_without_session_shows_error(self, client, sso_host):
        response = client.get(
            "/saml/idp/consent",
            headers={"Host": sso_host},
        )
        assert response.status_code == 400

    def test_consent_without_pending_sso_shows_error(self, client, sso_user, sso_host):
        mock_session = {
            "user_id": sso_user["id"],
        }
        with patch(
            "starlette.requests.Request.session",
            new_callable=lambda: property(lambda self: mock_session),
        ):
            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400

    def test_consent_renders_with_sp_info(self, client, sso_user, sso_host):
        """When session has user_id and pending SSO, consent page renders."""
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test Application",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "",
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch("database.users.get_user_by_id") as mock_user,
            patch("database.user_emails.get_primary_email") as mock_email,
        ):
            mock_user.return_value = {
                "id": sso_user["id"],
                "first_name": "Alice",
                "last_name": "Smith",
            }
            mock_email.return_value = {
                "email": "alice@test.com",
            }

            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 200
        assert "Test Application" in response.text
        assert "alice@test.com" in response.text


# ============================================================================
# Consent POST (continue/cancel)
# ============================================================================


class TestConsentRespond:
    def test_cancel_redirects_to_dashboard(self, client, sso_user, sso_host):
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test SP",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "",
            "_csrf_token": "test-csrf-token",
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(f"{ROUTER_MODULE}.log_event"),
        ):
            response = client.post(
                "/saml/idp/consent",
                data={"action": "cancel", "csrf_token": "test-csrf-token"},
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "/dashboard" in response.headers["location"]

    def test_cancel_logs_consent_denied_event(self, client, sso_user, sso_host):
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test SP",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "",
            "_csrf_token": "test-csrf-token",
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(f"{ROUTER_MODULE}.log_event") as mock_log,
        ):
            client.post(
                "/saml/idp/consent",
                data={"action": "cancel", "csrf_token": "test-csrf-token"},
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        mock_log.assert_called_once()
        assert mock_log.call_args[1]["event_type"] == "sso_consent_denied"

    def test_continue_renders_auto_submit_form(self, client, sso_user, sso_host):
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test SP",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "https://sp.example.com/app",
            "_csrf_token": "test-csrf-token",
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.build_sso_response",
                return_value=("base64-saml-response", "https://sp.example.com/acs"),
            ),
        ):
            response = client.post(
                "/saml/idp/consent",
                data={"action": "continue", "csrf_token": "test-csrf-token"},
                headers={"Host": sso_host},
            )

        assert response.status_code == 200
        assert "saml-form" in response.text
        assert "base64-saml-response" in response.text
        assert "https://sp.example.com/acs" in response.text

    def test_continue_without_pending_sso_shows_error(self, client, sso_user, sso_host):
        mock_session = {
            "user_id": sso_user["id"],
            "_csrf_token": "test-csrf-token",
        }

        with patch(
            "starlette.requests.Request.session",
            new_callable=lambda: property(lambda self: mock_session),
        ):
            response = client.post(
                "/saml/idp/consent",
                data={"action": "continue", "csrf_token": "test-csrf-token"},
                headers={"Host": sso_host},
            )

        assert response.status_code == 400


# ============================================================================
# CSRF Exemption
# ============================================================================


class TestCSRFExemption:
    def test_sso_post_is_csrf_exempt(self, client, sso_host):
        """POST to /saml/idp/sso should not require CSRF token."""
        xml = _make_authn_request_xml(issuer="https://unknown.com")
        saml_request = _encode_post(xml)

        with patch(
            "services.service_providers.get_sp_by_entity_id",
            return_value=None,
        ):
            # No CSRF token in form data
            response = client.post(
                "/saml/idp/sso",
                data={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
            )

        # Should get 400 (unknown SP), not 403 (CSRF failure)
        assert response.status_code == 400
        assert "Unknown Application" in response.text
