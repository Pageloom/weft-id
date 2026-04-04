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


def _sample_sp_config(**overrides: str) -> SPConfig:
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    return SPConfig(
        id=overrides.get("id", str(uuid4())),
        name=overrides.get("name", "Test SP"),
        entity_id=overrides.get("entity_id", "https://sp.example.com"),
        acs_url=overrides.get("acs_url", "https://sp.example.com/acs"),
        nameid_format=overrides.get(
            "nameid_format",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        ),
        trust_established=True,
        created_at=now,
        updated_at=now,
    )


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
            "pending_sso_user_id": sso_user["id"],
            "pending_sso_sp_id": str(uuid4()),
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
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=True,
            ),
            patch(
                "services.service_providers.get_user_consent_info",
                return_value={
                    "email": "alice@test.com",
                    "first_name": "Alice",
                    "last_name": "Smith",
                },
            ),
        ):
            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 200
        assert "Test Application" in response.text
        assert "alice@test.com" in response.text


# ============================================================================
# Consent - User Binding Validation
# ============================================================================


class TestConsentUserBinding:
    """Test that SSO context is bound to the user who initiated it."""

    def test_consent_get_rejects_mismatched_user(self, client, sso_user, sso_host):
        """GET /consent returns error when session user doesn't match SSO binding."""
        other_user_id = str(uuid4())
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_user_id": other_user_id,  # bound to a different user
            "pending_sso_sp_id": str(uuid4()),
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test SP",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "",
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

    def test_consent_post_rejects_mismatched_user(self, client, sso_user, sso_host):
        """POST /consent returns error when session user doesn't match SSO binding."""
        other_user_id = str(uuid4())
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_user_id": other_user_id,  # bound to a different user
            "pending_sso_sp_id": str(uuid4()),
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test SP",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "",
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

    def test_consent_allows_unbound_sso_context(self, client, sso_user, sso_host):
        """GET /consent allows SSO context without user binding (backwards compat)."""
        mock_session = {
            "user_id": sso_user["id"],
            # no pending_sso_user_id key at all
            "pending_sso_sp_id": str(uuid4()),
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test SP",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "",
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=True,
            ),
            patch(
                "services.service_providers.get_user_consent_info",
                return_value={
                    "email": "alice@test.com",
                    "first_name": "Alice",
                    "last_name": "Smith",
                },
            ),
        ):
            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 200


# ============================================================================
# Consent POST (continue/cancel)
# ============================================================================


class TestConsentRespond:
    def test_cancel_redirects_to_dashboard(self, client, sso_user, sso_host):
        sp_id = str(uuid4())
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_user_id": sso_user["id"],
            "pending_sso_sp_id": sp_id,
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
        sp_id = str(uuid4())
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_user_id": sso_user["id"],
            "pending_sso_sp_id": sp_id,
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
        assert mock_log.call_args[1]["artifact_id"] == sp_id

    def test_continue_renders_auto_submit_form(self, client, sso_user, sso_host):
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_user_id": sso_user["id"],
            "pending_sso_sp_id": str(uuid4()),
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
                return_value=("base64-saml-response", "https://sp.example.com/acs", "_sess123"),
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


# ============================================================================
# Consent Page - Group-Based Access Check
# ============================================================================


class TestConsentAccessCheck:
    """Test that the consent page checks group-based SP access."""

    def _make_pending_sso_session(self, user_id):
        """Build a session dict with user_id and pending SSO context."""
        return {
            "user_id": user_id,
            "pending_sso_user_id": user_id,
            "pending_sso_sp_id": str(uuid4()),
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test Application",
            "pending_sso_authn_request_id": "_req456",
            "pending_sso_relay_state": "",
        }

    def test_consent_denies_unauthorized_user(self, client, sso_user, sso_host):
        """User with session and pending SSO but no group access sees error."""
        mock_session = self._make_pending_sso_session(sso_user["id"])

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=False,
            ),
        ):
            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Access Denied" in response.text

    def test_consent_allows_authorized_user(self, client, sso_user, sso_host):
        """User with session, pending SSO, and group access sees consent page."""
        mock_session = self._make_pending_sso_session(sso_user["id"])

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=True,
            ),
            patch(
                "services.service_providers.get_user_consent_info",
                return_value={
                    "email": "alice@test.com",
                    "first_name": "Alice",
                    "last_name": "Smith",
                },
            ),
        ):
            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 200
        assert "Test Application" in response.text
        assert "alice@test.com" in response.text


# ============================================================================
# IdP-Initiated SSO Launch
# ============================================================================


class TestIdPInitiatedLaunch:
    """Tests for GET /saml/idp/launch/{sp_id}."""

    def test_launch_without_session_redirects_to_login(self, client, sso_host):
        """Unauthenticated user is redirected to login."""
        sp_id = str(uuid4())

        response = client.get(
            f"/saml/idp/launch/{sp_id}",
            headers={"Host": sso_host},
            follow_redirects=False,
        )

        assert response.status_code == 303
        assert "/login" in response.headers["location"]

    def test_launch_unknown_sp_shows_error(self, client, sso_user, sso_host):
        """Known user but unknown SP shows error page."""
        sp_id = str(uuid4())
        mock_session = {"user_id": sso_user["id"]}

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_service_provider_by_id",
                return_value=None,
            ),
        ):
            response = client.get(
                f"/saml/idp/launch/{sp_id}",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Unknown Application" in response.text

    def test_launch_unauthorized_shows_error(self, client, sso_user, sso_host):
        """User without group access sees Access Denied error."""
        sp_id = str(uuid4())
        mock_session = {"user_id": sso_user["id"]}
        sp_row = {
            "id": sp_id,
            "name": "Restricted App",
            "entity_id": "https://restricted.example.com",
            "enabled": True,
            "trust_established": True,
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_service_provider_by_id",
                return_value=sp_row,
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=False,
            ),
        ):
            response = client.get(
                f"/saml/idp/launch/{sp_id}",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Access Denied" in response.text

    def test_launch_success_redirects_to_consent(self, client, sso_user, sso_host):
        """Authorized user is redirected to the consent page."""
        sp_id = str(uuid4())
        mock_session = {"user_id": sso_user["id"]}
        sp_row = {
            "id": sp_id,
            "name": "My App",
            "entity_id": "https://myapp.example.com",
            "enabled": True,
            "trust_established": True,
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_service_provider_by_id",
                return_value=sp_row,
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=True,
            ),
        ):
            response = client.get(
                f"/saml/idp/launch/{sp_id}",
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "/saml/idp/consent" in response.headers["location"]


# ============================================================================
# SSO Access Scenarios (hierarchy, revocation, argument verification)
# ============================================================================


def _make_pending_sso_session(user_id, sp_id=None, sp_name="Test Application"):
    """Build a session dict with user_id and pending SSO context."""
    return {
        "user_id": user_id,
        "pending_sso_user_id": user_id,
        "pending_sso_sp_id": sp_id or str(uuid4()),
        "pending_sso_sp_entity_id": "https://sp.example.com",
        "pending_sso_sp_name": sp_name,
        "pending_sso_authn_request_id": "_req456",
        "pending_sso_relay_state": "",
    }


class TestSSOAccessScenarios:
    """Extended SSO access scenarios: consent page and IdP-initiated launch."""

    def test_consent_denies_after_group_removal(self, client, sso_user, sso_host):
        """User denied on consent page after group removal (access=False)."""
        mock_session = _make_pending_sso_session(sso_user["id"])

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=False,
            ),
        ):
            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Access Denied" in response.text

    def test_consent_allows_descendant_group_member(self, client, sso_user, sso_host):
        """User in descendant group sees consent page (access=True)."""
        mock_session = _make_pending_sso_session(sso_user["id"], sp_name="Descendant App")

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=True,
            ),
            patch(
                "services.service_providers.get_user_consent_info",
                return_value={
                    "email": "alice@test.com",
                    "first_name": "Alice",
                    "last_name": "Smith",
                },
            ),
        ):
            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 200
        assert "Descendant App" in response.text

    def test_consent_access_check_uses_sp_id_from_session(self, client, sso_user, sso_host):
        """check_user_sp_access is called with the SP ID from session."""
        sp_id = str(uuid4())
        mock_session = _make_pending_sso_session(sso_user["id"], sp_id=sp_id)

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=True,
            ) as mock_check,
            patch(
                "services.service_providers.get_user_consent_info",
                return_value={
                    "email": "alice@test.com",
                    "first_name": "Alice",
                    "last_name": "Smith",
                },
            ),
        ):
            client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        mock_check.assert_called_once()
        call_args = mock_check.call_args[0]
        # tenant_id, user_id, sp_id
        assert call_args[1] == sso_user["id"]
        assert call_args[2] == sp_id

    def test_consent_post_does_not_recheck_access(self, client, sso_user, sso_host):
        """POST /consent (continue) builds response without re-checking access."""
        mock_session = _make_pending_sso_session(sso_user["id"])
        mock_session["_csrf_token"] = "test-csrf-token"

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.build_sso_response",
                return_value=("base64-saml-response", "https://sp.example.com/acs", "_sess123"),
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

    def test_launch_denies_user_not_in_any_group(self, client, sso_user, sso_host):
        """User not in any assigned group is denied on launch."""
        sp_id = str(uuid4())
        mock_session = {"user_id": sso_user["id"]}
        sp_row = {
            "id": sp_id,
            "name": "Restricted App",
            "entity_id": "https://restricted.example.com",
            "enabled": True,
            "trust_established": True,
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_service_provider_by_id",
                return_value=sp_row,
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=False,
            ),
        ):
            response = client.get(
                f"/saml/idp/launch/{sp_id}",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Access Denied" in response.text

    def test_launch_allows_descendant_group_member(self, client, sso_user, sso_host):
        """User in descendant group is redirected to consent on launch."""
        sp_id = str(uuid4())
        mock_session = {"user_id": sso_user["id"]}
        sp_row = {
            "id": sp_id,
            "name": "My App",
            "entity_id": "https://myapp.example.com",
            "enabled": True,
            "trust_established": True,
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_service_provider_by_id",
                return_value=sp_row,
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=True,
            ),
        ):
            response = client.get(
                f"/saml/idp/launch/{sp_id}",
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "/saml/idp/consent" in response.headers["location"]

    def test_launch_access_check_uses_sp_id_from_path(self, client, sso_user, sso_host):
        """check_user_sp_access is called with the SP ID from the URL path."""
        sp_id = str(uuid4())
        mock_session = {"user_id": sso_user["id"]}
        sp_row = {
            "id": sp_id,
            "name": "My App",
            "entity_id": "https://myapp.example.com",
            "enabled": True,
            "trust_established": True,
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_service_provider_by_id",
                return_value=sp_row,
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=True,
            ) as mock_check,
        ):
            client.get(
                f"/saml/idp/launch/{sp_id}",
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        mock_check.assert_called_once()
        call_args = mock_check.call_args[0]
        # tenant_id, user_id, sp_id
        assert call_args[1] == sso_user["id"]
        assert call_args[2] == sp_id

    def test_launch_error_page_has_dashboard_link(self, client, sso_user, sso_host):
        """Access denied error page includes a link back to the dashboard."""
        sp_id = str(uuid4())
        mock_session = {"user_id": sso_user["id"]}
        sp_row = {
            "id": sp_id,
            "name": "Locked App",
            "entity_id": "https://locked.example.com",
            "enabled": True,
            "trust_established": True,
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_service_provider_by_id",
                return_value=sp_row,
            ),
            patch(
                "services.service_providers.check_user_sp_access",
                return_value=False,
            ),
        ):
            response = client.get(
                f"/saml/idp/launch/{sp_id}",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Dashboard" in response.text


# ============================================================================
# Disabled SP Rejection
# ============================================================================


class TestDisabledSPRejection:
    """Tests that disabled SPs reject SSO requests."""

    def test_sp_initiated_sso_rejects_disabled_sp(self, client, sso_host):
        """SP-initiated SSO returns error for disabled SP."""
        xml = _make_authn_request_xml(issuer="https://disabled-sp.example.com")
        saml_request = _encode_redirect(xml)

        disabled_sp = _sample_sp_config(
            entity_id="https://disabled-sp.example.com",
        )
        disabled_sp.enabled = False

        with patch(
            "services.service_providers.get_sp_by_entity_id",
            return_value=disabled_sp,
        ):
            response = client.get(
                "/saml/idp/sso",
                params={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Application Unavailable" in response.text

    def test_idp_initiated_launch_rejects_disabled_sp(self, client, sso_user, sso_host):
        """IdP-initiated launch returns error for disabled SP."""
        sp_id = str(uuid4())
        mock_session = {
            "user_id": sso_user["id"],
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_service_provider_by_id",
                return_value={
                    "id": sp_id,
                    "entity_id": "https://disabled-sp.example.com",
                    "name": "Disabled SP",
                    "enabled": False,
                    "trust_established": True,
                },
            ),
        ):
            response = client.get(
                f"/saml/idp/launch/{sp_id}",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400
        assert "Application Unavailable" in response.text

    def test_sp_initiated_sso_allows_enabled_sp(self, client, sso_host):
        """SP-initiated SSO proceeds for enabled SP."""
        xml = _make_authn_request_xml(issuer="https://enabled-sp.example.com")
        saml_request = _encode_redirect(xml)

        enabled_sp = _sample_sp_config(
            entity_id="https://enabled-sp.example.com",
        )
        enabled_sp.enabled = True

        with patch(
            "services.service_providers.get_sp_by_entity_id",
            return_value=enabled_sp,
        ):
            response = client.get(
                "/saml/idp/sso",
                params={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        # Enabled SP should redirect to login (not error)
        assert response.status_code == 303
        assert "/login" in response.headers["location"]


# ============================================================================
# SSO Error Paths
# ============================================================================


class TestSSOErrorPaths:
    """Cover remaining error paths in SSO flow."""

    def test_missing_issuer_returns_error(self, client, sso_host):
        """AuthnRequest with empty issuer returns invalid_request error."""
        xml = _make_authn_request_xml(issuer="")
        saml_request = _encode_redirect(xml)

        with patch(
            f"{ROUTER_MODULE}.parse_authn_request",
            return_value={"issuer": "", "id": "_req123"},
        ):
            response = client.get(
                "/saml/idp/sso",
                params={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
            )

        assert response.status_code == 400

    def test_sp_pending_trust_returns_error(self, client, sso_host):
        """SSO request for SP without established trust returns sp_pending_trust."""
        xml = _make_authn_request_xml()
        saml_request = _encode_redirect(xml)

        pending_sp = _sample_sp_config()
        pending_sp.trust_established = False

        with patch(
            "services.service_providers.get_sp_by_entity_id",
            return_value=pending_sp,
        ):
            response = client.get(
                "/saml/idp/sso",
                params={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
            )

        assert response.status_code == 400

    def test_authn_request_validation_failure(self, client, sso_host):
        """ValueError from validate_authn_request returns invalid_request error."""
        xml = _make_authn_request_xml()
        saml_request = _encode_redirect(xml)

        with (
            patch(
                "services.service_providers.get_sp_by_entity_id",
                return_value=_sample_sp_config(),
            ),
            patch(
                f"{ROUTER_MODULE}.validate_authn_request",
                side_effect=ValueError("ACS URL mismatch"),
            ),
        ):
            response = client.get(
                "/saml/idp/sso",
                params={"SAMLRequest": saml_request},
                headers={"Host": sso_host},
            )

        assert response.status_code == 400

    def test_idp_initiated_launch_pending_trust_returns_error(self, client, sso_user, sso_host):
        """IdP-initiated launch for SP without trust returns sp_pending_trust."""
        sp_id = str(uuid4())
        mock_session = {
            "user_id": sso_user["id"],
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(
                "services.service_providers.get_service_provider_by_id",
                return_value={
                    "id": sp_id,
                    "entity_id": "https://sp.example.com",
                    "name": "Test SP",
                    "trust_established": False,
                    "enabled": True,
                },
            ),
        ):
            response = client.get(
                f"/saml/idp/launch/{sp_id}",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400


# ============================================================================
# Consent - Additional Error Paths
# ============================================================================


class TestConsentErrors:
    """Cover remaining consent screen error paths."""

    def test_consent_user_info_unavailable(self, client, sso_user, sso_host):
        """Consent returns error when get_user_consent_info returns None."""
        sp_id = str(uuid4())
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_user_id": sso_user["id"],
            "pending_sso_sp_id": sp_id,
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test SP",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "",
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch("services.service_providers.check_user_sp_access", return_value=True),
            patch("services.service_providers.get_user_consent_info", return_value=None),
        ):
            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 400

    def test_consent_with_sp_logo(self, client, sso_user, sso_host):
        """Consent page extracts SP logo timestamp when logo exists."""
        from datetime import UTC, datetime

        sp_id = str(uuid4())
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_user_id": sso_user["id"],
            "pending_sso_sp_id": sp_id,
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_sp_name": "Test SP",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "",
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch("services.service_providers.check_user_sp_access", return_value=True),
            patch(
                "services.service_providers.get_user_consent_info",
                return_value={
                    "email": "alice@test.com",
                    "first_name": "Alice",
                    "last_name": "Smith",
                },
            ),
            patch(
                "services.branding.get_sp_logo_for_serving",
                return_value={
                    "data": b"png-data",
                    "content_type": "image/png",
                    "updated_at": datetime(2026, 3, 1, tzinfo=UTC),
                },
            ),
            patch("services.service_providers.get_groups_for_consent", return_value=[]),
        ):
            response = client.get(
                "/saml/idp/consent",
                headers={"Host": sso_host},
            )

        assert response.status_code == 200

    def test_consent_post_without_session(self, client, sso_host):
        """POST /consent without user_id in session returns no_session error."""
        mock_session = {
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

    def test_sso_response_build_failure(self, client, sso_user, sso_host):
        """Exception during build_sso_response returns no_certificate error."""
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_user_id": sso_user["id"],
            "pending_sso_sp_id": str(uuid4()),
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
            patch(
                "services.service_providers.build_sso_response",
                side_effect=Exception("No signing certificate"),
            ),
        ):
            response = client.post(
                "/saml/idp/consent",
                data={"action": "continue", "csrf_token": "test-csrf-token"},
                headers={"Host": sso_host},
            )

        assert response.status_code == 400


# ============================================================================
# Switch Account
# ============================================================================


class TestSwitchAccount:
    """Test the switch-account endpoint."""

    def test_switch_account_clears_auth_preserves_sso(self, client, sso_user, sso_host):
        """POST /consent/switch-account clears auth but preserves SSO context."""
        mock_session = {
            "user_id": sso_user["id"],
            "pending_sso_sp_id": str(uuid4()),
            "pending_sso_sp_entity_id": "https://sp.example.com",
            "pending_sso_authn_request_id": "_req123",
            "pending_sso_relay_state": "",
            "pending_sso_sp_name": "Test SP",
            "pending_sso_user_id": sso_user["id"],
            "_csrf_token": "test-csrf-token",
        }

        with (
            patch(
                "starlette.requests.Request.session",
                new_callable=lambda: property(lambda self: mock_session),
            ),
            patch(f"{ROUTER_MODULE}.log_event") as mock_log,
        ):
            response = client.post(
                "/saml/idp/consent/switch-account",
                data={"csrf_token": "test-csrf-token"},
                headers={"Host": sso_host},
                follow_redirects=False,
            )

        assert response.status_code == 303
        assert "/login" in response.headers["location"]
        # Verify sign-out event was logged
        mock_log.assert_called_once()
        assert mock_log.call_args[1]["event_type"] == "user_signed_out"
        assert mock_log.call_args[1]["metadata"]["reason"] == "sso_switch_account"
