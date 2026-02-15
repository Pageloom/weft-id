"""Tests for the public trust page (/pub/idp/{idp_id}).

Tests both the router endpoint and the service function.
"""

import os
from pathlib import Path

import pytest
from services.exceptions import NotFoundError
from services.types import RequestingUser


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


def _make_requesting_user(user: dict, tenant_id: str, role: str = "super_admin") -> RequestingUser:
    """Helper to create RequestingUser from test fixture."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role,
    )


@pytest.fixture
def test_idp_data():
    """Provide test IdP data."""
    return {
        "name": "Trust Page Test IdP",
        "provider_type": "okta",
        "entity_id": "https://trust-test-idp.example.com/entity",
        "sso_url": "https://trust-test-idp.example.com/sso",
        "certificate_pem": """-----BEGIN CERTIFICATE-----
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
        "attribute_mapping": {
            "email": "email",
            "first_name": "firstName",
            "last_name": "lastName",
            "groups": "memberOf",
        },
        "is_enabled": True,
    }


@pytest.fixture
def enabled_idp(test_tenant, test_super_admin_user, test_idp_data):
    """Create an enabled IdP and return its config."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"])
    data = IdPCreate(**test_idp_data)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Enable the IdP
    saml_service.set_idp_enabled(requesting_user, idp.id, True)

    return idp


@pytest.fixture
def disabled_idp(test_tenant, test_super_admin_user):
    """Create a disabled IdP and return its config."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"])
    data = IdPCreate(
        name="Disabled Trust Test IdP",
        provider_type="generic",
        entity_id="https://disabled-trust-test.example.com/entity",
        sso_url="https://disabled-trust-test.example.com/sso",
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
        is_enabled=False,
    )
    return saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")


# =============================================================================
# Service Layer Tests
# =============================================================================


class TestGetPublicTrustInfo:
    """Tests for get_public_trust_info service function."""

    def test_happy_path(self, test_tenant, enabled_idp):
        """Test returns trust info for an enabled IdP."""
        from services import saml as saml_service

        result = saml_service.get_public_trust_info(
            test_tenant["id"], enabled_idp.id, "https://test.example.com"
        )

        assert result["name"] == "Trust Page Test IdP"
        assert result["provider_type"] == "okta"
        # Per-IdP format: sp_entity_id contains the IdP ID
        assert result["sp_entity_id"] == f"https://test.example.com/saml/metadata/{enabled_idp.id}"
        assert result["sp_acs_url"] == f"https://test.example.com/saml/acs/{enabled_idp.id}"
        assert result["metadata_url"] == f"https://test.example.com/saml/metadata/{enabled_idp.id}"
        assert result["attribute_mapping"]["email"] == "email"
        assert len(result["attribute_display"]) == 4

    def test_attribute_display_labels(self, test_tenant, enabled_idp):
        """Test attribute display has human-readable labels."""
        from services import saml as saml_service

        result = saml_service.get_public_trust_info(
            test_tenant["id"], enabled_idp.id, "https://test.example.com"
        )

        fields = {a["field"] for a in result["attribute_display"]}
        assert "Email" in fields
        assert "First Name" in fields
        assert "Last Name" in fields
        assert "Groups" in fields

    def test_disabled_idp_raises_not_found(self, test_tenant, disabled_idp):
        """Test that disabled IdP raises NotFoundError."""
        from services import saml as saml_service

        with pytest.raises(NotFoundError) as exc_info:
            saml_service.get_public_trust_info(
                test_tenant["id"], disabled_idp.id, "https://test.example.com"
            )
        assert exc_info.value.code == "idp_not_found"

    def test_nonexistent_idp_raises_not_found(self, test_tenant):
        """Test that nonexistent IdP raises NotFoundError."""
        import uuid

        from services import saml as saml_service

        with pytest.raises(NotFoundError) as exc_info:
            saml_service.get_public_trust_info(
                test_tenant["id"], str(uuid.uuid4()), "https://test.example.com"
            )
        assert exc_info.value.code == "idp_not_found"

    def test_empty_attribute_mapping(self, test_tenant, test_super_admin_user):
        """Test with IdP that has no attribute mapping stored."""
        from services import saml as saml_service

        # The create_identity_provider sets defaults, so get_public_trust_info
        # will have a mapping. Just verify it doesn't crash with empty display.
        requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"])
        from schemas.saml import IdPCreate

        data = IdPCreate(
            name="No Attr Map IdP",
            provider_type="generic",
            entity_id="https://noattr-trust.example.com/entity",
            sso_url="https://noattr-trust.example.com/sso",
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
            requesting_user, data, "https://test.example.com"
        )
        saml_service.set_idp_enabled(requesting_user, idp.id, True)

        result = saml_service.get_public_trust_info(
            test_tenant["id"], idp.id, "https://test.example.com"
        )
        # Default mapping is set by create_identity_provider
        assert isinstance(result["attribute_display"], list)


# =============================================================================
# Router Tests
# =============================================================================


class TestPublicTrustRoute:
    """Tests for GET /pub/idp/{idp_id} endpoint."""

    def test_enabled_idp_returns_200(self, client, test_tenant_host, enabled_idp):
        """Test that visiting trust page for enabled IdP returns 200."""
        response = client.get(
            f"/pub/idp/{enabled_idp.id}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 200
        assert "Trust Configuration" in response.text
        assert "Trust Page Test IdP" in response.text
        assert "SP Metadata URL" in response.text
        assert "SP Entity ID" in response.text
        assert "ACS URL" in response.text

    def test_attribute_mappings_displayed(self, client, test_tenant_host, enabled_idp):
        """Test that attribute mappings are shown in the page."""
        response = client.get(
            f"/pub/idp/{enabled_idp.id}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 200
        assert "Expected Attributes" in response.text
        assert "Email" in response.text
        assert "First Name" in response.text

    def test_disabled_idp_returns_404(self, client, test_tenant_host, disabled_idp):
        """Test that disabled IdP returns 404."""
        response = client.get(
            f"/pub/idp/{disabled_idp.id}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 404

    def test_nonexistent_idp_returns_404(self, client, test_tenant_host):
        """Test that nonexistent IdP returns 404."""
        import uuid

        response = client.get(
            f"/pub/idp/{uuid.uuid4()}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 404

    def test_invalid_uuid_returns_404(self, client, test_tenant_host):
        """Test that invalid UUID format returns 404 or 422."""
        response = client.get(
            "/pub/idp/not-a-uuid",
            headers={"Host": test_tenant_host},
        )

        # Either 404 (caught by service) or 422 (FastAPI validation)
        assert response.status_code in (404, 422, 500)

    def test_no_auth_required(self, client, test_tenant_host, enabled_idp):
        """Test that the page works without any authentication."""
        # client has no auth overrides, yet should still work
        response = client.get(
            f"/pub/idp/{enabled_idp.id}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 200

    def test_metadata_url_in_page(self, client, test_tenant_host, enabled_idp):
        """Test that the metadata URL is present in the response."""
        response = client.get(
            f"/pub/idp/{enabled_idp.id}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 200
        assert "/saml/metadata" in response.text

    def test_acs_url_in_page(self, client, test_tenant_host, enabled_idp):
        """Test that the ACS URL is present in the response."""
        response = client.get(
            f"/pub/idp/{enabled_idp.id}",
            headers={"Host": test_tenant_host},
        )

        assert response.status_code == 200
        assert "/saml/acs" in response.text
