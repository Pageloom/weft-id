"""Tests for the SAML IdP attributes tab GET handler."""

import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from schemas.saml import IdPConfig

ROUTER_MODULE = "routers.saml.admin.providers"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def setup_app_directory():
    """Change to app directory so templates can be found."""
    original_cwd = os.getcwd()
    app_dir = Path(__file__).parent.parent.parent / "app"
    os.chdir(app_dir)
    yield
    os.chdir(original_cwd)


@pytest.fixture
def idp_user():
    """Mock super admin user dict for dependency overrides."""
    tenant_id = str(uuid4())
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "role": "super_admin",
        "email": "admin@test.com",
        "first_name": "Test",
        "last_name": "Admin",
        "tz": "UTC",
        "locale": "en_US",
    }


@pytest.fixture
def idp_admin_session(client, idp_user, override_auth):
    """Client with super_admin session for IdP routes."""
    override_auth(idp_user, level="super_admin")
    return client


@pytest.fixture
def idp_host():
    """Host header matching the user's tenant."""
    import settings

    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_tenant_lookup(idp_user):
    """Mock tenant lookup so test host resolves to our test tenant."""
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": idp_user["tenant_id"],
            "subdomain": "test",
        }
        yield


@pytest.fixture
def sample_idp_config():
    """Sample IdP config with attribute mapping and no metadata."""
    return IdPConfig(
        id=str(uuid4()),
        name="Test IdP",
        provider_type="okta",
        entity_id="https://test-idp.example.com/entity",
        sso_url="https://test-idp.example.com/sso",
        slo_url=None,
        certificate_pem="-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
        metadata_url=None,
        metadata_xml=None,
        metadata_last_fetched_at=None,
        metadata_fetch_error=None,
        sp_entity_id="https://app.example.com",
        sp_acs_url="https://app.example.com/saml/acs",
        attribute_mapping={
            "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "first_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
            "last_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
            "groups": "groups",
        },
        is_enabled=True,
        is_default=False,
        require_platform_mfa=False,
        jit_provisioning=False,
        trust_established=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


@pytest.fixture
def sample_idp_with_metadata(sample_idp_config):
    """IdP config that has metadata_xml set (so advertised attrs will be extracted)."""
    return sample_idp_config.model_copy(
        update={"metadata_xml": "<md:EntityDescriptor>...</md:EntityDescriptor>"}
    )


@pytest.fixture
def sample_advertised_attributes():
    """Advertised attributes returned by extract_idp_advertised_attributes."""
    return [
        {
            "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "friendly_name": "Email",
        },
        {
            "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
            "friendly_name": "Given Name",
        },
        {
            "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
            "friendly_name": "Surname",
        },
        {
            "name": "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
            "friendly_name": "",
        },
    ]


def _mock_idp_common(idp_config):
    """Return a patch for services.saml.get_identity_provider returning idp_config."""
    return patch(
        "services.saml.get_identity_provider",
        return_value=idp_config,
    )


# =============================================================================
# Tests
# =============================================================================


class TestAttributesTabWithoutMetadata:
    """Tests for the attributes tab when IdP has no metadata."""

    def test_attributes_tab_renders_without_metadata(
        self, idp_admin_session, idp_host, sample_idp_config
    ):
        """Single table shown, no 'Advertised by IdP' column, amber notice, no datalist."""
        with _mock_idp_common(sample_idp_config):
            response = idp_admin_session.get(
                f"/admin/settings/identity-providers/{sample_idp_config.id}/attributes",
                headers={"Host": idp_host},
            )

        assert response.status_code == 200
        html = response.text

        # Single table with Platform Field and IdP Attribute Name columns
        assert "Attribute Mapping" in html
        assert "Platform Field" in html
        assert "IdP Attribute Name" in html

        # No "Advertised by IdP" column when no metadata
        assert "Advertised by IdP" not in html

        # No datalist since no metadata
        assert "advertised-attrs" not in html

        # Amber notice shown for manual IdP
        assert "configured manually without metadata" in html

    def test_attributes_tab_prefills_current_mapping(
        self, idp_admin_session, idp_host, sample_idp_config
    ):
        """Form inputs contain current mapping values."""
        with _mock_idp_common(sample_idp_config):
            response = idp_admin_session.get(
                f"/admin/settings/identity-providers/{sample_idp_config.id}/attributes",
                headers={"Host": idp_host},
            )

        html = response.text

        # Check that current mapping values are in the form inputs
        assert 'value="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"' in html
        assert 'value="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"' in html
        assert 'value="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"' in html
        assert 'value="groups"' in html

    def test_attributes_tab_presets_button_label(
        self, idp_admin_session, idp_host, sample_idp_config
    ):
        """Presets link text includes provider type."""
        with _mock_idp_common(sample_idp_config):
            response = idp_admin_session.get(
                f"/admin/settings/identity-providers/{sample_idp_config.id}/attributes",
                headers={"Host": idp_host},
            )

        assert "Load Okta presets" in response.text


class TestAttributesTabWithAdvertisedAttributes:
    """Tests for the attributes tab when IdP has metadata with advertised attrs."""

    def test_attributes_tab_renders_with_advertised_attributes(
        self,
        idp_admin_session,
        idp_host,
        sample_idp_with_metadata,
        sample_advertised_attributes,
    ):
        """Datalist rendered, list attr on inputs, 'Advertised by IdP' column present."""
        with (
            _mock_idp_common(sample_idp_with_metadata),
            patch(
                f"{ROUTER_MODULE}.extract_idp_advertised_attributes",
                return_value=sample_advertised_attributes,
            ),
        ):
            response = idp_admin_session.get(
                f"/admin/settings/identity-providers/{sample_idp_with_metadata.id}/attributes",
                headers={"Host": idp_host},
            )

        assert response.status_code == 200
        html = response.text

        # Datalist rendered with advertised attribute values
        assert '<datalist id="advertised-attrs">' in html
        assert 'value="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"' in html

        # Inputs reference the datalist
        assert 'list="advertised-attrs"' in html

        # "Advertised by IdP" column shown
        assert "Advertised by IdP" in html

        # No amber notice (has metadata)
        assert "configured manually without metadata" not in html

    def test_attributes_tab_matched_badge(
        self,
        idp_admin_session,
        idp_host,
        sample_idp_with_metadata,
        sample_advertised_attributes,
    ):
        """When current mapping value matches an advertised attr, shows green 'Matched' badge."""
        with (
            _mock_idp_common(sample_idp_with_metadata),
            patch(
                f"{ROUTER_MODULE}.extract_idp_advertised_attributes",
                return_value=sample_advertised_attributes,
            ),
        ):
            response = idp_admin_session.get(
                f"/admin/settings/identity-providers/{sample_idp_with_metadata.id}/attributes",
                headers={"Host": idp_host},
            )

        html = response.text

        # Email, first_name, last_name all match advertised attrs -> green Matched badge
        assert "bg-green-100" in html
        assert ">Matched</span>" in html

    def test_attributes_tab_unmatched_badge(
        self,
        idp_admin_session,
        idp_host,
        sample_idp_with_metadata,
        sample_advertised_attributes,
    ):
        """When current mapping value doesn't match any advertised attr, shows 'Unmatched'."""
        with (
            _mock_idp_common(sample_idp_with_metadata),
            patch(
                f"{ROUTER_MODULE}.extract_idp_advertised_attributes",
                return_value=sample_advertised_attributes,
            ),
        ):
            response = idp_admin_session.get(
                f"/admin/settings/identity-providers/{sample_idp_with_metadata.id}/attributes",
                headers={"Host": idp_host},
            )

        html = response.text

        # The "groups" mapping value is "groups" which doesn't match any advertised attr name
        # (advertised attrs are URI-based), so it should show amber "Unmatched" badge
        assert "Unmatched" in html
        assert "bg-amber-100" in html
