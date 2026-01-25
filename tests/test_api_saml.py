"""Tests for SAML API endpoints."""

import uuid

import pytest

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def oauth2_super_admin_access_token(test_tenant, normal_oauth2_client, test_super_admin_user):
    """Create an OAuth2 access token for a super_admin user."""
    import database

    refresh_token, refresh_token_id = database.oauth2.create_refresh_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
    )

    access_token = database.oauth2.create_access_token(
        tenant_id=test_tenant["id"],
        tenant_id_value=test_tenant["id"],
        client_id=normal_oauth2_client["id"],
        user_id=test_super_admin_user["id"],
        parent_token_id=refresh_token_id,
    )

    yield access_token


@pytest.fixture
def oauth2_super_admin_header(oauth2_super_admin_access_token):
    """Create Authorization header for super_admin user."""
    return {"Authorization": f"Bearer {oauth2_super_admin_access_token}"}


@pytest.fixture
def sample_idp_data():
    """Sample data for creating an IdP."""
    return {
        "name": "Test IdP",
        "provider_type": "generic",
        "entity_id": "https://idp.example.com/metadata",
        "sso_url": "https://idp.example.com/sso",
        "slo_url": "https://idp.example.com/slo",
        "certificate_pem": """-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P2qk5TANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6
L2QqId5Z0gV7wJA7E9xC8TXj3TU4Dxs/xPnvIKI8MLSY0kU3W5QqG1KXNjp6Q/Bc
gv5IB7HGt/9xD6YR7nXW0XWPDjqYL9m6+x2g0lYqAQnhQ9X2W2p3mYcYK7zWM1y7
PjXa6N5t+1KTIxz5L5LlGgk9W2M6X3Q2l3q7q8Q3L5K5v+L5x5B5Q5x5Q5x5Q5x5
Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5
Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5Q5x5
Q5x5Q5x5Q5x5Q5x5Q5x5AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAA==
-----END CERTIFICATE-----""",
        "is_enabled": True,
        "is_default": False,
    }


@pytest.fixture
def created_idp(
    client, test_tenant_host, oauth2_super_admin_header, sample_idp_data, fast_sp_certificate
):
    """Create an IdP and return its data."""
    response = client.post(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_idp_data,
    )
    assert response.status_code == 201
    return response.json()


# =============================================================================
# List IdPs
# =============================================================================


def test_list_idps_as_super_admin(client, test_tenant_host, oauth2_super_admin_header):
    """Super admin can list IdPs."""
    response = client.get(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)


def test_list_idps_as_admin_forbidden(client, test_tenant_host, oauth2_admin_authorization_header):
    """Regular admin cannot list IdPs (requires super_admin)."""
    response = client.get(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


def test_list_idps_as_member_forbidden(client, test_tenant_host, oauth2_authorization_header):
    """Regular member cannot list IdPs."""
    response = client.get(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_list_idps_unauthenticated(client, test_tenant_host):
    """Unauthenticated request returns 401."""
    response = client.get(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


# =============================================================================
# Create IdP
# =============================================================================


def test_create_idp_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, sample_idp_data
):
    """Super admin can create an IdP."""
    response = client.post(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_idp_data,
    )

    assert response.status_code == 201
    data = response.json()
    assert data["name"] == sample_idp_data["name"]
    assert data["provider_type"] == sample_idp_data["provider_type"]
    assert data["entity_id"] == sample_idp_data["entity_id"]
    assert data["sso_url"] == sample_idp_data["sso_url"]
    assert "id" in data
    assert "created_at" in data
    assert "sp_entity_id" in data


def test_create_idp_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, sample_idp_data
):
    """Regular admin cannot create an IdP."""
    response = client.post(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json=sample_idp_data,
    )

    assert response.status_code == 403


def test_create_idp_invalid_provider_type(
    client, test_tenant_host, oauth2_super_admin_header, sample_idp_data
):
    """Invalid provider type returns 422."""
    sample_idp_data["provider_type"] = "invalid"
    response = client.post(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_idp_data,
    )

    assert response.status_code == 422


def test_create_idp_missing_required_field(client, test_tenant_host, oauth2_super_admin_header):
    """Missing required field returns 422."""
    response = client.post(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"name": "Test IdP"},  # Missing other required fields
    )

    assert response.status_code == 422


# =============================================================================
# Get IdP
# =============================================================================


def test_get_idp_as_super_admin(client, test_tenant_host, oauth2_super_admin_header, created_idp):
    """Super admin can get IdP details."""
    response = client.get(
        f"/api/v1/saml/idps/{created_idp['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == created_idp["id"]
    assert data["name"] == created_idp["name"]


def test_get_idp_not_found(client, test_tenant_host, oauth2_super_admin_header):
    """Getting non-existent IdP returns 404."""
    fake_id = str(uuid.uuid4())
    response = client.get(
        f"/api/v1/saml/idps/{fake_id}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 404


def test_get_idp_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_idp
):
    """Regular admin cannot get IdP details."""
    response = client.get(
        f"/api/v1/saml/idps/{created_idp['id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Update IdP
# =============================================================================


def test_update_idp_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, created_idp
):
    """Super admin can update an IdP."""
    response = client.patch(
        f"/api/v1/saml/idps/{created_idp['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"name": "Updated IdP Name"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated IdP Name"
    # Other fields unchanged
    assert data["entity_id"] == created_idp["entity_id"]


def test_update_idp_not_found(client, test_tenant_host, oauth2_super_admin_header):
    """Updating non-existent IdP returns 404."""
    fake_id = str(uuid.uuid4())
    response = client.patch(
        f"/api/v1/saml/idps/{fake_id}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"name": "New Name"},
    )

    assert response.status_code == 404


def test_update_idp_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_idp
):
    """Regular admin cannot update an IdP."""
    response = client.patch(
        f"/api/v1/saml/idps/{created_idp['id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"name": "New Name"},
    )

    assert response.status_code == 403


# =============================================================================
# Delete IdP
# =============================================================================


def test_delete_idp_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, sample_idp_data
):
    """Super admin can delete an IdP."""
    # Create first
    create_response = client.post(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_idp_data,
    )
    idp_id = create_response.json()["id"]

    # Delete
    response = client.delete(
        f"/api/v1/saml/idps/{idp_id}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 204

    # Verify deleted
    get_response = client.get(
        f"/api/v1/saml/idps/{idp_id}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert get_response.status_code == 404


def test_delete_idp_not_found(client, test_tenant_host, oauth2_super_admin_header):
    """Deleting non-existent IdP returns 404."""
    fake_id = str(uuid.uuid4())
    response = client.delete(
        f"/api/v1/saml/idps/{fake_id}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 404


def test_delete_idp_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_idp
):
    """Regular admin cannot delete an IdP."""
    response = client.delete(
        f"/api/v1/saml/idps/{created_idp['id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Enable/Disable IdP
# =============================================================================


def test_enable_idp_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, sample_idp_data
):
    """Super admin can enable an IdP."""
    # Create disabled IdP
    sample_idp_data["is_enabled"] = False
    create_response = client.post(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=sample_idp_data,
    )
    idp_id = create_response.json()["id"]

    # Enable
    response = client.post(
        f"/api/v1/saml/idps/{idp_id}/enable",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    assert response.json()["is_enabled"] is True


def test_disable_idp_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, created_idp
):
    """Super admin can disable an IdP."""
    response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/disable",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    assert response.json()["is_enabled"] is False


def test_enable_idp_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_idp
):
    """Regular admin cannot enable an IdP."""
    response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/enable",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Set Default IdP
# =============================================================================


def test_set_default_idp_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, created_idp
):
    """Super admin can set an IdP as default."""
    response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/set-default",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    assert response.json()["is_default"] is True


def test_set_default_idp_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_idp
):
    """Regular admin cannot set default IdP."""
    response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/set-default",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# SP Certificate
# =============================================================================


def test_get_sp_certificate_as_super_admin(client, test_tenant_host, oauth2_super_admin_header):
    """Super admin can get SP certificate."""
    response = client.get(
        "/api/v1/saml/sp/certificate",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert "certificate_pem" in data
    assert "expires_at" in data
    assert "created_at" in data
    # Verify it's PEM format
    assert data["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")


def test_get_sp_certificate_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Regular admin cannot get SP certificate."""
    response = client.get(
        "/api/v1/saml/sp/certificate",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# SP Metadata
# =============================================================================


def test_get_sp_metadata_as_super_admin(client, test_tenant_host, oauth2_super_admin_header):
    """Super admin can get SP metadata info."""
    response = client.get(
        "/api/v1/saml/sp/metadata",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert "entity_id" in data
    assert "acs_url" in data
    assert "metadata_url" in data
    assert "certificate_pem" in data
    assert "certificate_expires_at" in data


def test_get_sp_metadata_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Regular admin cannot get SP metadata."""
    response = client.get(
        "/api/v1/saml/sp/metadata",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


# =============================================================================
# Metadata Refresh
# =============================================================================


def test_refresh_idp_metadata_no_url(
    client, test_tenant_host, oauth2_super_admin_header, created_idp
):
    """Refreshing IdP without metadata URL returns error."""
    response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/refresh",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    # Should fail because the created IdP doesn't have a metadata_url
    assert response.status_code == 400


def test_refresh_idp_metadata_not_found(client, test_tenant_host, oauth2_super_admin_header):
    """Refreshing non-existent IdP returns 404."""
    fake_id = str(uuid.uuid4())
    response = client.post(
        f"/api/v1/saml/idps/{fake_id}/refresh",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 404


# =============================================================================
# Import IdP from Metadata
# =============================================================================


def test_import_idp_as_admin_forbidden(client, test_tenant_host, oauth2_admin_authorization_header):
    """Regular admin cannot import IdP."""
    response = client.post(
        "/api/v1/saml/idps/import",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Imported IdP",
            "provider_type": "okta",
            "metadata_url": "https://idp.example.com/metadata",
        },
    )

    assert response.status_code == 403


# =============================================================================
# Import IdP from Raw XML
# =============================================================================


# Check if the SAML library is available for XML parsing tests
try:
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser  # noqa: F401

    HAS_SAML_LIBRARY = True
except ImportError:
    HAS_SAML_LIBRARY = False


@pytest.fixture
def sample_idp_metadata_xml():
    """Sample IdP metadata XML for testing import."""
    return """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://api-xml-import.example.com/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://api-xml-import.example.com/sso"/>
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://api-xml-import.example.com/slo"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_xml_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, sample_idp_metadata_xml
):
    """Super admin can import IdP from raw metadata XML."""
    response = client.post(
        "/api/v1/saml/idps/import-xml",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            "name": "API XML Imported IdP",
            "provider_type": "generic",
            "metadata_xml": sample_idp_metadata_xml,
        },
    )

    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "API XML Imported IdP"
    assert data["provider_type"] == "generic"
    assert data["entity_id"] == "https://api-xml-import.example.com/entity"
    assert data["sso_url"] == "https://api-xml-import.example.com/sso"
    assert data["slo_url"] == "https://api-xml-import.example.com/slo"
    assert data["metadata_url"] is None  # No URL - imported from raw XML
    assert "id" in data
    assert "sp_entity_id" in data
    assert "sp_acs_url" in data


def test_import_idp_from_xml_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Regular admin cannot import IdP from XML."""
    response = client.post(
        "/api/v1/saml/idps/import-xml",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "name": "Should Fail",
            "provider_type": "generic",
            "metadata_xml": "<xml/>",
        },
    )

    assert response.status_code == 403


def test_import_idp_from_xml_unauthenticated(client, test_tenant_host):
    """Unauthenticated request returns 401."""
    response = client.post(
        "/api/v1/saml/idps/import-xml",
        headers={"Host": test_tenant_host},
        json={
            "name": "Should Fail",
            "provider_type": "generic",
            "metadata_xml": "<xml/>",
        },
    )

    assert response.status_code == 401


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_xml_invalid_xml(client, test_tenant_host, oauth2_super_admin_header):
    """Invalid XML returns 400."""
    response = client.post(
        "/api/v1/saml/idps/import-xml",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            "name": "Invalid Import",
            "provider_type": "generic",
            "metadata_xml": "not valid xml",
        },
    )

    assert response.status_code == 400


def test_import_idp_from_xml_invalid_provider_type(
    client, test_tenant_host, oauth2_super_admin_header
):
    """Invalid provider type returns 422."""
    response = client.post(
        "/api/v1/saml/idps/import-xml",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            "name": "Invalid Provider",
            "provider_type": "invalid_type",
            "metadata_xml": "<xml/>",
        },
    )

    assert response.status_code == 422


def test_import_idp_from_xml_missing_fields(client, test_tenant_host, oauth2_super_admin_header):
    """Missing required fields returns 422."""
    response = client.post(
        "/api/v1/saml/idps/import-xml",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={
            "name": "Missing Fields",
            # Missing provider_type and metadata_xml
        },
    )

    assert response.status_code == 422


# =============================================================================
# SAML Phase 4: Provider Presets API Tests
# =============================================================================


def test_get_provider_presets_okta(client, test_tenant_host):
    """Get Okta provider presets (no auth required)."""
    response = client.get(
        "/api/v1/saml/provider-presets/okta",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["provider_type"] == "okta"
    assert "attribute_mapping" in data
    assert data["attribute_mapping"]["email"] == "email"
    assert data["attribute_mapping"]["first_name"] == "firstName"
    assert data["attribute_mapping"]["last_name"] == "lastName"
    assert "setup_guide_url" in data


def test_get_provider_presets_azure_ad(client, test_tenant_host):
    """Get Azure AD provider presets with full URN claim names."""
    response = client.get(
        "/api/v1/saml/provider-presets/azure_ad",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["provider_type"] == "azure_ad"
    assert "xmlsoap.org" in data["attribute_mapping"]["email"]  # Full URN format
    assert "setup_guide_url" in data


def test_get_provider_presets_google(client, test_tenant_host):
    """Get Google provider presets."""
    response = client.get(
        "/api/v1/saml/provider-presets/google",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["provider_type"] == "google"
    assert data["attribute_mapping"]["first_name"] == "first_name"  # Underscore format
    assert "setup_guide_url" in data


def test_get_provider_presets_generic(client, test_tenant_host):
    """Get generic provider presets (fallback)."""
    response = client.get(
        "/api/v1/saml/provider-presets/generic",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["provider_type"] == "generic"


def test_get_provider_presets_unknown(client, test_tenant_host):
    """Unknown provider type returns 404."""
    response = client.get(
        "/api/v1/saml/provider-presets/unknown_provider",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 404


# =============================================================================
# SAML Phase 4: Certificate Rotation API Tests
# =============================================================================


def test_rotate_sp_certificate_as_super_admin(
    client, test_tenant_host, oauth2_super_admin_header, fast_sp_certificate
):
    """Super admin can rotate SP certificate."""
    # First ensure a certificate exists (creates one if not)
    get_response = client.get(
        "/api/v1/saml/sp/certificate",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert get_response.status_code == 200

    # Now rotate
    response = client.post(
        "/api/v1/saml/sp/certificate/rotate",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert "new_certificate_pem" in data
    assert data["new_certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "new_expires_at" in data
    assert "grace_period_ends_at" in data
    assert "warning" in data


def test_rotate_sp_certificate_custom_grace_period(
    client, test_tenant_host, oauth2_super_admin_header, fast_sp_certificate
):
    """Certificate rotation with custom grace period."""
    # First ensure a certificate exists (creates one if not)
    get_response = client.get(
        "/api/v1/saml/sp/certificate",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )
    assert get_response.status_code == 200

    # Now rotate with custom grace period
    response = client.post(
        "/api/v1/saml/sp/certificate/rotate?grace_period_days=14",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    # Grace period should be ~14 days from now
    assert "grace_period_ends_at" in data


def test_rotate_sp_certificate_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Regular admin cannot rotate SP certificate."""
    response = client.post(
        "/api/v1/saml/sp/certificate/rotate",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


def test_rotate_sp_certificate_unauthenticated(client, test_tenant_host):
    """Unauthenticated request returns 401."""
    response = client.post(
        "/api/v1/saml/sp/certificate/rotate",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


# =============================================================================
# Domain Binding API Tests (Phase 3)
# =============================================================================


@pytest.fixture
def privileged_domain(test_tenant, test_super_admin_user):
    """Create a privileged domain for domain binding tests."""
    import database

    domain_id = str(uuid.uuid4())
    database.execute(
        test_tenant["id"],
        """INSERT INTO tenant_privileged_domains (id, tenant_id, domain, created_by)
        VALUES (:id, :tenant_id, :domain, :created_by)""",
        {
            "id": domain_id,
            "tenant_id": test_tenant["id"],
            "domain": "test-binding.example.com",
            "created_by": test_super_admin_user["id"],
        },
    )
    return {"id": domain_id, "domain": "test-binding.example.com"}


def test_list_idp_domain_bindings_empty(
    client, test_tenant_host, oauth2_super_admin_header, created_idp
):
    """List domain bindings for IdP with no bindings."""
    response = client.get(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["items"] == []


def test_list_idp_domain_bindings_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_idp
):
    """Regular admin cannot list domain bindings."""
    response = client.get(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


def test_list_idp_domain_bindings_unauthenticated(client, test_tenant_host, created_idp):
    """Unauthenticated request returns 401."""
    response = client.get(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


def test_bind_domain_to_idp_success(
    client, test_tenant_host, oauth2_super_admin_header, created_idp, privileged_domain
):
    """Super admin can bind a domain to an IdP."""
    response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"domain_id": privileged_domain["id"]},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["domain_id"] == privileged_domain["id"]
    assert data["domain"] == privileged_domain["domain"]
    assert data["idp_id"] == created_idp["id"]


def test_bind_domain_to_idp_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_idp, privileged_domain
):
    """Regular admin cannot bind domains."""
    response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"domain_id": privileged_domain["id"]},
    )

    assert response.status_code == 403


def test_bind_domain_to_idp_invalid_domain(
    client, test_tenant_host, oauth2_super_admin_header, created_idp
):
    """Binding non-existent domain returns 404."""
    response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"domain_id": str(uuid.uuid4())},
    )

    assert response.status_code == 404


def test_bind_domain_to_idp_invalid_idp(
    client, test_tenant_host, oauth2_super_admin_header, privileged_domain
):
    """Binding to non-existent IdP returns 404."""
    response = client.post(
        f"/api/v1/saml/idps/{str(uuid.uuid4())}/domains",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"domain_id": privileged_domain["id"]},
    )

    assert response.status_code == 404


def test_list_idp_domain_bindings_with_binding(
    client, test_tenant_host, oauth2_super_admin_header, created_idp, privileged_domain
):
    """List domain bindings after binding a domain."""
    # First bind the domain
    bind_response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"domain_id": privileged_domain["id"]},
    )
    assert bind_response.status_code == 201

    # Then list bindings
    response = client.get(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["domain"] == privileged_domain["domain"]


def test_unbind_domain_from_idp_success(
    client, test_tenant_host, oauth2_super_admin_header, created_idp, privileged_domain
):
    """Super admin can unbind a domain from an IdP."""
    # First bind the domain
    bind_response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"domain_id": privileged_domain["id"]},
    )
    assert bind_response.status_code == 201

    # Then unbind
    response = client.delete(
        f"/api/v1/saml/idps/{created_idp['id']}/domains/{privileged_domain['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 204


def test_unbind_domain_from_idp_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_idp, privileged_domain
):
    """Regular admin cannot unbind domains."""
    response = client.delete(
        f"/api/v1/saml/idps/{created_idp['id']}/domains/{privileged_domain['id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


def test_unbind_domain_not_bound(
    client, test_tenant_host, oauth2_super_admin_header, created_idp, privileged_domain
):
    """Unbinding a domain that's not bound returns 404."""
    response = client.delete(
        f"/api/v1/saml/idps/{created_idp['id']}/domains/{privileged_domain['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 404


def test_rebind_domain_to_different_idp(
    client,
    test_tenant_host,
    oauth2_super_admin_header,
    created_idp,
    privileged_domain,
    sample_idp_data,
    fast_sp_certificate,
):
    """Super admin can rebind a domain to a different IdP."""
    # First bind the domain to created_idp
    bind_response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"domain_id": privileged_domain["id"]},
    )
    assert bind_response.status_code == 201

    # Create a second IdP with unique entity_id
    second_idp_data = {
        **sample_idp_data,
        "name": "Second IdP",
        "entity_id": f"https://second-idp.example.com/metadata/{uuid.uuid4()}",
    }
    create_response = client.post(
        "/api/v1/saml/idps",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json=second_idp_data,
    )
    assert create_response.status_code == 201
    second_idp = create_response.json()

    # Rebind to second IdP
    response = client.put(
        f"/api/v1/saml/idps/{second_idp['id']}/domains/{privileged_domain['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["idp_id"] == second_idp["id"]
    assert data["domain_id"] == privileged_domain["id"]


def test_rebind_domain_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header, created_idp, privileged_domain
):
    """Regular admin cannot rebind domains."""
    response = client.put(
        f"/api/v1/saml/idps/{created_idp['id']}/domains/{privileged_domain['id']}",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


def test_rebind_domain_not_bound(
    client, test_tenant_host, oauth2_super_admin_header, created_idp, privileged_domain
):
    """Rebinding a domain that's not bound returns 404."""
    response = client.put(
        f"/api/v1/saml/idps/{created_idp['id']}/domains/{privileged_domain['id']}",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 404


def test_get_unbound_domains(
    client, test_tenant_host, oauth2_super_admin_header, privileged_domain
):
    """Super admin can list unbound domains."""
    response = client.get(
        "/api/v1/saml/domains/unbound",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # The privileged_domain should be in the unbound list
    domain_ids = [d["id"] for d in data]
    assert privileged_domain["id"] in domain_ids


def test_get_unbound_domains_as_admin_forbidden(
    client, test_tenant_host, oauth2_admin_authorization_header
):
    """Regular admin cannot list unbound domains."""
    response = client.get(
        "/api/v1/saml/domains/unbound",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


def test_get_unbound_domains_unauthenticated(client, test_tenant_host):
    """Unauthenticated request returns 401."""
    response = client.get(
        "/api/v1/saml/domains/unbound",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


def test_get_unbound_domains_excludes_bound(
    client, test_tenant_host, oauth2_super_admin_header, created_idp, privileged_domain
):
    """Bound domains are excluded from unbound list."""
    # First bind the domain
    bind_response = client.post(
        f"/api/v1/saml/idps/{created_idp['id']}/domains",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
        json={"domain_id": privileged_domain["id"]},
    )
    assert bind_response.status_code == 201

    # Then check unbound list
    response = client.get(
        "/api/v1/saml/domains/unbound",
        headers={"Host": test_tenant_host, **oauth2_super_admin_header},
    )

    assert response.status_code == 200
    data = response.json()
    domain_ids = [d["id"] for d in data]
    assert privileged_domain["id"] not in domain_ids


# =============================================================================
# Email Auth Routing API Tests (Phase 3)
# =============================================================================


def test_check_email_auth_route_user_not_found(client, test_tenant_host):
    """Check auth route for non-existent user."""
    response = client.post(
        "/api/v1/saml/auth/check-email",
        headers={"Host": test_tenant_host},
        json={"email": "nonexistent@example.com"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["route_type"] == "not_found"
    assert data["idp_id"] is None


def test_check_email_auth_route_password_user(client, test_tenant_host, test_user):
    """Check auth route for user with password."""
    import database.user_emails

    # Get the user's email
    emails = database.user_emails.list_user_emails(test_user["tenant_id"], str(test_user["id"]))
    user_email = emails[0]["email"]

    response = client.post(
        "/api/v1/saml/auth/check-email",
        headers={"Host": test_tenant_host},
        json={"email": user_email},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["route_type"] == "password"
    assert data["idp_id"] is None


def test_check_email_auth_route_idp_user(
    client, test_tenant_host, test_user, created_idp, oauth2_super_admin_header
):
    """Check auth route for user assigned to IdP."""
    import database
    import database.user_emails

    # Assign user to IdP
    database.execute(
        test_user["tenant_id"],
        "UPDATE users SET saml_idp_id = :idp_id WHERE id = :user_id",
        {"idp_id": created_idp["id"], "user_id": test_user["id"]},
    )

    # Get the user's email
    emails = database.user_emails.list_user_emails(test_user["tenant_id"], str(test_user["id"]))
    user_email = emails[0]["email"]

    response = client.post(
        "/api/v1/saml/auth/check-email",
        headers={"Host": test_tenant_host},
        json={"email": user_email},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["route_type"] == "idp"
    assert data["idp_id"] == created_idp["id"]
    assert data["idp_name"] == created_idp["name"]

    # Clean up
    database.execute(
        test_user["tenant_id"],
        "UPDATE users SET saml_idp_id = NULL WHERE id = :user_id",
        {"user_id": test_user["id"]},
    )


def test_check_email_auth_route_inactivated_user(client, test_tenant_host, test_user):
    """Check auth route for inactivated user."""
    import database
    import database.user_emails

    # Inactivate user
    database.execute(
        test_user["tenant_id"],
        "UPDATE users SET is_inactivated = true WHERE id = :user_id",
        {"user_id": test_user["id"]},
    )

    # Get the user's email
    emails = database.user_emails.list_user_emails(test_user["tenant_id"], str(test_user["id"]))
    user_email = emails[0]["email"]

    response = client.post(
        "/api/v1/saml/auth/check-email",
        headers={"Host": test_tenant_host},
        json={"email": user_email},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["route_type"] == "inactivated"

    # Clean up
    database.execute(
        test_user["tenant_id"],
        "UPDATE users SET is_inactivated = false WHERE id = :user_id",
        {"user_id": test_user["id"]},
    )
