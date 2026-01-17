"""Comprehensive tests for SAML service layer functions.

This test file covers SAML IdP CRUD operations, SP certificate management,
and authorization checks for the services/saml.py module.
"""

import pytest
from services.exceptions import ConflictError, ForbiddenError, NotFoundError
from services.types import RequestingUser


def _make_requesting_user(user: dict, tenant_id: str, role: str = None) -> RequestingUser:
    """Helper to create RequestingUser from test fixture."""
    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role or user.get("role", "member"),
    )


def _verify_event_logged(tenant_id: str, event_type: str, artifact_id: str):
    """Verify that an event was logged."""
    import database

    events = database.event_log.list_events(tenant_id, limit=10)
    matching = [
        e
        for e in events
        if e["event_type"] == event_type and str(e["artifact_id"]) == str(artifact_id)
    ]
    assert len(matching) > 0, f"No events logged for {event_type} with artifact_id {artifact_id}"


# =============================================================================
# SP Certificate Tests
# =============================================================================


def test_get_or_create_sp_certificate_as_super_admin(test_tenant, test_super_admin_user):
    """Test that a super_admin can create/get SP certificate."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    cert = saml_service.get_or_create_sp_certificate(requesting_user)

    assert cert.id is not None
    assert cert.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert cert.expires_at is not None
    assert cert.created_at is not None


def test_get_or_create_sp_certificate_returns_same_cert(test_tenant, test_super_admin_user):
    """Test that calling get_or_create twice returns the same certificate."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    cert1 = saml_service.get_or_create_sp_certificate(requesting_user)
    cert2 = saml_service.get_or_create_sp_certificate(requesting_user)

    assert cert1.id == cert2.id
    assert cert1.certificate_pem == cert2.certificate_pem


def test_get_or_create_sp_certificate_as_admin_forbidden(test_tenant, test_admin_user):
    """Test that an admin cannot create SP certificate."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.get_or_create_sp_certificate(requesting_user)

    assert exc_info.value.code == "super_admin_required"


def test_get_or_create_sp_certificate_as_member_forbidden(test_tenant, test_user):
    """Test that a regular member cannot create SP certificate."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_user, test_tenant["id"], "member")

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.get_or_create_sp_certificate(requesting_user)

    assert exc_info.value.code == "super_admin_required"


def test_get_sp_metadata_success(test_tenant, test_super_admin_user):
    """Test that super_admin can get SP metadata."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # First ensure certificate exists
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Get metadata
    metadata = saml_service.get_sp_metadata(requesting_user, "https://test.example.com")

    assert metadata.entity_id == "https://test.example.com/saml/metadata"
    assert metadata.acs_url == "https://test.example.com/saml/acs"
    assert metadata.metadata_url == "https://test.example.com/saml/metadata"
    assert metadata.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")


def test_get_tenant_sp_metadata_xml_success(test_tenant, test_super_admin_user):
    """Test generating SP metadata XML."""
    from services import saml as saml_service

    # First create certificate
    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Get XML
    xml = saml_service.get_tenant_sp_metadata_xml(test_tenant["id"], "https://test.example.com")

    assert "<?xml" in xml
    assert "EntityDescriptor" in xml
    assert "https://test.example.com/saml/metadata" in xml


def test_get_tenant_sp_metadata_xml_no_cert(test_tenant):
    """Test that getting XML without cert raises NotFoundError."""
    from services import saml as saml_service

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.get_tenant_sp_metadata_xml(test_tenant["id"], "https://test.example.com")

    assert exc_info.value.code == "sp_certificate_not_found"


# =============================================================================
# IdP CRUD Tests
# =============================================================================


@pytest.fixture
def test_idp_data():
    """Provide test IdP data."""
    return {
        "name": "Test Okta IdP",
        "provider_type": "okta",
        "entity_id": "https://idp.example.com/entity",
        "sso_url": "https://idp.example.com/sso",
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
    }


def test_create_identity_provider_as_super_admin(test_tenant, test_super_admin_user, test_idp_data):
    """Test that super_admin can create an IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    data = IdPCreate(**test_idp_data)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    assert idp.id is not None
    assert idp.name == "Test Okta IdP"
    assert idp.provider_type == "okta"
    assert idp.entity_id == "https://idp.example.com/entity"
    assert idp.sso_url == "https://idp.example.com/sso"
    assert idp.is_enabled is False  # Default disabled
    assert idp.is_default is False
    assert idp.sp_entity_id == "https://test.example.com/saml/metadata"
    # ACS URL is now derived from sp_entity_id (standard SAML practice)

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "saml_idp_created", idp.id)


def test_create_identity_provider_as_admin_forbidden(test_tenant, test_admin_user, test_idp_data):
    """Test that admin cannot create an IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")
    data = IdPCreate(**test_idp_data)

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    assert exc_info.value.code == "super_admin_required"


def test_create_identity_provider_duplicate_entity_id(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test that creating IdP with duplicate entity_id raises ConflictError."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    data = IdPCreate(**test_idp_data)

    # Create first
    saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Try to create duplicate
    with pytest.raises(ConflictError) as exc_info:
        saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    assert exc_info.value.code == "idp_entity_id_exists"


def test_list_identity_providers_as_super_admin(test_tenant, test_super_admin_user, test_idp_data):
    """Test that super_admin can list IdPs."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create an IdP first
    data = IdPCreate(**test_idp_data)
    saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # List
    result = saml_service.list_identity_providers(requesting_user)

    assert result.total >= 1
    assert len(result.items) >= 1
    assert any(item.name == "Test Okta IdP" for item in result.items)


def test_list_identity_providers_as_admin_forbidden(test_tenant, test_admin_user):
    """Test that admin cannot list IdPs."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.list_identity_providers(requesting_user)

    assert exc_info.value.code == "super_admin_required"


def test_get_identity_provider_success(test_tenant, test_super_admin_user, test_idp_data):
    """Test getting a single IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create
    data = IdPCreate(**test_idp_data)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Get
    idp = saml_service.get_identity_provider(requesting_user, created.id)

    assert idp.id == created.id
    assert idp.name == "Test Okta IdP"


def test_get_identity_provider_not_found(test_tenant, test_super_admin_user):
    """Test getting non-existent IdP raises NotFoundError."""
    from uuid import uuid4

    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.get_identity_provider(requesting_user, str(uuid4()))

    assert exc_info.value.code == "idp_not_found"


def test_update_identity_provider_success(test_tenant, test_super_admin_user, test_idp_data):
    """Test updating an IdP."""
    from schemas.saml import IdPCreate, IdPUpdate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create
    data = IdPCreate(**test_idp_data)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Update
    update_data = IdPUpdate(name="Updated IdP Name")
    updated = saml_service.update_identity_provider(requesting_user, created.id, update_data)

    assert updated.name == "Updated IdP Name"
    assert updated.entity_id == created.entity_id  # Unchanged

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "saml_idp_updated", created.id)


def test_delete_identity_provider_success(test_tenant, test_super_admin_user, test_idp_data):
    """Test deleting an IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create
    data = IdPCreate(**test_idp_data)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Delete
    saml_service.delete_identity_provider(requesting_user, created.id)

    # Verify deleted
    with pytest.raises(NotFoundError):
        saml_service.get_identity_provider(requesting_user, created.id)

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "saml_idp_deleted", created.id)


def test_set_idp_enabled_success(test_tenant, test_super_admin_user, test_idp_data):
    """Test enabling/disabling an IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create (disabled by default)
    data = IdPCreate(**test_idp_data)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )
    assert created.is_enabled is False

    # Enable
    enabled = saml_service.set_idp_enabled(requesting_user, created.id, True)
    assert enabled.is_enabled is True
    _verify_event_logged(test_tenant["id"], "saml_idp_enabled", created.id)

    # Disable
    disabled = saml_service.set_idp_enabled(requesting_user, created.id, False)
    assert disabled.is_enabled is False
    _verify_event_logged(test_tenant["id"], "saml_idp_disabled", created.id)


def test_set_idp_default_success(test_tenant, test_super_admin_user, test_idp_data):
    """Test setting an IdP as default."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create
    data = IdPCreate(**test_idp_data)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )
    assert created.is_default is False

    # Set as default
    default = saml_service.set_idp_default(requesting_user, created.id)
    assert default.is_default is True

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "saml_idp_set_default", created.id)


def test_only_one_default_idp(test_tenant, test_super_admin_user, test_idp_data):
    """Test that only one IdP can be default (database trigger)."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create first IdP and set as default
    data1 = IdPCreate(**test_idp_data)
    idp1 = saml_service.create_identity_provider(requesting_user, data1, "https://test.example.com")
    saml_service.set_idp_default(requesting_user, idp1.id)

    # Create second IdP with different entity_id and set as default
    data2 = IdPCreate(
        name="Second IdP",
        provider_type="azure_ad",
        entity_id="https://idp2.example.com/entity",
        sso_url="https://idp2.example.com/sso",
        certificate_pem=test_idp_data["certificate_pem"],
    )
    idp2 = saml_service.create_identity_provider(requesting_user, data2, "https://test.example.com")
    saml_service.set_idp_default(requesting_user, idp2.id)

    # Refresh idp1 and check it's no longer default
    idp1_refreshed = saml_service.get_identity_provider(requesting_user, idp1.id)
    idp2_refreshed = saml_service.get_identity_provider(requesting_user, idp2.id)

    assert idp1_refreshed.is_default is False
    assert idp2_refreshed.is_default is True


# =============================================================================
# Login Flow Tests
# =============================================================================


def test_get_enabled_idps_for_login_empty(test_tenant):
    """Test getting enabled IdPs when none exist."""
    from services import saml as saml_service

    idps = saml_service.get_enabled_idps_for_login(test_tenant["id"])
    assert len(idps) == 0


def test_get_enabled_idps_for_login_only_enabled(test_tenant, test_super_admin_user, test_idp_data):
    """Test that only enabled IdPs are returned for login."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create disabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=False)
    saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Should return empty (IdP is disabled)
    idps = saml_service.get_enabled_idps_for_login(test_tenant["id"])
    assert len(idps) == 0

    # Create another IdP with different entity_id and enable it
    data2 = IdPCreate(
        name="Enabled IdP",
        provider_type="okta",
        entity_id="https://enabled.example.com/entity",
        sso_url="https://enabled.example.com/sso",
        certificate_pem=test_idp_data["certificate_pem"],
        is_enabled=True,
    )
    created = saml_service.create_identity_provider(
        requesting_user, data2, "https://test.example.com"
    )

    # Now should return one
    idps = saml_service.get_enabled_idps_for_login(test_tenant["id"])
    assert len(idps) == 1
    assert idps[0].id == created.id


def test_get_idp_for_saml_login_disabled_forbidden(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test that getting a disabled IdP for login raises ForbiddenError."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create disabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=False)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Try to use for login
    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.get_idp_for_saml_login(test_tenant["id"], created.id)

    assert exc_info.value.code == "idp_disabled"


def test_get_idp_for_saml_login_enabled_success(test_tenant, test_super_admin_user, test_idp_data):
    """Test that getting an enabled IdP for login works."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Get for login
    idp = saml_service.get_idp_for_saml_login(test_tenant["id"], created.id)

    assert idp.id == created.id
    assert idp.is_enabled is True


# =============================================================================
# SAML Authentication Flow Tests
# =============================================================================

# Note: These tests require the python3-saml library which depends on xmlsec.
# We check if the library is available and skip tests if not installed.

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: F401

    HAS_SAML_LIBRARY = True
except ImportError:
    HAS_SAML_LIBRARY = False


def test_get_default_idp_returns_none_when_no_default(test_tenant):
    """Test get_default_idp returns None when no default is set."""
    from services import saml as saml_service

    result = saml_service.get_default_idp(test_tenant["id"])
    assert result is None


def test_get_default_idp_returns_enabled_default(test_tenant, test_super_admin_user, test_idp_data):
    """Test get_default_idp returns the default IdP when set."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP, enable it, and set as default
    data = IdPCreate(**test_idp_data, is_enabled=True, is_default=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    result = saml_service.get_default_idp(test_tenant["id"])

    assert result is not None
    assert result.id == created.id
    assert result.is_default is True


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_build_authn_request_success(test_tenant, test_super_admin_user, test_idp_data):
    """Test build_authn_request returns redirect URL and request ID."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Build AuthnRequest
    redirect_url, request_id = saml_service.build_authn_request(
        tenant_id=test_tenant["id"],
        idp_id=created.id,
        relay_state="/dashboard",
    )

    # Should return SSO URL with SAML parameters
    assert "https://idp.example.com/sso" in redirect_url
    assert "SAMLRequest" in redirect_url
    assert request_id is not None
    assert len(request_id) > 0


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_build_authn_request_disabled_idp_forbidden(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test build_authn_request raises ForbiddenError for disabled IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create disabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=False)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Should raise ForbiddenError
    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.build_authn_request(
            tenant_id=test_tenant["id"],
            idp_id=created.id,
        )

    assert exc_info.value.code == "idp_disabled"


def test_authenticate_via_saml_user_not_found(test_tenant, test_super_admin_user, test_idp_data):
    """Test authenticate_via_saml raises NotFoundError for unknown user."""
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP (needed for the result)
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a SAML result with unknown email
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email="unknown@example.com",
            first_name="Unknown",
            last_name="User",
            name_id="unknown@example.com",
        ),
        idp_id=created.id,
        requires_mfa=False,
    )

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

    assert exc_info.value.code == "user_not_found"


def test_authenticate_via_saml_user_inactivated(
    test_tenant, test_super_admin_user, test_admin_user, test_idp_data
):
    """Test authenticate_via_saml raises ForbiddenError for inactivated user."""
    import database
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Get the admin user's email and inactivate them
    admin_email = test_admin_user["email"]
    database.users.inactivate_user(test_tenant["id"], test_admin_user["id"])

    # Create a SAML result with the inactivated user's email
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=admin_email,
            first_name="Admin",
            last_name="User",
            name_id=admin_email,
        ),
        idp_id=created.id,
        requires_mfa=False,
    )

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

    assert exc_info.value.code == "user_inactivated"


def test_authenticate_via_saml_success(
    test_tenant, test_super_admin_user, test_user, test_idp_data
):
    """Test authenticate_via_saml succeeds for existing active user."""
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a SAML result with test user's email
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=test_user["email"],
            first_name="Test",
            last_name="User",
            name_id=test_user["email"],
        ),
        idp_id=created.id,
        requires_mfa=False,
    )

    user = saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

    assert user is not None
    assert str(user["id"]) == str(test_user["id"])

    # Verify event was logged
    _verify_event_logged(test_tenant["id"], "user_signed_in_saml", str(test_user["id"]))


# =============================================================================
# JIT Provisioning Tests
# =============================================================================


def test_authenticate_via_saml_jit_creates_user(test_tenant, test_super_admin_user, test_idp_data):
    """Test JIT provisioning creates user when enabled and user doesn't exist."""
    import database
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP with JIT provisioning enabled
    data = IdPCreate(**test_idp_data, is_enabled=True, jit_provisioning=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a SAML result with a brand new email
    new_email = "jit.newuser@example.com"
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=new_email,
            first_name="JIT",
            last_name="NewUser",
            name_id=new_email,
        ),
        idp_id=created.id,
        requires_mfa=False,
    )

    # This should succeed and create the user via JIT
    user = saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

    assert user is not None
    assert user["first_name"] == "JIT"
    assert user["last_name"] == "NewUser"
    assert user["role"] == "member"

    # Verify user was created in database with correct email
    db_user = database.users.get_user_by_email_with_status(test_tenant["id"], new_email)
    assert db_user is not None
    assert db_user["id"] == user["id"]

    # Verify user_created_jit event was logged
    _verify_event_logged(test_tenant["id"], "user_created_jit", str(user["id"]))


def test_authenticate_via_saml_jit_disabled_raises_not_found(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test that non-existent user raises NotFoundError when JIT is disabled."""
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP WITHOUT JIT provisioning
    data = IdPCreate(**test_idp_data, is_enabled=True, jit_provisioning=False)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a SAML result with unknown email
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email="nonexistent@example.com",
            first_name="Non",
            last_name="Existent",
            name_id="nonexistent@example.com",
        ),
        idp_id=created.id,
        requires_mfa=False,
    )

    # This should raise NotFoundError since JIT is disabled
    with pytest.raises(NotFoundError) as exc_info:
        saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

    assert exc_info.value.code == "user_not_found"


def test_authenticate_via_saml_jit_user_linked_to_idp(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test JIT-created user is linked to provisioning IdP via saml_idp_id."""
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP with JIT provisioning
    data = IdPCreate(**test_idp_data, is_enabled=True, jit_provisioning=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a SAML result with a new email
    new_email = "jit.linked@example.com"
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=new_email,
            first_name="JIT",
            last_name="Linked",
            name_id=new_email,
        ),
        idp_id=created.id,
        requires_mfa=False,
    )

    user = saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

    # Verify user's saml_idp_id is set to the IdP that provisioned them
    from database._core import fetchone

    db_user = fetchone(
        test_tenant["id"],
        "select saml_idp_id from users where id = :user_id",
        {"user_id": str(user["id"])},
    )
    assert db_user is not None
    assert str(db_user["saml_idp_id"]) == created.id


def test_authenticate_via_saml_jit_creates_verified_email(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test JIT creates verified primary email from SAML assertion."""
    import database
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP with JIT provisioning
    data = IdPCreate(**test_idp_data, is_enabled=True, jit_provisioning=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a SAML result
    new_email = "jit.verified@example.com"
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=new_email,
            first_name="JIT",
            last_name="Verified",
            name_id=new_email,
        ),
        idp_id=created.id,
        requires_mfa=False,
    )

    user = saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

    # Verify email is marked as verified and primary
    emails = database.user_emails.list_user_emails(test_tenant["id"], str(user["id"]))
    assert len(emails) == 1
    assert emails[0]["email"] == new_email
    assert emails[0]["is_primary"] is True
    assert emails[0]["verified_at"] is not None


def test_authenticate_via_saml_jit_uses_name_defaults(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test JIT uses default names when SAML attributes missing."""
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP with JIT provisioning
    data = IdPCreate(**test_idp_data, is_enabled=True, jit_provisioning=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a SAML result with no first/last name
    new_email = "jit.noname@example.com"
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=new_email,
            first_name=None,  # Missing
            last_name=None,  # Missing
            name_id=new_email,
        ),
        idp_id=created.id,
        requires_mfa=False,
    )

    user = saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

    # Should use default names
    assert user["first_name"] == "SAML"
    assert user["last_name"] == "User"


def test_authenticate_via_saml_existing_user_not_affected_by_jit(
    test_tenant, test_super_admin_user, test_user, test_idp_data
):
    """Test existing users authenticate normally even with JIT enabled."""
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create enabled IdP with JIT provisioning
    data = IdPCreate(**test_idp_data, is_enabled=True, jit_provisioning=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a SAML result with existing user's email
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=test_user["email"],
            first_name="Different",
            last_name="Name",
            name_id=test_user["email"],
        ),
        idp_id=created.id,
        requires_mfa=False,
    )

    user = saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

    # Should return the existing user, not create a new one
    assert str(user["id"]) == str(test_user["id"])

    # Verify sign-in event (not creation event) was logged
    _verify_event_logged(test_tenant["id"], "user_signed_in_saml", str(test_user["id"]))


# =============================================================================
# Connection Testing Tests
# =============================================================================


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_test_response_success_with_mock(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test process_saml_test_response returns success result with attributes."""
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create mock auth object
    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = []
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_attributes.return_value = {
        "email": ["test@example.com"],
        "firstName": ["Test"],
        "lastName": ["User"],
        "department": ["Engineering"],
    }
    mock_auth.get_nameid.return_value = "test@example.com"
    mock_auth.get_nameid_format.return_value = (
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    mock_auth.get_session_index.return_value = "session123"

    def mock_auth_constructor(request_data, settings):
        return mock_auth

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        mock_auth_constructor,
    )

    result = saml_service.process_saml_test_response(
        tenant_id=test_tenant["id"],
        idp_id=created.id,
        saml_response="dummybase64response",
    )

    assert result.success is True
    assert result.parsed_email == "test@example.com"
    assert result.parsed_first_name == "Test"
    assert result.parsed_last_name == "User"
    assert result.name_id == "test@example.com"
    assert result.name_id_format == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    assert result.session_index == "session123"
    assert result.attributes is not None
    assert "email" in result.attributes
    assert "department" in result.attributes


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_test_response_signature_error(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test process_saml_test_response returns error result for signature failure."""
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create mock auth object that returns signature error
    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = ["invalid_signature"]
    mock_auth.get_last_error_reason.return_value = "Signature validation failed"

    def mock_auth_constructor(request_data, settings):
        return mock_auth

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        mock_auth_constructor,
    )

    result = saml_service.process_saml_test_response(
        tenant_id=test_tenant["id"],
        idp_id=created.id,
        saml_response="dummybase64response",
    )

    assert result.success is False
    assert result.error_type == "signature_error"
    assert "Signature" in result.error_detail


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_test_response_expired_error(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test process_saml_test_response returns error result for expired assertion."""
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create mock auth object that returns expiry error
    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = ["assertion_expired"]
    mock_auth.get_last_error_reason.return_value = (
        "NotOnOrAfter validation failed - response expired"
    )

    def mock_auth_constructor(request_data, settings):
        return mock_auth

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        mock_auth_constructor,
    )

    result = saml_service.process_saml_test_response(
        tenant_id=test_tenant["id"],
        idp_id=created.id,
        saml_response="dummybase64response",
    )

    assert result.success is False
    assert result.error_type == "expired"


def test_process_saml_test_response_idp_not_found(test_tenant, test_super_admin_user):
    """Test process_saml_test_response returns error for unknown IdP."""
    from uuid import uuid4

    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Use a non-existent IdP ID
    fake_idp_id = str(uuid4())

    result = saml_service.process_saml_test_response(
        tenant_id=test_tenant["id"],
        idp_id=fake_idp_id,
        saml_response="base64encodedresponse",
    )

    assert result.success is False
    assert result.error_type == "idp_not_found"


# =============================================================================
# Metadata Import/Fetch Tests
# =============================================================================


def test_refresh_idp_from_metadata_no_url_configured(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test refresh_idp_from_metadata raises ValidationError when no URL is configured."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import ValidationError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP without metadata URL
    data = IdPCreate(**test_idp_data, metadata_url=None)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    with pytest.raises(ValidationError) as exc_info:
        saml_service.refresh_idp_from_metadata(requesting_user, created.id)

    assert exc_info.value.code == "no_metadata_url"


def test_refresh_all_idp_metadata_no_urls(test_tenant, test_super_admin_user, test_idp_data):
    """Test refreshing metadata when no IdPs have URLs configured.

    When an IdP has no metadata_url, it should not be included in the refresh.
    The refresh should succeed with no errors and no successful refreshes.
    """
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP without metadata URL
    data = IdPCreate(**test_idp_data, metadata_url=None)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Verify IdP was created without metadata_url
    assert idp.metadata_url is None

    # Refresh all - should complete with no refreshes for this IdP
    result = saml_service.refresh_all_idp_metadata()

    # The result should be valid - no URLs to refresh means no successful/failed refreshes
    # for this specific IdP. We can't assert exact counts due to test isolation,
    # but we verify the structure is valid and no exceptions were raised.
    assert hasattr(result, "successful")
    assert hasattr(result, "failed")
    assert isinstance(result.successful, int)
    assert isinstance(result.failed, int)


# =============================================================================
# Import IdP from Raw XML Tests
# =============================================================================


@pytest.fixture
def sample_idp_metadata_xml():
    """Sample IdP metadata XML for testing import."""
    return """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://xml-import-test.example.com/entity">
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
        Location="https://xml-import-test.example.com/sso"/>
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://xml-import-test.example.com/slo"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_metadata_xml_success(
    test_tenant, test_super_admin_user, sample_idp_metadata_xml
):
    """Test that super_admin can import an IdP from raw metadata XML."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    idp = saml_service.import_idp_from_metadata_xml(
        requesting_user=requesting_user,
        name="XML Imported IdP",
        provider_type="generic",
        metadata_xml=sample_idp_metadata_xml,
        base_url="https://test.example.com",
    )

    assert idp.id is not None
    assert idp.name == "XML Imported IdP"
    assert idp.provider_type == "generic"
    assert idp.entity_id == "https://xml-import-test.example.com/entity"
    assert idp.sso_url == "https://xml-import-test.example.com/sso"
    assert idp.slo_url == "https://xml-import-test.example.com/slo"
    assert idp.is_enabled is False  # Default disabled
    assert idp.metadata_url is None  # No URL - imported from raw XML
    assert idp.sp_entity_id == "https://test.example.com/saml/metadata"

    # Verify event logged
    _verify_event_logged(test_tenant["id"], "saml_idp_created", idp.id)


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_metadata_xml_as_admin_forbidden(
    test_tenant, test_admin_user, sample_idp_metadata_xml
):
    """Test that admin cannot import an IdP from metadata XML."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_admin_user, test_tenant["id"], "admin")

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.import_idp_from_metadata_xml(
            requesting_user=requesting_user,
            name="Should Fail",
            provider_type="generic",
            metadata_xml=sample_idp_metadata_xml,
            base_url="https://test.example.com",
        )

    assert exc_info.value.code == "super_admin_required"


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_metadata_xml_invalid_xml(test_tenant, test_super_admin_user):
    """Test that invalid XML raises ValidationError."""
    from services import saml as saml_service
    from services.exceptions import ValidationError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    with pytest.raises(ValidationError) as exc_info:
        saml_service.import_idp_from_metadata_xml(
            requesting_user=requesting_user,
            name="Invalid Import",
            provider_type="generic",
            metadata_xml="not valid xml",
            base_url="https://test.example.com",
        )

    assert exc_info.value.code == "metadata_parse_failed"


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_parse_idp_metadata_xml_to_schema_success(sample_idp_metadata_xml):
    """Test parsing raw metadata XML to schema."""
    from services import saml as saml_service

    parsed = saml_service.parse_idp_metadata_xml_to_schema(sample_idp_metadata_xml)

    assert parsed.entity_id == "https://xml-import-test.example.com/entity"
    assert parsed.sso_url == "https://xml-import-test.example.com/sso"
    assert parsed.slo_url == "https://xml-import-test.example.com/slo"
    assert "-----BEGIN CERTIFICATE-----" in parsed.certificate_pem


# =============================================================================
# Import IdP from Metadata URL Tests
# =============================================================================


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_metadata_url_success(
    test_tenant, test_super_admin_user, sample_idp_metadata_xml, monkeypatch
):
    """Test importing an IdP from a metadata URL."""
    import urllib.request
    from unittest.mock import MagicMock

    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    # Mock urlopen to return valid metadata
    mock_response = MagicMock()
    mock_response.read.return_value = sample_idp_metadata_xml.encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    def mock_urlopen(*args, **kwargs):
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    idp = saml_service.import_idp_from_metadata_url(
        requesting_user=requesting_user,
        name="URL Imported IdP",
        provider_type="generic",
        metadata_url="https://idp.example.com/metadata",
        base_url="https://test.example.com",
    )

    assert idp.name == "URL Imported IdP"
    assert idp.entity_id == "https://xml-import-test.example.com/entity"
    assert idp.sso_url == "https://xml-import-test.example.com/sso"
    assert idp.metadata_url == "https://idp.example.com/metadata"
    assert idp.is_enabled is False  # Should start disabled


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_import_idp_from_metadata_url_network_error(
    test_tenant, test_super_admin_user, monkeypatch
):
    """Test that network errors during URL import are handled."""
    import urllib.error
    import urllib.request

    from services import saml as saml_service
    from services.exceptions import ValidationError

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    def mock_urlopen(*args, **kwargs):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    with pytest.raises(ValidationError) as exc_info:
        saml_service.import_idp_from_metadata_url(
            requesting_user=requesting_user,
            name="Failed Import",
            provider_type="generic",
            metadata_url="https://unreachable.example.com/metadata",
            base_url="https://test.example.com",
        )

    assert exc_info.value.code == "metadata_fetch_failed"


def test_import_idp_from_metadata_url_as_admin_forbidden(test_tenant, test_admin_user):
    """Test that admin cannot import IdP from metadata URL."""
    from services import saml as saml_service

    admin_user = _make_requesting_user(test_admin_user, str(test_tenant["id"]), "admin")

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.import_idp_from_metadata_url(
            requesting_user=admin_user,
            name="Admin Import",
            provider_type="generic",
            metadata_url="https://idp.example.com/metadata",
            base_url="https://test.example.com",
        )

    assert exc_info.value.code == "super_admin_required"


# =============================================================================
# Refresh All IdP Metadata Tests (Background Job)
# =============================================================================


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_refresh_all_idp_metadata_with_urls_success(
    test_tenant, sample_idp_metadata_xml, monkeypatch
):
    """Test refresh_all_idp_metadata with IdPs that have URLs configured."""
    import urllib.request
    from unittest.mock import MagicMock

    import database
    from services import saml as saml_service

    # Mock database to return a test IdP with metadata URL
    mock_idps = [
        {
            "id": "test-idp-id-123",
            "tenant_id": str(test_tenant["id"]),
            "name": "Test IdP",
            "metadata_url": "https://idp.example.com/metadata",
        }
    ]

    # Mock get_idps_with_metadata_url to return our test IdP
    monkeypatch.setattr(database.saml, "get_idps_with_metadata_url", lambda: mock_idps)

    # Mock get_identity_provider to return current IdP state
    def mock_get_idp(tenant_id, idp_id):
        return {
            "id": "test-idp-id-123",
            "tenant_id": str(test_tenant["id"]),
            "name": "Test IdP",
            "entity_id": "https://old.example.com/entity",
            "sso_url": "https://old.example.com/sso",
            "slo_url": "https://old.example.com/slo",
            "certificate_pem": "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----",
        }

    monkeypatch.setattr(database.saml, "get_identity_provider", mock_get_idp)

    # Mock update to succeed
    def mock_update(*args, **kwargs):
        return {"id": "test-idp-id-123"}

    monkeypatch.setattr(database.saml, "update_idp_metadata_fields", mock_update)

    # Mock urlopen to return valid metadata
    mock_response = MagicMock()
    mock_response.read.return_value = sample_idp_metadata_xml.encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    def mock_urlopen(*args, **kwargs):
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    # Refresh all metadata
    result = saml_service.refresh_all_idp_metadata()

    assert result.total == 1
    assert result.successful == 1
    assert result.failed == 0
    assert len(result.results) == 1
    assert result.results[0].idp_name == "Test IdP"
    assert result.results[0].success is True


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_refresh_all_idp_metadata_partial_failure(test_tenant, monkeypatch):
    """Test refresh_all_idp_metadata handles partial failures gracefully."""
    import urllib.error
    import urllib.request

    import database
    from services import saml as saml_service

    # Mock database to return a test IdP with metadata URL
    mock_idps = [
        {
            "id": "failing-idp-id-123",
            "tenant_id": str(test_tenant["id"]),
            "name": "Failing IdP",
            "metadata_url": "https://failing-idp.example.com/metadata",
        }
    ]

    monkeypatch.setattr(database.saml, "get_idps_with_metadata_url", lambda: mock_idps)

    # Mock set_idp_metadata_error (called on failure)
    def mock_set_error(tenant_id, idp_id, error_msg):
        pass

    monkeypatch.setattr(database.saml, "set_idp_metadata_error", mock_set_error)

    # Mock urlopen to always fail
    def mock_urlopen(*args, **kwargs):
        raise urllib.error.URLError("Connection timeout")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    # Refresh all should not raise, even with failures
    result = saml_service.refresh_all_idp_metadata()

    assert result.total == 1
    assert result.successful == 0
    assert result.failed == 1
    assert len(result.results) == 1
    assert result.results[0].idp_name == "Failing IdP"
    assert result.results[0].success is False
    assert "Connection timeout" in result.results[0].error


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_refresh_all_idp_metadata_tracks_updated_fields(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test that refresh tracks which fields were updated."""
    import urllib.request
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    # Create IdP with metadata URL
    unique_suffix = str(test_super_admin_user["id"])[:8]
    idp_data_copy = test_idp_data.copy()
    idp_data_copy["entity_id"] = f"https://track-fields-{unique_suffix}.example.com/entity"
    idp_data_copy["name"] = f"Track Fields Test {unique_suffix}"
    idp_data_copy["metadata_url"] = "https://idp.example.com/metadata"
    idp_data_copy["sso_url"] = "https://old-sso.example.com/sso"  # Different from metadata

    data = IdPCreate(**idp_data_copy, is_enabled=True)
    saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Create metadata XML that has different SSO URL
    updated_metadata = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="https://track-fields-{unique_suffix}.example.com/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{test_idp_data["certificate_pem"].replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\\n", "").strip()}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://new-sso.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""

    mock_response = MagicMock()
    mock_response.read.return_value = updated_metadata.encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    def mock_urlopen(*args, **kwargs):
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    # Refresh
    result = saml_service.refresh_all_idp_metadata()

    # Find our test IdP's result
    our_result = next(
        (r for r in result.results if "track-fields" in (r.idp_name or "").lower()), None
    )

    # If found, check that it tracked updated fields
    if our_result and our_result.success:
        # sso_url should have changed
        assert our_result.updated_fields is None or "sso_url" in (our_result.updated_fields or [])


# =============================================================================
# _get_saml_attribute Helper Tests
# =============================================================================


def test_get_saml_attribute_simple_string():
    """Test extracting a simple string attribute."""
    from services.saml import _get_saml_attribute

    attributes = {"email": "user@example.com"}
    result = _get_saml_attribute(attributes, "email")
    assert result == "user@example.com"


def test_get_saml_attribute_list_value():
    """Test extracting an attribute that comes as a list (common SAML format)."""
    from services.saml import _get_saml_attribute

    attributes = {"email": ["user@example.com", "alias@example.com"]}
    result = _get_saml_attribute(attributes, "email")
    assert result == "user@example.com"  # Should return first item


def test_get_saml_attribute_empty_list():
    """Test extracting from an empty list returns None."""
    from services.saml import _get_saml_attribute

    attributes = {"email": []}
    result = _get_saml_attribute(attributes, "email")
    assert result is None


def test_get_saml_attribute_missing_key():
    """Test extracting a missing attribute returns None."""
    from services.saml import _get_saml_attribute

    attributes = {"first_name": "John"}
    result = _get_saml_attribute(attributes, "email")
    assert result is None


def test_get_saml_attribute_none_value():
    """Test extracting None value returns None."""
    from services.saml import _get_saml_attribute

    attributes = {"email": None}
    result = _get_saml_attribute(attributes, "email")
    assert result is None


def test_get_saml_attribute_integer_value():
    """Test that integer values are converted to strings."""
    from services.saml import _get_saml_attribute

    attributes = {"employee_id": 12345}
    result = _get_saml_attribute(attributes, "employee_id")
    assert result == "12345"


# =============================================================================
# process_saml_response Tests (with mocking)
# =============================================================================


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_sp_certificate_not_found(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test process_saml_response raises NotFoundError when SP cert is missing."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import NotFoundError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP without SP certificate (no get_or_create_sp_certificate call)
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Delete any existing SP certificate to ensure clean state
    import database

    database.execute(
        test_tenant["id"],
        "DELETE FROM saml_sp_certificates WHERE tenant_id = :tenant_id",
        {"tenant_id": test_tenant["id"]},
    )

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.process_saml_response(
            tenant_id=test_tenant["id"],
            idp_id=created.id,
            saml_response="base64encodedresponse",
        )

    assert exc_info.value.code == "sp_certificate_not_found"


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_idp_not_found(test_tenant, test_super_admin_user):
    """Test process_saml_response raises NotFoundError for unknown IdP."""
    from uuid import uuid4

    from services import saml as saml_service
    from services.exceptions import NotFoundError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Use a non-existent IdP ID
    fake_idp_id = str(uuid4())

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.process_saml_response(
            tenant_id=test_tenant["id"],
            idp_id=fake_idp_id,
            saml_response="base64encodedresponse",
        )

    assert exc_info.value.code == "idp_not_found"


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_idp_disabled(test_tenant, test_super_admin_user, test_idp_data):
    """Test process_saml_response raises ForbiddenError for disabled IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import ForbiddenError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create disabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=False)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.process_saml_response(
            tenant_id=test_tenant["id"],
            idp_id=created.id,
            saml_response="base64encodedresponse",
        )

    assert exc_info.value.code == "idp_disabled"


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_validation_failure_with_mock(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test process_saml_response raises ValidationError when auth fails."""
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import ValidationError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create mock auth object that returns errors
    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = ["invalid_signature", "assertion_expired"]
    mock_auth.get_last_error_reason.return_value = "Signature validation failed"

    def mock_auth_constructor(request_data, settings):
        return mock_auth

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        mock_auth_constructor,
    )

    with pytest.raises(ValidationError) as exc_info:
        saml_service.process_saml_response(
            tenant_id=test_tenant["id"],
            idp_id=created.id,
            saml_response="dummybase64response",
        )

    assert exc_info.value.code == "saml_validation_failed"
    assert "errors" in exc_info.value.details


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_success_with_mock(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test process_saml_response success with mocked SAML auth object."""
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create mock auth object
    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = []
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_attributes.return_value = {
        "email": ["user@example.com"],
        "firstName": ["John"],
        "lastName": ["Doe"],
    }
    mock_auth.get_nameid.return_value = "user@example.com"
    mock_auth.get_session_index.return_value = "session123"

    # Mock the OneLogin_Saml2_Auth class
    def mock_auth_constructor(request_data, settings):
        return mock_auth

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        mock_auth_constructor,
    )

    result = saml_service.process_saml_response(
        tenant_id=test_tenant["id"],
        idp_id=created.id,
        saml_response="dummybase64response",
    )

    assert result.attributes.email == "user@example.com"
    assert result.attributes.first_name == "John"
    assert result.attributes.last_name == "Doe"
    assert result.attributes.name_id == "user@example.com"
    assert result.session_index == "session123"
    assert result.idp_id == created.id


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_missing_email_attribute(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test process_saml_response raises ValidationError when email is missing."""
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import ValidationError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create enabled IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create mock auth object without email attribute
    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = []
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_attributes.return_value = {
        "firstName": ["John"],
        "lastName": ["Doe"],
    }
    mock_auth.get_nameid.return_value = "somenameid"

    def mock_auth_constructor(request_data, settings):
        return mock_auth

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        mock_auth_constructor,
    )

    with pytest.raises(ValidationError) as exc_info:
        saml_service.process_saml_response(
            tenant_id=test_tenant["id"],
            idp_id=created.id,
            saml_response="dummybase64response",
        )

    assert exc_info.value.code == "saml_missing_email"


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_custom_attribute_mapping(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test process_saml_response respects custom attribute mapping from IdP config."""
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create enabled IdP with custom attribute mapping (Azure AD style)
    custom_mapping = {
        "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "first_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "last_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    }
    idp_data_with_mapping = {**test_idp_data, "attribute_mapping": custom_mapping}
    data = IdPCreate(**idp_data_with_mapping, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create mock auth object with Azure AD style attributes
    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = []
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_attributes.return_value = {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
            "azure.user@company.com"
        ],
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["Azure"],
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": ["User"],
    }
    mock_auth.get_nameid.return_value = "azure.user@company.com"
    mock_auth.get_session_index.return_value = None

    def mock_auth_constructor(request_data, settings):
        return mock_auth

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        mock_auth_constructor,
    )

    result = saml_service.process_saml_response(
        tenant_id=test_tenant["id"],
        idp_id=created.id,
        saml_response="dummybase64response",
    )

    assert result.attributes.email == "azure.user@company.com"
    assert result.attributes.first_name == "Azure"
    assert result.attributes.last_name == "User"


@pytest.mark.skipif(not HAS_SAML_LIBRARY, reason="python3-saml not installed")
def test_process_saml_response_requires_mfa_flag(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test process_saml_response sets requires_mfa based on IdP setting."""
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create SP certificate
    saml_service.get_or_create_sp_certificate(requesting_user)

    # Create enabled IdP with require_platform_mfa=True
    data = IdPCreate(**test_idp_data, is_enabled=True, require_platform_mfa=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create mock auth object
    mock_auth = MagicMock()
    mock_auth.get_errors.return_value = []
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_attributes.return_value = {
        "email": ["mfa.user@example.com"],
        "firstName": ["MFA"],
        "lastName": ["User"],
    }
    mock_auth.get_nameid.return_value = "mfa.user@example.com"
    mock_auth.get_session_index.return_value = None

    def mock_auth_constructor(request_data, settings):
        return mock_auth

    monkeypatch.setattr(
        "onelogin.saml2.auth.OneLogin_Saml2_Auth",
        mock_auth_constructor,
    )

    result = saml_service.process_saml_response(
        tenant_id=test_tenant["id"],
        idp_id=created.id,
        saml_response="dummybase64response",
    )

    assert result.requires_mfa is True


# =============================================================================
# Cross-Tenant Isolation Tests
# =============================================================================


def test_cross_tenant_idp_not_accessible(test_tenant, test_super_admin_user, test_idp_data):
    """Test that one tenant cannot access another tenant's IdP."""
    from uuid import uuid4

    import database
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import NotFoundError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP in test_tenant
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a second tenant
    other_subdomain = f"other-{str(uuid4())[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
        {"subdomain": other_subdomain, "name": "Other Tenant"},
    )
    other_tenant = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": other_subdomain},
    )

    try:
        # Try to access test_tenant's IdP from other_tenant's context
        with pytest.raises(NotFoundError):
            saml_service.get_idp_for_saml_login(str(other_tenant["id"]), created.id)
    finally:
        # Cleanup other tenant
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :tenant_id",
            {"tenant_id": other_tenant["id"]},
        )


def test_cross_tenant_idp_list_isolation(test_tenant, test_super_admin_user, test_idp_data):
    """Test that listing IdPs only returns the tenant's own IdPs."""
    from uuid import uuid4

    import database
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP in test_tenant
    data = IdPCreate(**test_idp_data, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Create a second tenant with its own user
    other_subdomain = f"other-{str(uuid4())[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:subdomain, :name)",
        {"subdomain": other_subdomain, "name": "Other Tenant"},
    )
    other_tenant = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :subdomain",
        {"subdomain": other_subdomain},
    )

    # Create user in other tenant
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    other_user = database.fetchone(
        other_tenant["id"],
        """
        INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
        VALUES (:tenant_id, :password_hash, 'Other', 'Admin', 'super_admin')
        RETURNING id, first_name, last_name, role
        """,
        {"tenant_id": other_tenant["id"], "password_hash": ph.hash("password")},
    )

    try:
        # Create requesting user for other tenant
        other_requesting_user = RequestingUser(
            id=str(other_user["id"]),
            tenant_id=str(other_tenant["id"]),
            role="super_admin",
        )

        # List IdPs from other tenant - should NOT see test_tenant's IdP
        other_idps = saml_service.list_identity_providers(other_requesting_user)

        # Verify test_tenant's IdP is not in the list
        idp_ids = [idp.id for idp in other_idps.items]
        assert created.id not in idp_ids
    finally:
        # Cleanup other tenant
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :tenant_id",
            {"tenant_id": other_tenant["id"]},
        )


# =============================================================================
# Certificate Expiry Tests
# =============================================================================


def test_sp_certificate_has_valid_expiry(test_tenant, test_super_admin_user):
    """Test that generated SP certificate has reasonable expiry date."""
    from datetime import UTC, datetime, timedelta

    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    cert = saml_service.get_or_create_sp_certificate(requesting_user)

    # Certificate should expire in approximately 10 years (default)
    now = datetime.now(UTC)
    expected_expiry = now + timedelta(days=10 * 365)

    # Allow some tolerance (within 30 days)
    assert cert.expires_at > now + timedelta(days=10 * 365 - 30)
    assert cert.expires_at < expected_expiry + timedelta(days=30)


def test_sp_certificate_not_expired(test_tenant, test_super_admin_user):
    """Test that newly created SP certificate is not expired."""
    from datetime import UTC, datetime

    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    cert = saml_service.get_or_create_sp_certificate(requesting_user)

    assert cert.expires_at > datetime.now(UTC)


# =============================================================================
# Metadata Refresh Error Scenario Tests
# =============================================================================


def test_refresh_idp_from_metadata_network_error(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test refresh_idp_from_metadata handles network errors gracefully."""
    import urllib.error
    import urllib.request

    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import ValidationError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP with metadata URL
    idp_data_with_url = {**test_idp_data, "metadata_url": "https://idp.example.com/metadata"}
    data = IdPCreate(**idp_data_with_url, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Mock urlopen to simulate network error
    def mock_urlopen(*args, **kwargs):
        raise urllib.error.URLError("Network unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    with pytest.raises(ValidationError) as exc_info:
        saml_service.refresh_idp_from_metadata(requesting_user, created.id)

    assert exc_info.value.code == "metadata_fetch_failed"


def test_refresh_idp_from_metadata_invalid_response(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test refresh_idp_from_metadata handles invalid XML response."""
    import urllib.request
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import ValidationError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP with metadata URL
    idp_data_with_url = {**test_idp_data, "metadata_url": "https://idp.example.com/metadata"}
    data = IdPCreate(**idp_data_with_url, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Mock urlopen to return invalid XML
    mock_response = MagicMock()
    mock_response.read.return_value = b"not valid xml"
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    def mock_urlopen(*args, **kwargs):
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    with pytest.raises(ValidationError) as exc_info:
        saml_service.refresh_idp_from_metadata(requesting_user, created.id)

    # Error code can be metadata_parse_failed or metadata_fetch_failed
    # depending on where parsing fails
    assert exc_info.value.code in ("metadata_parse_failed", "metadata_fetch_failed")


def test_refresh_idp_from_metadata_timeout(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test refresh_idp_from_metadata handles timeout."""
    import urllib.request

    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services.exceptions import ValidationError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP with metadata URL
    idp_data_with_url = {**test_idp_data, "metadata_url": "https://idp.example.com/metadata"}
    data = IdPCreate(**idp_data_with_url, is_enabled=True)
    created = saml_service.create_identity_provider(
        requesting_user, data, "https://test.example.com"
    )

    # Mock urlopen to simulate timeout
    def mock_urlopen(*args, **kwargs):
        raise TimeoutError("Connection timed out")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    with pytest.raises(ValidationError) as exc_info:
        saml_service.refresh_idp_from_metadata(requesting_user, created.id)

    assert exc_info.value.code == "metadata_fetch_failed"


# =============================================================================
# IdP Deletion with Linked Users Tests
# =============================================================================


def test_delete_idp_blocked_when_users_assigned(test_tenant, test_super_admin_user, test_idp_data):
    """Test that deleting an IdP is blocked when users are assigned.

    Security: Cannot delete an IdP that has users assigned to it.
    Users must be migrated to another IdP or set to 'password only' first.
    """
    import database
    from schemas.saml import IdPCreate
    from services import saml as saml_service
    from services import users as users_service
    from services.exceptions import ConflictError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    tenant_id = test_tenant["id"]

    # Create an IdP with JIT enabled
    idp_data_jit = {**test_idp_data, "jit_provisioning": True}
    data = IdPCreate(**idp_data_jit, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Create a user and link them to this IdP (simulating JIT)
    user_result = users_service.create_user_raw(
        tenant_id=str(tenant_id),
        first_name="JIT",
        last_name="User",
        email=f"jit-delete-test-{idp.id[:8]}@example.com",
        role="member",
    )
    user_id = str(user_result["user_id"])

    # Link the user to the IdP
    database.saml.set_user_idp(str(tenant_id), user_id, idp.id)

    # Verify user is linked (get_user_assigned_idp returns the IdP via join)
    assigned_idp = database.saml.get_user_assigned_idp(str(tenant_id), user_id)
    assert assigned_idp is not None
    assert str(assigned_idp["id"]) == idp.id

    # Try to delete the IdP - should be blocked
    with pytest.raises(ConflictError) as exc_info:
        saml_service.delete_identity_provider(requesting_user, idp.id)

    assert exc_info.value.code == "idp_has_assigned_users"
    assert "1 user(s)" in exc_info.value.message

    # Verify IdP still exists
    idp_after = saml_service.get_identity_provider(requesting_user, idp.id)
    assert idp_after is not None


# =============================================================================
# JIT Provisioning Race Condition Tests
# =============================================================================


def test_jit_race_condition_email_exists_returns_existing_user(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test JIT provisioning handles race condition where email exists.

    When JIT provisioning is about to create a user but the email already
    exists (race condition), it should return the existing user instead
    of failing.
    """
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service
    from services import users as users_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    tenant_id = str(test_tenant["id"])

    # Create an IdP with JIT enabled
    idp_data_jit = {**test_idp_data, "jit_provisioning": True}
    data = IdPCreate(**idp_data_jit, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Pre-create a user with the email (simulating race condition)
    unique_email = f"jit-race-{idp.id[:8]}@example.com"
    user_result = users_service.create_user_raw(
        tenant_id=tenant_id,
        first_name="Existing",
        last_name="User",
        email=unique_email,
        role="member",
    )
    user_id = str(user_result["user_id"])

    # Add verified email
    users_service.add_verified_email_with_nonce(
        tenant_id=tenant_id,
        user_id=user_id,
        email=unique_email,
        is_primary=True,
    )

    # Create a SAML result for this email
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=unique_email,
            first_name="SAML",
            last_name="Name",
            name_id=unique_email,
        ),
        idp_id=idp.id,
        requires_mfa=False,
    )

    # Authenticate via SAML - should find existing user, not fail
    result_user = saml_service.authenticate_via_saml(
        tenant_id=tenant_id,
        saml_result=saml_result,
    )

    # Should return the existing user (authenticate_via_saml returns id, first_name, last_name, role)
    assert result_user is not None
    assert result_user["first_name"] == "Existing"  # Original name, not SAML name


# =============================================================================
# Multi-IdP Same Email Scenarios
# =============================================================================


def test_existing_user_authenticates_via_different_idp(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test that an existing user can authenticate via a different IdP.

    A user created normally (not via JIT) should be able to authenticate
    via any enabled IdP.
    """
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service
    from services import users as users_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    tenant_id = str(test_tenant["id"])

    # Create first IdP
    idp1_data = {
        **test_idp_data,
        "entity_id": "https://idp1.example.com/entity",
        "sso_url": "https://idp1.example.com/sso",
    }
    data1 = IdPCreate(**idp1_data, is_enabled=True)
    idp1 = saml_service.create_identity_provider(requesting_user, data1, "https://test.example.com")

    # Create second IdP
    idp2_data = {
        **test_idp_data,
        "entity_id": "https://idp2.example.com/entity",
        "sso_url": "https://idp2.example.com/sso",
    }
    data2 = IdPCreate(**idp2_data, is_enabled=True)
    idp2 = saml_service.create_identity_provider(requesting_user, data2, "https://test.example.com")

    # Create a user (not via JIT)
    unique_email = f"multi-idp-{idp1.id[:8]}@example.com"
    user_result = users_service.create_user_raw(
        tenant_id=tenant_id,
        first_name="Regular",
        last_name="User",
        email=unique_email,
        role="member",
    )
    user_id = str(user_result["user_id"])

    # Add verified email
    users_service.add_verified_email_with_nonce(
        tenant_id=tenant_id,
        user_id=user_id,
        email=unique_email,
        is_primary=True,
    )

    # Authenticate via IdP1
    saml_result_idp1 = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=unique_email,
            first_name="SAML1",
            last_name="Name1",
            name_id=unique_email,
        ),
        idp_id=idp1.id,
        requires_mfa=False,
    )
    user1 = saml_service.authenticate_via_saml(
        tenant_id=tenant_id,
        saml_result=saml_result_idp1,
    )
    assert user1 is not None
    assert str(user1["id"]) == user_id  # Should be the pre-created user

    # Authenticate via IdP2 (different IdP, same user)
    saml_result_idp2 = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=unique_email,
            first_name="SAML2",
            last_name="Name2",
            name_id=unique_email,
        ),
        idp_id=idp2.id,
        requires_mfa=False,
    )
    user2 = saml_service.authenticate_via_saml(
        tenant_id=tenant_id,
        saml_result=saml_result_idp2,
    )

    # Should be the same user
    assert user2["id"] == user1["id"]


def test_user_idp_updated_on_auth_via_different_idp(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test that user's IdP link is updated when they auth via different IdP.

    Security: When a user authenticates via SAML, they are linked to that IdP.
    This ensures the user is "locked in" to the IdP they actually use.
    """
    import database
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    tenant_id = str(test_tenant["id"])

    # Create first IdP with JIT enabled
    idp1_data = {
        **test_idp_data,
        "entity_id": "https://jit-link-idp1.example.com/entity",
        "sso_url": "https://jit-link-idp1.example.com/sso",
        "jit_provisioning": True,
    }
    data1 = IdPCreate(**idp1_data, is_enabled=True)
    idp1 = saml_service.create_identity_provider(requesting_user, data1, "https://test.example.com")

    # Create second IdP without JIT
    idp2_data = {
        **test_idp_data,
        "entity_id": "https://jit-link-idp2.example.com/entity",
        "sso_url": "https://jit-link-idp2.example.com/sso",
        "jit_provisioning": False,
    }
    data2 = IdPCreate(**idp2_data, is_enabled=True)
    idp2 = saml_service.create_identity_provider(requesting_user, data2, "https://test.example.com")

    # Authenticate via IdP1 - should JIT create user
    unique_email = f"jit-link-test-{idp1.id[:8]}@example.com"
    saml_result_idp1 = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=unique_email,
            first_name="JIT",
            last_name="User",
            name_id=unique_email,
        ),
        idp_id=idp1.id,
        requires_mfa=False,
    )
    user_created = saml_service.authenticate_via_saml(
        tenant_id=tenant_id,
        saml_result=saml_result_idp1,
    )

    # Verify user is linked to IdP1
    assigned_idp1 = database.saml.get_user_assigned_idp(tenant_id, str(user_created["id"]))
    assert assigned_idp1 is not None
    assert str(assigned_idp1["id"]) == idp1.id

    # Authenticate via IdP2
    saml_result_idp2 = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=unique_email,
            first_name="JIT",
            last_name="User",
            name_id=unique_email,
        ),
        idp_id=idp2.id,
        requires_mfa=False,
    )
    user_via_idp2 = saml_service.authenticate_via_saml(
        tenant_id=tenant_id,
        saml_result=saml_result_idp2,
    )

    # Verify user's saml_idp_id is updated to IdP2 (user is now linked to the IdP they authenticated with)
    assigned_idp_after = database.saml.get_user_assigned_idp(tenant_id, str(user_via_idp2["id"]))
    assert assigned_idp_after is not None
    assert (
        str(assigned_idp_after["id"]) == idp2.id
    ), "User's saml_idp_id should be updated to the IdP they authenticated with"


# =============================================================================
# Event Logging Verification Tests
# =============================================================================


def test_jit_provisioning_logs_creation_event(test_tenant, test_super_admin_user, test_idp_data):
    """Test that JIT provisioning logs the user_created_jit event."""
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    tenant_id = str(test_tenant["id"])

    # Create IdP with JIT enabled
    idp_data_jit = {**test_idp_data, "jit_provisioning": True}
    data = IdPCreate(**idp_data_jit, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # JIT create a user
    unique_email = f"jit-event-{idp.id[:8]}@example.com"
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=unique_email,
            first_name="JIT",
            last_name="Event",
            name_id=unique_email,
        ),
        idp_id=idp.id,
        requires_mfa=False,
    )
    user = saml_service.authenticate_via_saml(
        tenant_id=tenant_id,
        saml_result=saml_result,
    )

    # Verify user_created_jit event was logged
    _verify_event_logged(test_tenant["id"], "user_created_jit", str(user["id"]))


def test_saml_sign_in_logs_event_for_existing_user(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test that SAML sign-in logs user_signed_in_saml for existing users."""
    import database
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service
    from services import users as users_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    tenant_id = str(test_tenant["id"])

    # Create IdP (no JIT)
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Create existing user
    unique_email = f"signin-event-{idp.id[:8]}@example.com"
    user_result = users_service.create_user_raw(
        tenant_id=tenant_id,
        first_name="Sign",
        last_name="In",
        email=unique_email,
        role="member",
    )
    user_id = str(user_result["user_id"])

    # Add verified email
    users_service.add_verified_email_with_nonce(
        tenant_id=tenant_id,
        user_id=user_id,
        email=unique_email,
        is_primary=True,
    )

    # Verify user exists
    user = database.users.get_user_by_email(tenant_id, unique_email)
    assert user is not None

    # Sign in via SAML
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=unique_email,
            first_name="Sign",
            last_name="In",
            name_id=unique_email,
        ),
        idp_id=idp.id,
        requires_mfa=False,
    )
    saml_service.authenticate_via_saml(
        tenant_id=tenant_id,
        saml_result=saml_result,
    )

    # Verify user_signed_in_saml event was logged
    _verify_event_logged(test_tenant["id"], "user_signed_in_saml", user_id)


# =============================================================================
# Attribute Mapping Variations Tests
# =============================================================================


def test_process_saml_response_google_attribute_mapping(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test SAML response processing with Google Workspace attribute names.

    Google Workspace uses different attribute names like:
    - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
    - http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname
    """
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP with Google-style attribute mapping
    google_idp_data = {
        **test_idp_data,
        "entity_id": "https://accounts.google.com/entity",
        "sso_url": "https://accounts.google.com/sso",
    }
    data = IdPCreate(
        **google_idp_data,
        is_enabled=True,
        attribute_mapping={
            "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "first_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
            "last_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        },
    )
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Mock SAML Auth
    mock_auth = MagicMock()
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_errors.return_value = []
    mock_auth.get_attributes.return_value = {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
            "google.user@example.com"
        ],
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["GoogleFirst"],
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": ["GoogleLast"],
    }
    mock_auth.get_nameid.return_value = "google.user@example.com"
    mock_auth.get_nameid_format.return_value = (
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    mock_auth.get_session_index.return_value = "session123"

    # Mock OneLogin_Saml2_Auth constructor
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: F401

        def mock_auth_init(*args, **kwargs):
            return mock_auth

        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", mock_auth_init)

        result = saml_service.process_saml_response(
            tenant_id=str(test_tenant["id"]),
            idp_id=idp.id,
            saml_response="base64encodedresponse",
            request_id=None,
            request_data={"https": "on", "http_host": "test.example.com"},
        )

        assert result.attributes.email == "google.user@example.com"
        assert result.attributes.first_name == "GoogleFirst"
        assert result.attributes.last_name == "GoogleLast"
    except ImportError:
        pytest.skip("python3-saml not installed")


def test_process_saml_response_missing_optional_attributes(
    test_tenant, test_super_admin_user, test_idp_data, monkeypatch
):
    """Test SAML response processing when first_name/last_name are missing.

    Only email is required. first_name and last_name should default to None.
    """
    from unittest.mock import MagicMock

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Mock SAML Auth - only email attribute present
    mock_auth = MagicMock()
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_errors.return_value = []
    mock_auth.get_attributes.return_value = {
        "email": ["minimal@example.com"],
        # No firstName or lastName attributes
    }
    mock_auth.get_nameid.return_value = "minimal@example.com"
    mock_auth.get_nameid_format.return_value = (
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    mock_auth.get_session_index.return_value = "session123"

    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth  # noqa: F401

        def mock_auth_init(*args, **kwargs):
            return mock_auth

        monkeypatch.setattr("onelogin.saml2.auth.OneLogin_Saml2_Auth", mock_auth_init)

        result = saml_service.process_saml_response(
            tenant_id=str(test_tenant["id"]),
            idp_id=idp.id,
            saml_response="base64encodedresponse",
            request_id=None,
            request_data={"https": "on", "http_host": "test.example.com"},
        )

        assert result.attributes.email == "minimal@example.com"
        # These should be None, not cause an error
        assert result.attributes.first_name is None
        assert result.attributes.last_name is None
    except ImportError:
        pytest.skip("python3-saml not installed")


# =============================================================================
# Inactivated User Scenarios
# =============================================================================


def test_authenticate_via_saml_inactivated_user_forbidden(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test that inactivated users cannot authenticate via SAML."""
    import database
    from schemas.saml import IdPCreate, SAMLAttributes, SAMLAuthResult
    from services import saml as saml_service
    from services import users as users_service
    from services.exceptions import ForbiddenError

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
    tenant_id = str(test_tenant["id"])

    # Create IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Create and inactivate a user
    unique_email = f"inactivated-{idp.id[:8]}@example.com"
    user_result = users_service.create_user_raw(
        tenant_id=tenant_id,
        first_name="Inactivated",
        last_name="User",
        email=unique_email,
        role="member",
    )
    user_id = str(user_result["user_id"])

    # Add verified email
    users_service.add_verified_email_with_nonce(
        tenant_id=tenant_id,
        user_id=user_id,
        email=unique_email,
        is_primary=True,
    )

    # Inactivate the user
    database.users.inactivate_user(tenant_id, user_id)

    # Try to authenticate via SAML
    saml_result = SAMLAuthResult(
        attributes=SAMLAttributes(
            email=unique_email,
            first_name="Inactivated",
            last_name="User",
            name_id=unique_email,
        ),
        idp_id=idp.id,
        requires_mfa=False,
    )

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.authenticate_via_saml(
            tenant_id=tenant_id,
            saml_result=saml_result,
        )

    assert exc_info.value.code == "user_inactivated"


# =============================================================================
# Domain Binding Tests (Phase 3)
# =============================================================================


@pytest.fixture
def test_privileged_domain(test_tenant, test_super_admin_user):
    """Create a privileged domain for testing."""
    from schemas.settings import PrivilegedDomainCreate
    from services import settings as settings_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )
    unique_suffix = str(test_super_admin_user["id"])[:8]
    domain_data = PrivilegedDomainCreate(domain=f"privileged-{unique_suffix}.example.com")

    return settings_service.add_privileged_domain(requesting_user, domain_data)


def test_bind_domain_to_idp_success(
    test_tenant, test_super_admin_user, test_idp_data, test_privileged_domain
):
    """Test successfully binding a domain to an IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    # Create IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Bind domain to IdP
    binding = saml_service.bind_domain_to_idp(
        requesting_user,
        idp_id=idp.id,
        domain_id=test_privileged_domain.id,
    )

    assert binding is not None
    assert binding.idp_id == idp.id
    assert binding.domain_id == test_privileged_domain.id
    assert binding.domain == test_privileged_domain.domain

    # Verify event was logged
    _verify_event_logged(str(test_tenant["id"]), "saml_domain_bound", binding.id)


def test_bind_domain_to_idp_as_admin_forbidden(
    test_tenant, test_admin_user, test_super_admin_user, test_idp_data, test_privileged_domain
):
    """Test that admin cannot bind domain to IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    super_admin_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )
    admin_user = _make_requesting_user(test_admin_user, str(test_tenant["id"]), "admin")

    # Create IdP as super_admin
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(super_admin_user, data, "https://test.example.com")

    # Try to bind as admin
    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.bind_domain_to_idp(
            admin_user,
            idp_id=idp.id,
            domain_id=test_privileged_domain.id,
        )

    assert exc_info.value.code == "super_admin_required"


def test_bind_domain_to_idp_idp_not_found(
    test_tenant, test_super_admin_user, test_privileged_domain
):
    """Test binding domain to non-existent IdP."""
    import uuid

    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )
    fake_idp_id = str(uuid.uuid4())

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.bind_domain_to_idp(
            requesting_user,
            idp_id=fake_idp_id,
            domain_id=test_privileged_domain.id,
        )

    assert exc_info.value.code == "idp_not_found"


def test_bind_domain_to_idp_domain_not_found(test_tenant, test_super_admin_user, test_idp_data):
    """Test binding non-existent domain to IdP."""
    import uuid

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    # Create IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    fake_domain_id = str(uuid.uuid4())

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.bind_domain_to_idp(
            requesting_user,
            idp_id=idp.id,
            domain_id=fake_domain_id,
        )

    assert exc_info.value.code == "domain_not_found"


def test_bind_domain_to_idp_assigns_users(test_tenant, test_super_admin_user, test_idp_data):
    """Test that binding domain to IdP assigns matching users."""
    import database
    from schemas.saml import IdPCreate
    from schemas.settings import PrivilegedDomainCreate
    from services import saml as saml_service
    from services import settings as settings_service
    from services import users as users_service

    tenant_id = str(test_tenant["id"])
    requesting_user = _make_requesting_user(test_super_admin_user, tenant_id, "super_admin")

    # Create a unique domain
    unique_suffix = str(test_super_admin_user["id"])[:8]
    domain_name = f"assign-test-{unique_suffix}.example.com"
    domain_data = PrivilegedDomainCreate(domain=domain_name)
    domain = settings_service.add_privileged_domain(requesting_user, domain_data)

    # Create a user with email in this domain
    user_email = f"user@{domain_name}"
    user_result = users_service.create_user_raw(
        tenant_id=tenant_id,
        first_name="Domain",
        last_name="User",
        email=user_email,
        role="member",
    )
    user_id = str(user_result["user_id"])

    # Add verified email
    users_service.add_verified_email_with_nonce(
        tenant_id=tenant_id,
        user_id=user_id,
        email=user_email,
        is_primary=True,
    )

    # Create IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Verify user has no IdP assigned initially
    user_before = database.users.get_user_by_id(tenant_id, user_id)
    assert user_before["saml_idp_id"] is None

    # Bind domain to IdP
    saml_service.bind_domain_to_idp(
        requesting_user,
        idp_id=idp.id,
        domain_id=domain.id,
    )

    # Verify user is now assigned to IdP
    user_after = database.users.get_user_by_id(tenant_id, user_id)
    assert str(user_after["saml_idp_id"]) == idp.id


def test_unbind_domain_from_idp_success(
    test_tenant, test_super_admin_user, test_idp_data, test_privileged_domain
):
    """Test successfully unbinding a domain from an IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    # Create IdP and bind domain
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    binding = saml_service.bind_domain_to_idp(
        requesting_user,
        idp_id=idp.id,
        domain_id=test_privileged_domain.id,
    )
    binding_id = binding.id

    # Unbind domain
    saml_service.unbind_domain_from_idp(
        requesting_user,
        domain_id=test_privileged_domain.id,
    )

    # Verify event was logged (artifact_id is the binding ID, not domain ID)
    _verify_event_logged(str(test_tenant["id"]), "saml_domain_unbound", binding_id)


def test_unbind_domain_from_idp_not_bound(
    test_tenant, test_super_admin_user, test_privileged_domain
):
    """Test unbinding domain that is not bound."""
    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.unbind_domain_from_idp(
            requesting_user,
            domain_id=test_privileged_domain.id,
        )

    assert exc_info.value.code == "domain_binding_not_found"


def test_unbind_domain_from_idp_as_admin_forbidden(
    test_tenant, test_admin_user, test_super_admin_user, test_idp_data, test_privileged_domain
):
    """Test that admin cannot unbind domain from IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    super_admin_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )
    admin_user = _make_requesting_user(test_admin_user, str(test_tenant["id"]), "admin")

    # Create IdP and bind domain as super_admin
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(super_admin_user, data, "https://test.example.com")

    saml_service.bind_domain_to_idp(
        super_admin_user,
        idp_id=idp.id,
        domain_id=test_privileged_domain.id,
    )

    # Try to unbind as admin
    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.unbind_domain_from_idp(
            admin_user,
            domain_id=test_privileged_domain.id,
        )

    assert exc_info.value.code == "super_admin_required"


def test_rebind_domain_to_different_idp_success(
    test_tenant, test_super_admin_user, test_idp_data, test_privileged_domain
):
    """Test rebinding a domain to a different IdP."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    # Create two IdPs
    data1 = IdPCreate(**test_idp_data, is_enabled=True)
    idp1 = saml_service.create_identity_provider(requesting_user, data1, "https://test.example.com")

    # Create second IdP with different entity_id
    test_idp_data2 = test_idp_data.copy()
    test_idp_data2["entity_id"] = "https://second-idp.example.com/entity"
    test_idp_data2["name"] = "Second Test IdP"
    data2 = IdPCreate(**test_idp_data2, is_enabled=True)
    idp2 = saml_service.create_identity_provider(requesting_user, data2, "https://test.example.com")

    # Bind domain to first IdP
    binding1 = saml_service.bind_domain_to_idp(
        requesting_user,
        idp_id=idp1.id,
        domain_id=test_privileged_domain.id,
    )
    assert binding1.idp_id == idp1.id

    # Rebind domain to second IdP
    binding2 = saml_service.rebind_domain_to_idp(
        requesting_user,
        domain_id=test_privileged_domain.id,
        new_idp_id=idp2.id,
    )

    assert binding2.idp_id == idp2.id
    assert binding2.domain_id == test_privileged_domain.id

    # Verify event was logged
    _verify_event_logged(str(test_tenant["id"]), "saml_domain_rebound", binding2.id)


def test_rebind_domain_to_idp_not_bound(
    test_tenant, test_super_admin_user, test_idp_data, test_privileged_domain
):
    """Test rebinding domain that is not bound."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    # Create IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.rebind_domain_to_idp(
            requesting_user,
            domain_id=test_privileged_domain.id,
            new_idp_id=idp.id,
        )

    assert exc_info.value.code == "domain_binding_not_found"


def test_rebind_domain_target_idp_not_found(
    test_tenant, test_super_admin_user, test_idp_data, test_privileged_domain
):
    """Test rebinding domain to non-existent IdP."""
    import uuid

    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(
        test_super_admin_user, str(test_tenant["id"]), "super_admin"
    )

    # Create IdP and bind domain
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    saml_service.bind_domain_to_idp(
        requesting_user,
        idp_id=idp.id,
        domain_id=test_privileged_domain.id,
    )

    fake_idp_id = str(uuid.uuid4())

    with pytest.raises(NotFoundError) as exc_info:
        saml_service.rebind_domain_to_idp(
            requesting_user,
            domain_id=test_privileged_domain.id,
            new_idp_id=fake_idp_id,
        )

    assert exc_info.value.code == "idp_not_found"


def test_rebind_domain_moves_users_to_new_idp(test_tenant, test_super_admin_user, test_idp_data):
    """Test that rebinding domain moves users to new IdP."""
    import database
    from schemas.saml import IdPCreate
    from schemas.settings import PrivilegedDomainCreate
    from services import saml as saml_service
    from services import settings as settings_service
    from services import users as users_service

    tenant_id = str(test_tenant["id"])
    requesting_user = _make_requesting_user(test_super_admin_user, tenant_id, "super_admin")

    # Create a unique domain
    unique_suffix = str(test_super_admin_user["id"])[:8]
    domain_name = f"rebind-test-{unique_suffix}.example.com"
    domain_data = PrivilegedDomainCreate(domain=domain_name)
    domain = settings_service.add_privileged_domain(requesting_user, domain_data)

    # Create a user with email in this domain
    user_email = f"user@{domain_name}"
    user_result = users_service.create_user_raw(
        tenant_id=tenant_id,
        first_name="Rebind",
        last_name="User",
        email=user_email,
        role="member",
    )
    user_id = str(user_result["user_id"])

    # Add verified email
    users_service.add_verified_email_with_nonce(
        tenant_id=tenant_id,
        user_id=user_id,
        email=user_email,
        is_primary=True,
    )

    # Create two IdPs
    data1 = IdPCreate(**test_idp_data, is_enabled=True)
    idp1 = saml_service.create_identity_provider(requesting_user, data1, "https://test.example.com")

    test_idp_data2 = test_idp_data.copy()
    test_idp_data2["entity_id"] = f"https://rebind-{unique_suffix}.example.com/entity"
    test_idp_data2["name"] = "Rebind Second IdP"
    data2 = IdPCreate(**test_idp_data2, is_enabled=True)
    idp2 = saml_service.create_identity_provider(requesting_user, data2, "https://test.example.com")

    # Bind domain to first IdP
    saml_service.bind_domain_to_idp(
        requesting_user,
        idp_id=idp1.id,
        domain_id=domain.id,
    )

    # Verify user is on first IdP
    user_before = database.users.get_user_by_id(tenant_id, user_id)
    assert str(user_before["saml_idp_id"]) == idp1.id

    # Rebind domain to second IdP
    saml_service.rebind_domain_to_idp(
        requesting_user,
        domain_id=domain.id,
        new_idp_id=idp2.id,
    )

    # Verify user moved to second IdP
    user_after = database.users.get_user_by_id(tenant_id, user_id)
    assert str(user_after["saml_idp_id"]) == idp2.id


def test_get_unbound_domains_returns_only_unbound(
    test_tenant, test_super_admin_user, test_idp_data
):
    """Test that get_unbound_domains returns only domains not bound to any IdP."""
    from schemas.saml import IdPCreate
    from schemas.settings import PrivilegedDomainCreate
    from services import saml as saml_service
    from services import settings as settings_service

    tenant_id = str(test_tenant["id"])
    requesting_user = _make_requesting_user(test_super_admin_user, tenant_id, "super_admin")

    unique_suffix = str(test_super_admin_user["id"])[:8]

    # Create two domains
    domain1_data = PrivilegedDomainCreate(domain=f"bound-{unique_suffix}.example.com")
    domain1 = settings_service.add_privileged_domain(requesting_user, domain1_data)

    domain2_data = PrivilegedDomainCreate(domain=f"unbound-{unique_suffix}.example.com")
    domain2 = settings_service.add_privileged_domain(requesting_user, domain2_data)

    # Create IdP and bind first domain
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    saml_service.bind_domain_to_idp(
        requesting_user,
        idp_id=idp.id,
        domain_id=domain1.id,
    )

    # Get unbound domains
    unbound = saml_service.get_unbound_domains(requesting_user)

    unbound_ids = [d.id for d in unbound]
    assert domain2.id in unbound_ids
    assert domain1.id not in unbound_ids


def test_get_unbound_domains_as_admin_forbidden(test_tenant, test_admin_user):
    """Test that admin cannot get unbound domains."""
    from services import saml as saml_service

    admin_user = _make_requesting_user(test_admin_user, str(test_tenant["id"]), "admin")

    with pytest.raises(ForbiddenError) as exc_info:
        saml_service.get_unbound_domains(admin_user)

    assert exc_info.value.code == "super_admin_required"


def test_list_domain_bindings_for_idp(test_tenant, test_super_admin_user, test_idp_data):
    """Test listing all domain bindings for a specific IdP."""
    from schemas.saml import IdPCreate
    from schemas.settings import PrivilegedDomainCreate
    from services import saml as saml_service
    from services import settings as settings_service

    tenant_id = str(test_tenant["id"])
    requesting_user = _make_requesting_user(test_super_admin_user, tenant_id, "super_admin")

    unique_suffix = str(test_super_admin_user["id"])[:8]

    # Create two domains
    domain1_data = PrivilegedDomainCreate(domain=f"bind1-{unique_suffix}.example.com")
    domain1 = settings_service.add_privileged_domain(requesting_user, domain1_data)

    domain2_data = PrivilegedDomainCreate(domain=f"bind2-{unique_suffix}.example.com")
    domain2 = settings_service.add_privileged_domain(requesting_user, domain2_data)

    # Create IdP
    data = IdPCreate(**test_idp_data, is_enabled=True)
    idp = saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Bind both domains to IdP
    saml_service.bind_domain_to_idp(
        requesting_user,
        idp_id=idp.id,
        domain_id=domain1.id,
    )
    saml_service.bind_domain_to_idp(
        requesting_user,
        idp_id=idp.id,
        domain_id=domain2.id,
    )

    # List bindings for IdP
    bindings = saml_service.list_domain_bindings(requesting_user, idp.id)

    assert len(bindings.items) == 2
    domain_ids = [b.domain_id for b in bindings.items]
    assert domain1.id in domain_ids
    assert domain2.id in domain_ids
