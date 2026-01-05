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
    """Test refreshing metadata when no IdPs have URLs configured."""
    from schemas.saml import IdPCreate
    from services import saml as saml_service

    requesting_user = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

    # Create IdP without metadata URL
    data = IdPCreate(**test_idp_data, metadata_url=None)
    saml_service.create_identity_provider(requesting_user, data, "https://test.example.com")

    # Refresh - should complete with no refreshes
    result = saml_service.refresh_all_idp_metadata()

    # May or may not have IdPs depending on test isolation
    assert result.successful >= 0
    assert result.failed >= 0


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
