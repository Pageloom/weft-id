"""Tests for Pydantic schema input length validation.

Verifies that all input schemas enforce max_length on string fields,
rejecting oversized strings with validation errors.
"""

import pytest
from pydantic import ValidationError

from app.schemas.api import UserCreate, UserProfileUpdate, UserUpdate
from app.schemas.branding import BrandingSettingsUpdate
from app.schemas.groups import (
    BulkMemberAdd,
    BulkMemberRemove,
    GroupChildAdd,
    GroupMemberAdd,
    GroupParentAdd,
    UserGroupsAdd,
)
from app.schemas.oauth2 import (
    AuthorizeForm,
    AuthorizeParams,
    B2BClientCreate,
    ClientRoleUpdate,
    ClientUpdate,
    NormalClientCreate,
)
from app.schemas.saml import (
    DomainBindingCreate,
    IdPCreate,
    IdPMetadataImport,
    IdPMetadataImportXML,
    IdPUpdate,
    UserIdpAssignment,
)
from app.schemas.service_providers import (
    SPCreate,
    SPEstablishTrustManual,
    SPEstablishTrustURL,
    SPEstablishTrustXML,
    SPGroupAssignAdd,
    SPGroupBulkAssign,
    SPMetadataImportURL,
    SPMetadataImportXML,
    SPMetadataReimport,
    SPUpdate,
)

# ============================================================================
# api.py schemas
# ============================================================================


class TestUserProfileUpdate:
    def test_timezone_max_length(self):
        with pytest.raises(ValidationError):
            UserProfileUpdate(timezone="x" * 51)

    def test_locale_max_length(self):
        with pytest.raises(ValidationError):
            UserProfileUpdate(locale="x" * 11)

    def test_theme_max_length(self):
        with pytest.raises(ValidationError):
            UserProfileUpdate(theme="x" * 7)

    def test_valid_timezone(self):
        m = UserProfileUpdate(timezone="America/New_York")
        assert m.timezone == "America/New_York"


class TestUserCreate:
    def test_role_max_length(self):
        with pytest.raises(ValidationError):
            UserCreate(
                first_name="A",
                last_name="B",
                email="a@b.com",
                role="x" * 51,
            )

    def test_valid_role(self):
        m = UserCreate(first_name="A", last_name="B", email="a@b.com", role="admin")
        assert m.role == "admin"


class TestUserUpdate:
    def test_role_max_length(self):
        with pytest.raises(ValidationError):
            UserUpdate(role="x" * 51)


# ============================================================================
# branding.py schemas
# ============================================================================


class TestBrandingSettingsUpdate:
    def test_tenant_name_max_length(self):
        with pytest.raises(ValidationError):
            BrandingSettingsUpdate(logo_mode="mandala", tenant_name="x" * 81)

    def test_valid_tenant_name(self):
        m = BrandingSettingsUpdate(logo_mode="mandala", tenant_name="My Site")
        assert m.tenant_name == "My Site"


# ============================================================================
# oauth2.py schemas
# ============================================================================


class TestNormalClientCreate:
    def test_redirect_uri_max_length(self):
        with pytest.raises(ValidationError):
            NormalClientCreate(
                name="Test",
                redirect_uris=["x" * 2049],
            )

    def test_valid_redirect_uris(self):
        m = NormalClientCreate(name="Test", redirect_uris=["https://example.com/cb"])
        assert m.redirect_uris == ["https://example.com/cb"]


class TestClientUpdate:
    def test_redirect_uri_max_length(self):
        with pytest.raises(ValidationError):
            ClientUpdate(redirect_uris=["x" * 2049])


class TestB2BClientCreate:
    def test_role_max_length(self):
        with pytest.raises(ValidationError):
            B2BClientCreate(name="Test", role="x" * 51)


class TestClientRoleUpdate:
    def test_role_max_length(self):
        with pytest.raises(ValidationError):
            ClientRoleUpdate(role="x" * 51)


class TestAuthorizeParams:
    def test_client_id_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeParams(client_id="x" * 256, redirect_uri="https://x.com")

    def test_redirect_uri_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeParams(client_id="abc", redirect_uri="x" * 2049)

    def test_state_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeParams(client_id="abc", redirect_uri="https://x.com", state="x" * 2049)

    def test_code_challenge_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeParams(client_id="abc", redirect_uri="https://x.com", code_challenge="x" * 129)

    def test_code_challenge_method_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeParams(
                client_id="abc",
                redirect_uri="https://x.com",
                code_challenge_method="x" * 11,
            )


class TestAuthorizeForm:
    def test_client_id_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeForm(client_id="x" * 256, redirect_uri="https://x.com", action="allow")

    def test_redirect_uri_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeForm(client_id="abc", redirect_uri="x" * 2049, action="allow")

    def test_state_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeForm(
                client_id="abc", redirect_uri="https://x.com", action="allow", state="x" * 2049
            )

    def test_code_challenge_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeForm(
                client_id="abc",
                redirect_uri="https://x.com",
                action="allow",
                code_challenge="x" * 129,
            )

    def test_action_max_length(self):
        with pytest.raises(ValidationError):
            AuthorizeForm(client_id="abc", redirect_uri="https://x.com", action="x" * 11)


# ============================================================================
# saml.py schemas
# ============================================================================


class TestIdPCreate:
    def test_provider_type_max_length(self):
        with pytest.raises(ValidationError):
            IdPCreate(name="Test", provider_type="x" * 51)

    def test_entity_id_max_length(self):
        with pytest.raises(ValidationError):
            IdPCreate(name="Test", provider_type="generic", entity_id="x" * 2049)

    def test_sso_url_max_length(self):
        with pytest.raises(ValidationError):
            IdPCreate(name="Test", provider_type="generic", sso_url="x" * 2049)

    def test_slo_url_max_length(self):
        with pytest.raises(ValidationError):
            IdPCreate(name="Test", provider_type="generic", slo_url="x" * 2049)

    def test_certificate_pem_max_length(self):
        with pytest.raises(ValidationError):
            IdPCreate(name="Test", provider_type="generic", certificate_pem="x" * 16001)

    def test_metadata_url_max_length(self):
        with pytest.raises(ValidationError):
            IdPCreate(name="Test", provider_type="generic", metadata_url="x" * 2049)

    def test_metadata_xml_max_length(self):
        with pytest.raises(ValidationError):
            IdPCreate(name="Test", provider_type="generic", metadata_xml="x" * 1000001)

    def test_attribute_mapping_key_max_length(self):
        with pytest.raises(ValidationError):
            IdPCreate(
                name="Test",
                provider_type="generic",
                attribute_mapping={"x" * 256: "val"},
            )

    def test_attribute_mapping_value_max_length(self):
        with pytest.raises(ValidationError):
            IdPCreate(
                name="Test",
                provider_type="generic",
                attribute_mapping={"key": "x" * 256},
            )


class TestIdPUpdate:
    def test_name_max_length(self):
        with pytest.raises(ValidationError):
            IdPUpdate(name="x" * 256)

    def test_sso_url_max_length(self):
        with pytest.raises(ValidationError):
            IdPUpdate(sso_url="x" * 2049)

    def test_slo_url_max_length(self):
        with pytest.raises(ValidationError):
            IdPUpdate(slo_url="x" * 2049)

    def test_certificate_pem_max_length(self):
        with pytest.raises(ValidationError):
            IdPUpdate(certificate_pem="x" * 16001)

    def test_metadata_url_max_length(self):
        with pytest.raises(ValidationError):
            IdPUpdate(metadata_url="x" * 2049)

    def test_attribute_mapping_key_max_length(self):
        with pytest.raises(ValidationError):
            IdPUpdate(attribute_mapping={"x" * 256: "val"})

    def test_attribute_mapping_value_max_length(self):
        with pytest.raises(ValidationError):
            IdPUpdate(attribute_mapping={"key": "x" * 256})


class TestIdPMetadataImport:
    def test_provider_type_max_length(self):
        with pytest.raises(ValidationError):
            IdPMetadataImport(name="Test", provider_type="x" * 51, metadata_url="https://x.com")

    def test_metadata_url_max_length(self):
        with pytest.raises(ValidationError):
            IdPMetadataImport(name="Test", provider_type="generic", metadata_url="x" * 2049)


class TestIdPMetadataImportXML:
    def test_provider_type_max_length(self):
        with pytest.raises(ValidationError):
            IdPMetadataImportXML(name="Test", provider_type="x" * 51, metadata_xml="<xml/>")

    def test_metadata_xml_max_length(self):
        with pytest.raises(ValidationError):
            IdPMetadataImportXML(name="Test", provider_type="generic", metadata_xml="x" * 1000001)


class TestDomainBindingCreate:
    def test_domain_id_max_length(self):
        with pytest.raises(ValidationError):
            DomainBindingCreate(domain_id="x" * 37)


class TestUserIdpAssignment:
    def test_saml_idp_id_max_length(self):
        with pytest.raises(ValidationError):
            UserIdpAssignment(saml_idp_id="x" * 37)


# ============================================================================
# service_providers.py schemas
# ============================================================================


class TestSPCreate:
    def test_entity_id_max_length(self):
        with pytest.raises(ValidationError):
            SPCreate(name="Test", entity_id="x" * 2049)

    def test_acs_url_max_length(self):
        with pytest.raises(ValidationError):
            SPCreate(name="Test", acs_url="x" * 2049)

    def test_description_max_length(self):
        with pytest.raises(ValidationError):
            SPCreate(name="Test", description="x" * 2001)

    def test_slo_url_max_length(self):
        with pytest.raises(ValidationError):
            SPCreate(name="Test", slo_url="x" * 2049)


class TestSPMetadataImportXML:
    def test_metadata_xml_max_length(self):
        with pytest.raises(ValidationError):
            SPMetadataImportXML(name="Test", metadata_xml="x" * 1000001)


class TestSPMetadataImportURL:
    def test_metadata_url_max_length(self):
        with pytest.raises(ValidationError):
            SPMetadataImportURL(name="Test", metadata_url="x" * 2049)


class TestSPEstablishTrustURL:
    def test_metadata_url_max_length(self):
        with pytest.raises(ValidationError):
            SPEstablishTrustURL(metadata_url="x" * 2049)


class TestSPEstablishTrustXML:
    def test_metadata_xml_max_length(self):
        with pytest.raises(ValidationError):
            SPEstablishTrustXML(metadata_xml="x" * 1000001)


class TestSPEstablishTrustManual:
    def test_entity_id_max_length(self):
        with pytest.raises(ValidationError):
            SPEstablishTrustManual(entity_id="x" * 2049, acs_url="https://x.com/acs")

    def test_acs_url_max_length(self):
        with pytest.raises(ValidationError):
            SPEstablishTrustManual(entity_id="urn:test", acs_url="x" * 2049)

    def test_slo_url_max_length(self):
        with pytest.raises(ValidationError):
            SPEstablishTrustManual(
                entity_id="urn:test", acs_url="https://x.com/acs", slo_url="x" * 2049
            )


class TestSPUpdate:
    def test_description_max_length(self):
        with pytest.raises(ValidationError):
            SPUpdate(description="x" * 2001)

    def test_acs_url_max_length(self):
        with pytest.raises(ValidationError):
            SPUpdate(acs_url="x" * 2049)

    def test_slo_url_max_length(self):
        with pytest.raises(ValidationError):
            SPUpdate(slo_url="x" * 2049)

    def test_attribute_mapping_key_max_length(self):
        with pytest.raises(ValidationError):
            SPUpdate(attribute_mapping={"x" * 256: "val"})

    def test_attribute_mapping_value_max_length(self):
        with pytest.raises(ValidationError):
            SPUpdate(attribute_mapping={"key": "x" * 256})


class TestSPGroupAssignAdd:
    def test_group_id_max_length(self):
        with pytest.raises(ValidationError):
            SPGroupAssignAdd(group_id="x" * 37)


class TestSPGroupBulkAssign:
    def test_group_id_max_length(self):
        with pytest.raises(ValidationError):
            SPGroupBulkAssign(group_ids=["x" * 37])

    def test_list_max_length(self):
        with pytest.raises(ValidationError):
            SPGroupBulkAssign(group_ids=["a" * 36] * 5001)


class TestSPMetadataReimport:
    def test_metadata_xml_max_length(self):
        with pytest.raises(ValidationError):
            SPMetadataReimport(metadata_xml="x" * 1000001)


# ============================================================================
# groups.py schemas
# ============================================================================


class TestGroupMemberAdd:
    def test_user_id_max_length(self):
        with pytest.raises(ValidationError):
            GroupMemberAdd(user_id="x" * 37)


class TestGroupChildAdd:
    def test_child_group_id_max_length(self):
        with pytest.raises(ValidationError):
            GroupChildAdd(child_group_id="x" * 37)


class TestGroupParentAdd:
    def test_parent_group_id_max_length(self):
        with pytest.raises(ValidationError):
            GroupParentAdd(parent_group_id="x" * 37)


class TestBulkMemberRemove:
    def test_user_id_max_length(self):
        with pytest.raises(ValidationError):
            BulkMemberRemove(user_ids=["x" * 37])

    def test_list_max_length(self):
        with pytest.raises(ValidationError):
            BulkMemberRemove(user_ids=["a" * 36] * 5001)


class TestBulkMemberAdd:
    def test_user_id_max_length(self):
        with pytest.raises(ValidationError):
            BulkMemberAdd(user_ids=["x" * 37])

    def test_list_max_length(self):
        with pytest.raises(ValidationError):
            BulkMemberAdd(user_ids=["a" * 36] * 5001)


class TestUserGroupsAdd:
    def test_group_id_max_length(self):
        with pytest.raises(ValidationError):
            UserGroupsAdd(group_ids=["x" * 37])

    def test_list_max_length(self):
        with pytest.raises(ValidationError):
            UserGroupsAdd(group_ids=["a" * 36] * 5001)
