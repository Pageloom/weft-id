"""Tests for SAML upstream attribute ingestion (Iteration 5).

Covers:
* ``_extract_mapped_attributes`` lifts standard registry keys via the per-IdP
  ``attribute_mapping`` into a separate ``standard_attributes`` dict.
* ``authenticate_via_saml`` wires that dict into ``apply_idp_attributes`` for
  both existing-user and JIT-user branches.
* Mirror flag (per-tenant per-attribute) is honored: ``mirror_from_idp=true``
  copies the value into ``user_attributes``; ``mirror_from_idp=false`` only
  records it in ``user_idp_attributes``.
* IdP-mirror failure does not break SAML login.
* ``IdPCreate`` / ``IdPUpdate`` validators reject unknown mapping keys and
  accept registry keys.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def idp_data_no_mapping():
    """IdP data without an explicit attribute_mapping (uses defaults)."""
    return {
        "name": "Iter5 IdP",
        "provider_type": "okta",
        "entity_id": "https://iter5.example.com/entity",
        "sso_url": "https://iter5.example.com/sso",
        "certificate_pem": (
            "-----BEGIN CERTIFICATE-----\n"
            "MIICpDCCAYwCCQC5RNM/8zPIfzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n"
            "-----END CERTIFICATE-----"
        ),
    }


def _make_requesting_user(user, tenant_id, role="super_admin"):
    from services.types import RequestingUser

    return RequestingUser(
        id=str(user["id"]),
        tenant_id=tenant_id,
        role=role,
    )


def _build_idp_config(**overrides):
    """Build an IdPConfig stub for _extract_mapped_attributes tests."""
    from datetime import UTC, datetime

    from schemas.saml import IdPConfig

    base = {
        "id": "00000000-0000-0000-0000-000000000001",
        "name": "Stub IdP",
        "provider_type": "okta",
        "entity_id": "https://stub/idp",
        "sso_url": "https://stub/sso",
        "slo_url": None,
        "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "metadata_url": None,
        "metadata_xml": None,
        "metadata_last_fetched_at": None,
        "metadata_fetch_error": None,
        "sp_entity_id": "https://test/saml/metadata",
        "sp_acs_url": "https://test/saml/acs",
        "attribute_mapping": {
            "email": "email",
            "first_name": "firstName",
            "last_name": "lastName",
            "groups": "groups",
        },
        "is_enabled": True,
        "is_default": False,
        "require_platform_mfa": False,
        "jit_provisioning": False,
        "trust_established": True,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    base.update(overrides)
    return IdPConfig(**base)


# ---------------------------------------------------------------------------
# _extract_mapped_attributes
# ---------------------------------------------------------------------------


class TestExtractMappedAttributes:
    """Unit tests for _extract_mapped_attributes (no DB)."""

    def _mock_auth(self, raw_attributes):
        auth = MagicMock()
        auth.get_attributes.return_value = raw_attributes
        auth.get_nameid.return_value = "user@example.com"
        auth.get_nameid_format.return_value = (
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        )
        return auth

    def test_includes_standard_attributes_with_default_friendly_names(self):
        from services.saml.auth import _extract_mapped_attributes

        idp = _build_idp_config()
        auth = self._mock_auth(
            {
                "email": ["user@example.com"],
                "firstName": ["Ada"],
                "lastName": ["Lovelace"],
                "jobTitle": ["Engineer"],
                "phoneWork": ["+1 555 1234"],
                "department": ["Research"],
            }
        )

        result = _extract_mapped_attributes(auth, idp)

        std = result["standard_attributes"]
        assert std["job_title"] == "Engineer"
        assert std["phone_work"] == "+1 555 1234"
        assert std["department"] == "Research"

    def test_uses_per_idp_mapping_for_standard_keys(self):
        from services.saml.auth import _extract_mapped_attributes

        idp = _build_idp_config(
            attribute_mapping={
                "email": "email",
                "first_name": "firstName",
                "last_name": "lastName",
                "groups": "groups",
                "job_title": "custom.title.field",
                "phone_work": "urn:oid:2.5.4.20",
            }
        )
        auth = self._mock_auth(
            {
                "email": ["u@e.com"],
                "firstName": ["A"],
                "lastName": ["B"],
                "custom.title.field": ["Architect"],
                "urn:oid:2.5.4.20": ["+1 555 9999"],
                # This should NOT land because the mapping points elsewhere.
                "jobTitle": ["IGNORED"],
            }
        )

        std = _extract_mapped_attributes(auth, idp)["standard_attributes"]

        assert std["job_title"] == "Architect"
        assert std["phone_work"] == "+1 555 9999"

    def test_omits_keys_not_present_in_assertion(self):
        from services.saml.auth import _extract_mapped_attributes

        idp = _build_idp_config()
        auth = self._mock_auth(
            {
                "email": ["u@e.com"],
                "firstName": ["A"],
                "lastName": ["B"],
            }
        )

        std = _extract_mapped_attributes(auth, idp)["standard_attributes"]
        assert std == {}

    def test_drops_empty_standard_values(self):
        from services.saml.auth import _extract_mapped_attributes

        idp = _build_idp_config()
        auth = self._mock_auth(
            {
                "email": ["u@e.com"],
                "firstName": ["A"],
                "lastName": ["B"],
                "jobTitle": [""],
                "phoneWork": [None],
                "department": ["   "],
                "city": ["Stockholm"],
            }
        )

        std = _extract_mapped_attributes(auth, idp)["standard_attributes"]
        assert "job_title" not in std
        assert "phone_work" not in std
        assert "department" not in std
        assert std["city"] == "Stockholm"


# ---------------------------------------------------------------------------
# authenticate_via_saml wiring
# ---------------------------------------------------------------------------


class TestAuthenticateViaSAMLWiring:
    """Verify apply_idp_attributes is invoked for both branches."""

    def _make_saml_result(self, idp_id, email, std_attrs=None, **overrides):
        from schemas.saml import SAMLAttributes, SAMLAuthResult

        return SAMLAuthResult(
            attributes=SAMLAttributes(
                email=email,
                first_name=overrides.get("first_name", "Test"),
                last_name=overrides.get("last_name", "User"),
                name_id=email,
            ),
            idp_id=idp_id,
            requires_mfa=False,
            standard_attributes=std_attrs or {},
        )

    def test_existing_user_invokes_apply_idp_attributes(
        self, test_tenant, test_super_admin_user, test_user, idp_data_no_mapping
    ):
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        idp = saml_service.create_identity_provider(
            requesting,
            IdPCreate(**idp_data_no_mapping, is_enabled=True),
            "https://test.example.com",
        )

        saml_result = self._make_saml_result(
            idp.id,
            test_user["email"],
            std_attrs={"job_title": "Engineer"},
        )

        with patch("services.saml.provisioning.apply_idp_attributes") as mock_apply:
            saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

        mock_apply.assert_called_once()
        call_kwargs = mock_apply.call_args.kwargs
        assert call_kwargs["tenant_id"] == test_tenant["id"]
        assert call_kwargs["user_id"] == str(test_user["id"])
        assert call_kwargs["idp_id"] == idp.id
        assert call_kwargs["attributes"] == {"job_title": "Engineer"}
        assert call_kwargs["actor_user_id"] == str(test_user["id"])

    def test_jit_user_invokes_apply_idp_attributes(
        self, test_tenant, test_super_admin_user, idp_data_no_mapping
    ):
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        idp = saml_service.create_identity_provider(
            requesting,
            IdPCreate(**idp_data_no_mapping, is_enabled=True, jit_provisioning=True),
            "https://test.example.com",
        )

        new_email = "iter5.jit@example.com"
        saml_result = self._make_saml_result(
            idp.id,
            new_email,
            std_attrs={"department": "Sales"},
            first_name="JIT",
            last_name="Person",
        )

        with patch("services.saml.provisioning.apply_idp_attributes") as mock_apply:
            user = saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

        mock_apply.assert_called_once()
        call_kwargs = mock_apply.call_args.kwargs
        assert call_kwargs["tenant_id"] == test_tenant["id"]
        assert call_kwargs["user_id"] == str(user["id"])
        assert call_kwargs["idp_id"] == idp.id
        assert call_kwargs["attributes"] == {"department": "Sales"}

    def test_apply_idp_attributes_failure_does_not_break_login(
        self, test_tenant, test_super_admin_user, test_user, idp_data_no_mapping
    ):
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")
        idp = saml_service.create_identity_provider(
            requesting,
            IdPCreate(**idp_data_no_mapping, is_enabled=True),
            "https://test.example.com",
        )

        saml_result = self._make_saml_result(
            idp.id,
            test_user["email"],
            std_attrs={"job_title": "Engineer"},
        )

        with patch(
            "services.saml.provisioning.apply_idp_attributes",
            side_effect=RuntimeError("simulated DB outage"),
        ):
            user = saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

        # Login still succeeds.
        assert str(user["id"]) == str(test_user["id"])


# ---------------------------------------------------------------------------
# Mirror flag end-to-end
# ---------------------------------------------------------------------------


class TestMirrorFlagEndToEnd:
    """Verify the mirror_from_idp flag drives canonical writes."""

    def _make_saml_result(self, idp_id, email, std_attrs):
        from schemas.saml import SAMLAttributes, SAMLAuthResult

        return SAMLAuthResult(
            attributes=SAMLAttributes(
                email=email,
                first_name="Test",
                last_name="User",
                name_id=email,
            ),
            idp_id=idp_id,
            requires_mfa=False,
            standard_attributes=std_attrs,
        )

    def _seed_tenant_config(self, tenant_id):
        """Ensure all 14 attribute config rows exist for the tenant."""
        from services.settings import attributes as attributes_settings

        attributes_settings.seed_tenant_attribute_config(tenant_id)

    def _set_attribute_policy(self, requesting_user, attribute_key, *, enabled, mirror_from_idp):
        from services.settings import attributes as attributes_settings

        # Make sure the row exists.
        attributes_settings.seed_tenant_attribute_config(requesting_user["tenant_id"])

        attributes_settings.update_tenant_attribute_config(
            requesting_user,
            attribute_key,
            enabled=enabled,
            required=False,
            mirror_from_idp=mirror_from_idp,
            locked_for_users=False,
            send_to_sps_default=False,
        )

    def test_mirror_on_writes_user_attributes_and_idp_mirror(
        self, test_tenant, test_super_admin_user, test_user, idp_data_no_mapping
    ):
        import database
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

        # Enable + mirror_from_idp=true for job_title
        self._set_attribute_policy(requesting, "job_title", enabled=True, mirror_from_idp=True)

        idp = saml_service.create_identity_provider(
            requesting,
            IdPCreate(**idp_data_no_mapping, is_enabled=True),
            "https://test.example.com",
        )

        saml_result = self._make_saml_result(idp.id, test_user["email"], {"job_title": "Engineer"})

        saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "job_title"
        )
        assert canonical is not None
        assert canonical["value"] == "Engineer"

        idp_rows = database.user_idp_attributes.list_attributes_for_idp(
            test_tenant["id"], str(test_user["id"]), idp.id
        )
        idp_row_keys = {r["attribute_key"] for r in idp_rows}
        assert "job_title" in idp_row_keys

    def test_mirror_off_skips_user_attributes_but_writes_idp_mirror(
        self, test_tenant, test_super_admin_user, test_user, idp_data_no_mapping
    ):
        import database
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

        # Clear any pre-existing canonical row from prior tests.
        database.user_attributes.delete_attribute(
            test_tenant["id"], str(test_user["id"]), "department"
        )

        # Enable but mirror_from_idp=false for department
        self._set_attribute_policy(requesting, "department", enabled=True, mirror_from_idp=False)

        idp = saml_service.create_identity_provider(
            requesting,
            IdPCreate(**idp_data_no_mapping, is_enabled=True),
            "https://test.example.com",
        )

        saml_result = self._make_saml_result(idp.id, test_user["email"], {"department": "Research"})

        saml_service.authenticate_via_saml(test_tenant["id"], saml_result)

        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "department"
        )
        assert canonical is None

        idp_rows = database.user_idp_attributes.list_attributes_for_idp(
            test_tenant["id"], str(test_user["id"]), idp.id
        )
        idp_row_map = {r["attribute_key"]: r["value"] for r in idp_rows}
        assert idp_row_map.get("department") == "Research"

    def test_mirror_flag_flip_does_not_retract_prior_canonical_value(
        self, test_tenant, test_super_admin_user, test_user, idp_data_no_mapping
    ):
        """Toggling mirror_from_idp=true→false leaves the prior canonical row in place.

        The two-space pivot deliberately makes mirroring a one-way copy:
        once a value lands in ``user_attributes`` it is owned by the
        user/admin. Disabling the mirror flag stops FUTURE IdP logins from
        overwriting the canonical row, but does not retract values already
        mirrored. Pin this so a future refactor cannot accidentally
        introduce a "clear canonical on flag-off" side effect.
        """
        import database
        from schemas.saml import IdPCreate
        from services import saml as saml_service

        requesting = _make_requesting_user(test_super_admin_user, test_tenant["id"], "super_admin")

        # Enable + mirror=true, IdP login writes canonical.
        self._set_attribute_policy(requesting, "job_title", enabled=True, mirror_from_idp=True)
        idp = saml_service.create_identity_provider(
            requesting,
            IdPCreate(**idp_data_no_mapping, is_enabled=True),
            "https://test.example.com",
        )
        saml_service.authenticate_via_saml(
            test_tenant["id"],
            self._make_saml_result(idp.id, test_user["email"], {"job_title": "Engineer"}),
        )
        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "job_title"
        )
        assert canonical is not None and canonical["value"] == "Engineer"

        # Admin flips mirror_from_idp=false; canonical row must persist.
        self._set_attribute_policy(requesting, "job_title", enabled=True, mirror_from_idp=False)
        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "job_title"
        )
        assert canonical is not None
        assert canonical["value"] == "Engineer"

        # Next IdP login with a new value: canonical must NOT be overwritten
        # because mirror is now off. IdP-mirror table receives the new value.
        saml_service.authenticate_via_saml(
            test_tenant["id"],
            self._make_saml_result(idp.id, test_user["email"], {"job_title": "Senior Engineer"}),
        )
        canonical = database.user_attributes.get_attribute(
            test_tenant["id"], str(test_user["id"]), "job_title"
        )
        assert canonical["value"] == "Engineer"  # unchanged

        idp_rows = database.user_idp_attributes.list_attributes_for_idp(
            test_tenant["id"], str(test_user["id"]), idp.id
        )
        idp_row_map = {r["attribute_key"]: r["value"] for r in idp_rows}
        assert idp_row_map.get("job_title") == "Senior Engineer"


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestAttributeMappingValidation:
    """IdPCreate / IdPUpdate validators on attribute_mapping keys."""

    def test_idp_create_accepts_fixed_keys(self):
        from schemas.saml import IdPCreate

        # Default-construction (no explicit mapping) must pass.
        IdPCreate(name="X", provider_type="okta")

    def test_idp_create_accepts_registry_key(self):
        from schemas.saml import IdPCreate

        IdPCreate(
            name="X",
            provider_type="okta",
            attribute_mapping={
                "email": "email",
                "first_name": "firstName",
                "last_name": "lastName",
                "groups": "groups",
                "job_title": "title",
                "phone_work": "phone",
            },
        )

    def test_idp_create_rejects_unknown_key(self):
        from pydantic import ValidationError as PydanticValidationError
        from schemas.saml import IdPCreate

        with pytest.raises(PydanticValidationError) as exc_info:
            IdPCreate(
                name="X",
                provider_type="okta",
                attribute_mapping={"bogus": "xyz"},
            )

        assert "unknown keys" in str(exc_info.value)
        assert "bogus" in str(exc_info.value)

    def test_idp_update_accepts_partial_registry_mapping(self):
        from schemas.saml import IdPUpdate

        IdPUpdate(attribute_mapping={"job_title": "title"})

    def test_idp_update_rejects_unknown_key(self):
        from pydantic import ValidationError as PydanticValidationError
        from schemas.saml import IdPUpdate

        with pytest.raises(PydanticValidationError):
            IdPUpdate(attribute_mapping={"weird": "xyz"})

    def test_idp_update_none_mapping_passes(self):
        from schemas.saml import IdPUpdate

        IdPUpdate(attribute_mapping=None)
