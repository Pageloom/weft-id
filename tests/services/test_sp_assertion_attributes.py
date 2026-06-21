"""Tests for Iteration 6: SP assertion attribute bridge + SP create seeding.

Covers the helper that bridges the SP's attribute_mapping with the value
sources (users row + user_attributes EAV) and the SP create paths that
seed attribute_mapping from tenant_attribute_config.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from constants.user_attributes import ATTRIBUTE_KEYS
from services.service_providers.crud import _seeded_attribute_mapping
from services.service_providers.sso import _build_assertion_attributes


def _all_enabled_config(extra: list[str] | None = None) -> list[dict]:
    """Build a tenant_attribute_config snapshot with every registry key enabled.

    Lets _build_assertion_attributes tests focus on the EAV-merge behaviour
    without worrying about the tenant-disabled filter (Fix 1).
    """
    keys = set(ATTRIBUTE_KEYS)
    if extra:
        keys.update(extra)
    return [{"attribute_key": k, "enabled": True} for k in keys]


# ============================================================================
# Bridge helper: _build_assertion_attributes
# ============================================================================


class TestBuildAssertionAttributes:
    """Bridge between attribute_mapping and value sources."""

    @patch("services.service_providers.sso.database")
    def test_fixed_keys_from_users_row(self, mock_db):
        """Email/firstName/lastName/displayName come from users row, not EAV."""
        mock_db.user_attributes.list_attributes.return_value = []
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="alice@example.com",
            first_name="Alice",
            last_name="Smith",
            group_names=[],
            attribute_mapping=None,
        )
        assert result["email"] == "alice@example.com"
        assert result["firstName"] == "Alice"
        assert result["lastName"] == "Smith"
        assert result["displayName"] == "Alice Smith"
        assert "groups" not in result

    @patch("services.service_providers.sso.database")
    def test_groups_included_when_present(self, mock_db):
        mock_db.user_attributes.list_attributes.return_value = []
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=["engineering", "managers"],
            attribute_mapping=None,
        )
        assert result["groups"] == ["engineering", "managers"]

    @patch("services.service_providers.sso.database")
    def test_standard_attributes_merged_from_eav(self, mock_db):
        """EAV rows for registry keys are merged into the result."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer"},
            {"attribute_key": "department", "value": "R&D"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={
                "email": "email",
                "job_title": "jobTitle",
                "department": "department",
            },
        )
        assert result["job_title"] == "Engineer"
        assert result["department"] == "R&D"

    @patch("services.service_providers.sso.database")
    def test_missing_value_not_emitted(self, mock_db):
        """Mapping with no matching EAV value produces no entry."""
        mock_db.user_attributes.list_attributes.return_value = []
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"email": "email", "job_title": "jobTitle"},
        )
        # job_title in mapping but no value in EAV => no key in result.
        assert "job_title" not in result

    @patch("services.service_providers.sso.database")
    def test_eav_key_not_in_mapping_is_dropped(self, mock_db):
        """User has a value but SP mapping omits the key => omit from result."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer"},
            {"attribute_key": "department", "value": "R&D"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"email": "email", "job_title": "jobTitle"},
        )
        # job_title in mapping => present
        assert result["job_title"] == "Engineer"
        # department NOT in mapping => omitted
        assert "department" not in result

    @patch("services.service_providers.sso.database")
    def test_no_mapping_includes_all_standard_values(self, mock_db):
        """attribute_mapping=None means: include every non-empty EAV value."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping=None,
        )
        assert result["job_title"] == "Engineer"

    @patch("services.service_providers.sso.database")
    def test_unknown_registry_key_skipped(self, mock_db):
        """Stray EAV rows for keys outside the registry are silently dropped."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "fake_unknown_key", "value": "x"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"fake_unknown_key": "fake"},
        )
        assert "fake_unknown_key" not in result

    @patch("services.service_providers.sso.database")
    def test_empty_eav_value_dropped(self, mock_db):
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": ""},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )
        assert "job_title" not in result

    @patch("services.service_providers.sso.database")
    def test_empty_first_last_skipped(self, mock_db):
        """Empty firstName/lastName/displayName not emitted."""
        mock_db.user_attributes.list_attributes.return_value = []
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="",
            last_name="",
            group_names=[],
            attribute_mapping=None,
        )
        assert "firstName" not in result
        assert "lastName" not in result
        assert "displayName" not in result
        assert result["email"] == "a@b.com"

    @patch("services.service_providers.sso.database")
    def test_db_failure_does_not_break_assertion(self, mock_db):
        """DB error on EAV read is swallowed; fixed keys still emitted."""
        mock_db.user_attributes.list_attributes.side_effect = RuntimeError("boom")
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )
        # Fixed keys still present; standard keys absent.
        assert result["email"] == "a@b.com"
        assert "job_title" not in result

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_config_read_failure_emits_audit_event_with_phase_config(self, mock_db, mock_log_event):
        """tenant_attribute_config read failure logs an audit event with
        ``phase=config`` and the exception class name, and the assertion
        still builds without raising."""

        class FakeConfigDBError(RuntimeError):
            pass

        mock_db.tenant_attribute_config.list_config.side_effect = FakeConfigDBError("kaboom")
        mock_db.user_attributes.list_attributes.return_value = []

        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )

        # Assertion still built.
        assert result["email"] == "a@b.com"

        # Find the config-phase audit event among any log_event calls.
        config_calls = [
            c
            for c in mock_log_event.call_args_list
            if c.kwargs.get("event_type") == "tenant_attribute_config_read_failed"
            and c.kwargs.get("metadata", {}).get("phase") == "config"
        ]
        assert len(config_calls) == 1
        call = config_calls[0]
        assert call.kwargs["tenant_id"] == "tenant-1"
        assert call.kwargs["actor_user_id"] == "user-1"
        assert call.kwargs["artifact_type"] == "tenant"
        assert call.kwargs["artifact_id"] == "tenant-1"
        assert call.kwargs["metadata"]["error_class"] == "FakeConfigDBError"

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_user_attributes_read_failure_emits_audit_event_with_phase_user_attributes(
        self, mock_db, mock_log_event
    ):
        """user_attributes read failure logs an audit event with
        ``phase=user_attributes`` and the exception class name, and the
        assertion still builds without raising."""

        class FakeUserAttrDBError(RuntimeError):
            pass

        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        mock_db.user_attributes.list_attributes.side_effect = FakeUserAttrDBError("nope")

        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )

        # Assertion still built; fixed key intact.
        assert result["email"] == "a@b.com"
        assert "job_title" not in result

        user_attr_calls = [
            c
            for c in mock_log_event.call_args_list
            if c.kwargs.get("event_type") == "tenant_attribute_config_read_failed"
            and c.kwargs.get("metadata", {}).get("phase") == "user_attributes"
        ]
        assert len(user_attr_calls) == 1
        call = user_attr_calls[0]
        assert call.kwargs["tenant_id"] == "tenant-1"
        assert call.kwargs["actor_user_id"] == "user-1"
        assert call.kwargs["artifact_type"] == "user"
        assert call.kwargs["artifact_id"] == "user-1"
        assert call.kwargs["metadata"]["error_class"] == "FakeUserAttrDBError"

    @patch("services.service_providers.sso.log_event")
    @patch("services.service_providers.sso.database")
    def test_log_event_failure_does_not_cascade_into_sso(self, mock_db, mock_log_event):
        """If the audit ``log_event`` itself raises (e.g. the same DB outage
        that broke the config read also breaks event logging), the SSO
        assertion still builds. The nested try/except is the guard."""
        mock_db.tenant_attribute_config.list_config.side_effect = RuntimeError("db down")
        mock_db.user_attributes.list_attributes.return_value = []
        mock_log_event.side_effect = RuntimeError("event log also down")

        # Must not raise.
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )

        # Fixed keys still emitted; standard attrs are absent because the
        # config read failed.
        assert result["email"] == "a@b.com"
        assert "job_title" not in result

    @patch("services.service_providers.sso.database")
    def test_tenant_disabled_attribute_does_not_leak(self, mock_db):
        """Fix 1: a tenant-disabled standard attribute is NOT emitted even when
        the SP mapping still references the key and the user has a value."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer"},
        ]
        # job_title disabled at the tenant level
        mock_db.tenant_attribute_config.list_config.return_value = [
            {"attribute_key": "job_title", "enabled": False},
            {"attribute_key": "department", "enabled": True},
        ]
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"email": "email", "job_title": "jobTitle"},
        )
        # job_title in mapping AND has EAV value, but tenant disabled => omitted
        assert "job_title" not in result
        assert result["email"] == "a@b.com"

    @patch("services.service_providers.sso.database")
    def test_display_name_eav_wins_over_fixed_composition(self, mock_db):
        """Fix 2: when registry display_name has a value AND the mapping
        includes display_name, the fixed displayName composition is dropped
        so the wire name 'displayName' is emitted exactly once (from EAV)."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "display_name", "value": "Custom Display"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="Alice",
            last_name="Smith",
            group_names=[],
            attribute_mapping={
                "email": "email",
                "displayName": "displayName",
                "display_name": "displayName",
            },
        )
        assert result["display_name"] == "Custom Display"
        # Fixed displayName has been dropped so build_saml_response emits the
        # wire name exactly once.
        assert "displayName" not in result

    @patch("services.service_providers.sso.database")
    def test_display_name_dedup_runs_for_unmapped_sp(self, mock_db):
        """Blocker 2: when the SP has no attribute_mapping configured and the
        user has BOTH a fixed displayName (from first+last) AND an EAV
        display_name value, the result must contain exactly one of them.

        Without this guard, build_saml_response emits two ``<saml:Attribute>``
        elements for what is logically the same field. The EAV value wins.
        """
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "display_name", "value": "Custom Display"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="Alice",
            last_name="Smith",
            group_names=[],
            attribute_mapping=None,  # <-- unmapped SP
        )
        # EAV display_name wins; fixed displayName is dropped.
        assert result["display_name"] == "Custom Display"
        assert "displayName" not in result

    @patch("services.service_providers.sso.database")
    def test_display_name_unmapped_no_eav_keeps_fixed_composition(self, mock_db):
        """Blocker 2: unmapped SP, no EAV display_name => fixed displayName
        is preserved (the existing behaviour when there is nothing to dedup
        against)."""
        mock_db.user_attributes.list_attributes.return_value = []
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="Alice",
            last_name="Smith",
            group_names=[],
            attribute_mapping=None,
        )
        assert result["displayName"] == "Alice Smith"
        assert "display_name" not in result

    @patch("services.service_providers.sso.database")
    def test_display_name_falls_back_to_fixed_composition(self, mock_db):
        """Fix 2: when display_name is mapped but the user has no stored
        value, the fixed firstName+lastName composition fills the wire slot."""
        mock_db.user_attributes.list_attributes.return_value = []
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="Alice",
            last_name="Smith",
            group_names=[],
            attribute_mapping={
                "email": "email",
                "displayName": "displayName",
                "display_name": "displayName",
            },
        )
        # No EAV value => display_name key absent and fixed composition wins.
        assert "display_name" not in result
        assert result["displayName"] == "Alice Smith"

    @patch("services.service_providers.sso.database")
    def test_corrupt_eav_value_skipped(self, mock_db):
        """Fix 3: a row whose value fails the per-type validator is silently
        dropped rather than breaking the whole assertion. ``country`` requires
        ISO 3166-1 alpha-2 (exactly 2 letters), so 'XYZ' fails validation."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "country", "value": "XYZ"},
            {"attribute_key": "job_title", "value": "Engineer"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"country": "country", "job_title": "jobTitle"},
        )
        # Corrupt country dropped; valid job_title still emitted.
        assert "country" not in result
        assert result["job_title"] == "Engineer"

    @patch("services.service_providers.sso.database")
    def test_result_keys_are_fixed_or_in_mapping(self, mock_db):
        """Invariant: when attribute_mapping is provided, every key in the
        result dict is either a fixed key or appears in attribute_mapping."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer"},
            {"attribute_key": "department", "value": "R&D"},
            # An EAV row for a registry key the SP did NOT map.
            {"attribute_key": "organization", "value": "Acme"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = _all_enabled_config()
        mapping = {
            "email": "email",
            "firstName": "firstName",
            "lastName": "lastName",
            "displayName": "displayName",
            "groups": "groups",
            "job_title": "jobTitle",
            "department": "department",
        }
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=["g1"],
            attribute_mapping=mapping,
        )
        fixed = {"email", "firstName", "lastName", "displayName", "groups"}
        for key in result:
            assert key in fixed or key in mapping, (
                f"unexpected key {key!r} in result not covered by fixed set or mapping"
            )


class TestSelfSourcedProvenanceFilter:
    """A user-set ('self'-sourced) value must not enter a signed assertion
    unless the tenant marked the attribute ``allow_self_sourced_to_sp``.
    'idp'/'admin'-sourced values are authority-grade and always pass.
    """

    @staticmethod
    def _config(allow_self: bool) -> list[dict]:
        """Enabled config for job_title with an explicit allow_self flag."""
        return [
            {
                "attribute_key": "job_title",
                "enabled": True,
                "allow_self_sourced_to_sp": allow_self,
            },
        ]

    @patch("services.service_providers.sso.database")
    def test_self_sourced_withheld_by_default(self, mock_db):
        """allow_self_sourced_to_sp=False => a 'self' value is dropped."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer", "source": "self"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = self._config(False)
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )
        assert "job_title" not in result

    @patch("services.service_providers.sso.database")
    def test_self_sourced_emitted_when_opted_in(self, mock_db):
        """allow_self_sourced_to_sp=True => the 'self' value flows to the SP."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer", "source": "self"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = self._config(True)
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )
        assert result["job_title"] == "Engineer"

    @patch("services.service_providers.sso.database")
    def test_admin_sourced_always_emitted(self, mock_db):
        """An 'admin' value is authority-grade: emitted even with allow off."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer", "source": "admin"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = self._config(False)
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )
        assert result["job_title"] == "Engineer"

    @patch("services.service_providers.sso.database")
    def test_idp_sourced_always_emitted(self, mock_db):
        """An 'idp' value is authority-grade: emitted even with allow off."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer", "source": "idp"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = self._config(False)
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )
        assert result["job_title"] == "Engineer"

    @patch("services.service_providers.sso.database")
    def test_self_sourced_withheld_on_config_outage(self, mock_db):
        """Default-deny: when the config read fails (no per-key flag), a 'self'
        value is withheld rather than leaked into the signed assertion."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer", "source": "self"},
        ]
        mock_db.tenant_attribute_config.list_config.side_effect = RuntimeError("db down")
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )
        assert "job_title" not in result

    @patch("services.service_providers.sso.database")
    def test_missing_source_treated_as_trusted(self, mock_db):
        """A row with no source key (legacy/unset) is not 'self', so it is not
        gated by the provenance filter and flows as before."""
        mock_db.user_attributes.list_attributes.return_value = [
            {"attribute_key": "job_title", "value": "Engineer"},
        ]
        mock_db.tenant_attribute_config.list_config.return_value = self._config(False)
        result = _build_assertion_attributes(
            "tenant-1",
            "user-1",
            email="a@b.com",
            first_name="A",
            last_name="B",
            group_names=[],
            attribute_mapping={"job_title": "jobTitle"},
        )
        assert result["job_title"] == "Engineer"


# ============================================================================
# SP create seeding: _seeded_attribute_mapping
# ============================================================================


class TestSeededAttributeMapping:
    """Defaults seeded into a new SP's attribute_mapping."""

    @patch("services.service_providers.crud.database")
    def test_returns_fixed_defaults_when_no_config(self, mock_db):
        """No tenant config rows => only the fixed defaults."""
        mock_db.tenant_attribute_config.list_config.return_value = []
        result = _seeded_attribute_mapping("tenant-1")
        assert result == {
            "email": "email",
            "firstName": "firstName",
            "lastName": "lastName",
            "displayName": "displayName",
            "groups": "groups",
        }

    @patch("services.service_providers.crud.database")
    def test_includes_enabled_and_send_default_keys(self, mock_db):
        """Each (enabled=true AND send_to_sps_default=true) row adds a default row."""
        mock_db.tenant_attribute_config.list_config.return_value = [
            {
                "attribute_key": "job_title",
                "enabled": True,
                "send_to_sps_default": True,
            },
            {
                "attribute_key": "department",
                "enabled": True,
                "send_to_sps_default": True,
            },
        ]
        result = _seeded_attribute_mapping("tenant-1")
        assert result["job_title"] == "jobTitle"
        assert result["department"] == "department"

    @patch("services.service_providers.crud.database")
    def test_skips_disabled_keys(self, mock_db):
        mock_db.tenant_attribute_config.list_config.return_value = [
            {
                "attribute_key": "job_title",
                "enabled": False,
                "send_to_sps_default": True,
            },
        ]
        result = _seeded_attribute_mapping("tenant-1")
        assert "job_title" not in result

    @patch("services.service_providers.crud.database")
    def test_skips_send_default_false(self, mock_db):
        mock_db.tenant_attribute_config.list_config.return_value = [
            {
                "attribute_key": "job_title",
                "enabled": True,
                "send_to_sps_default": False,
            },
        ]
        result = _seeded_attribute_mapping("tenant-1")
        assert "job_title" not in result

    @patch("services.service_providers.crud.database")
    def test_skips_unknown_registry_keys(self, mock_db):
        mock_db.tenant_attribute_config.list_config.return_value = [
            {
                "attribute_key": "not_a_real_attr",
                "enabled": True,
                "send_to_sps_default": True,
            },
        ]
        result = _seeded_attribute_mapping("tenant-1")
        assert "not_a_real_attr" not in result

    @patch("services.service_providers.crud.database")
    def test_db_failure_returns_fixed_defaults(self, mock_db):
        mock_db.tenant_attribute_config.list_config.side_effect = RuntimeError("boom")
        result = _seeded_attribute_mapping("tenant-1")
        # Falls back to fixed defaults rather than failing.
        assert "email" in result
        assert "firstName" in result


# ============================================================================
# Schema validator: SPUpdate.attribute_mapping
# ============================================================================


class TestSPUpdateAttributeMappingValidator:
    """SPUpdate rejects mapping keys outside fixed-SP set ∪ registry."""

    def test_accepts_fixed_keys(self):
        from schemas.service_providers import SPUpdate

        u = SPUpdate(
            attribute_mapping={
                "email": "email",
                "firstName": "givenName",
                "lastName": "sn",
                "displayName": "cn",
                "groups": "groups",
            }
        )
        assert u.attribute_mapping is not None

    def test_accepts_standard_registry_keys(self):
        from schemas.service_providers import SPUpdate

        u = SPUpdate(attribute_mapping={"job_title": "jobTitle", "department": "department"})
        assert u.attribute_mapping["job_title"] == "jobTitle"

    def test_rejects_unknown_keys(self):
        from pydantic import ValidationError as PydanticValidationError
        from schemas.service_providers import SPUpdate

        with pytest.raises(PydanticValidationError) as exc_info:
            SPUpdate(attribute_mapping={"made_up": "x"})
        assert "made_up" in str(exc_info.value)

    def test_none_accepted(self):
        from schemas.service_providers import SPUpdate

        u = SPUpdate(attribute_mapping=None)
        assert u.attribute_mapping is None

    def test_allowed_keys_equal_fixed_union_registry(self):
        """Fix 4: validator's allowed-key set is exactly the consolidated
        FIXED_SP_ATTRIBUTE_KEYS ∪ ATTRIBUTE_KEYS. No drift between the
        constant module and the schema validator."""
        from constants.user_attributes import (
            ATTRIBUTE_KEYS,
            FIXED_SP_ATTRIBUTE_KEYS,
        )
        from pydantic import ValidationError as PydanticValidationError
        from schemas.service_providers import SPUpdate

        expected_allowed = FIXED_SP_ATTRIBUTE_KEYS | ATTRIBUTE_KEYS
        # Every allowed key must pass validation.
        u = SPUpdate(attribute_mapping={k: "x" for k in expected_allowed})
        assert u.attribute_mapping is not None
        assert set(u.attribute_mapping.keys()) == expected_allowed
        # Anything outside that union must fail.
        with pytest.raises(PydanticValidationError):
            SPUpdate(attribute_mapping={"definitely_not_an_attr": "x"})


# ============================================================================
# Manual create_service_provider seeds attribute_mapping
# ============================================================================


class TestCreateServiceProviderSeedsMapping:
    @patch("services.service_providers.crud._get_or_create_sp_signing_certificate")
    @patch("services.service_providers.crud.log_event")
    @patch("services.service_providers.crud.database")
    def test_manual_create_passes_seeded_mapping(self, mock_db, _mock_log, _mock_cert):
        """Manual SP creation seeds attribute_mapping from tenant config."""
        from schemas.service_providers import SPCreate
        from services.service_providers.crud import create_service_provider

        mock_db.tenant_attribute_config.list_config.return_value = [
            {
                "attribute_key": "job_title",
                "enabled": True,
                "send_to_sps_default": True,
            },
        ]
        mock_db.service_providers.create_service_provider.return_value = {
            "id": "sp-1",
            "name": "Test",
            "entity_id": None,
            "acs_url": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "include_group_claims": False,
            "trust_established": False,
            "available_to_all": False,
            "enabled": True,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }

        create_service_provider(
            requesting_user={"id": "u1", "tenant_id": "t1", "role": "super_admin"},
            data=SPCreate(name="Test"),
        )

        kwargs = mock_db.service_providers.create_service_provider.call_args.kwargs
        mapping = kwargs.get("attribute_mapping")
        assert mapping is not None
        # Fixed defaults preserved
        assert mapping["email"] == "email"
        assert mapping["firstName"] == "firstName"
        # Seeded standard attribute included
        assert mapping["job_title"] == "jobTitle"

    @patch("services.service_providers.crud._get_or_create_sp_signing_certificate")
    @patch("services.service_providers.crud.log_event")
    @patch("services.service_providers.crud.database")
    def test_manual_create_omits_unseeded_keys(self, mock_db, _mock_log, _mock_cert):
        """Standard attrs that are disabled or opt-out are NOT in the seeded mapping."""
        from schemas.service_providers import SPCreate
        from services.service_providers.crud import create_service_provider

        mock_db.tenant_attribute_config.list_config.return_value = [
            {
                "attribute_key": "job_title",
                "enabled": True,
                "send_to_sps_default": False,
            },
            {
                "attribute_key": "department",
                "enabled": False,
                "send_to_sps_default": True,
            },
        ]
        mock_db.service_providers.create_service_provider.return_value = {
            "id": "sp-1",
            "name": "Test",
            "entity_id": None,
            "acs_url": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "include_group_claims": False,
            "trust_established": False,
            "available_to_all": False,
            "enabled": True,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }

        create_service_provider(
            requesting_user={"id": "u1", "tenant_id": "t1", "role": "super_admin"},
            data=SPCreate(name="Test"),
        )

        kwargs = mock_db.service_providers.create_service_provider.call_args.kwargs
        mapping = kwargs.get("attribute_mapping") or {}
        assert "job_title" not in mapping
        assert "department" not in mapping


# ============================================================================
# XML import path: auto-detected OID wins over seeded default
# ============================================================================


class TestImportSPMetadataAttributeMapping:
    """When SP metadata declares its expected attribute URIs and the tenant
    also seeds defaults, the auto-detected URI from the SP wins (so federation
    SPs that ask for OIDs get OIDs, not the friendly-name fallback)."""

    @patch("services.service_providers.crud._get_or_create_sp_signing_certificate")
    @patch("services.service_providers.crud.log_event")
    @patch("services.service_providers.crud.database")
    @patch("utils.saml_idp.parse_sp_metadata_xml")
    def test_auto_detected_oid_overrides_seeded_friendly_name(
        self, mock_parse, mock_db, _mock_log, _mock_cert
    ):
        """SP requests urn:oid:0.9.2342.19200300.100.1.3 for email AND tenant
        config seeds email -> 'email'. The OID wins so the SP gets what it
        asked for."""
        from services.service_providers.crud import import_sp_from_metadata_xml

        # Tenant config seeds the fixed defaults (email -> "email" comes from
        # FIXED_SP_DEFAULTS); no extra registry attrs needed for this test.
        mock_db.tenant_attribute_config.list_config.return_value = []
        mock_db.service_providers.get_service_provider_by_entity_id.return_value = None
        mock_db.service_providers.create_service_provider.return_value = {
            "id": "sp-1",
            "name": "Test",
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "include_group_claims": False,
            "trust_established": True,
            "available_to_all": False,
            "enabled": True,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        mock_parse.return_value = {
            "entity_id": "https://sp.example.com",
            "acs_url": "https://sp.example.com/acs",
            "certificate_pem": None,
            "encryption_certificate_pem": None,
            "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "slo_url": None,
            "requested_attributes": [
                {
                    "name": "urn:oid:0.9.2342.19200300.100.1.3",
                    "friendly_name": "mail",
                    "is_required": True,
                },
            ],
        }

        import_sp_from_metadata_xml(
            requesting_user={"id": "u1", "tenant_id": "t1", "role": "super_admin"},
            name="Test SP",
            metadata_xml="<EntityDescriptor/>",
        )

        kwargs = mock_db.service_providers.create_service_provider.call_args.kwargs
        mapping = kwargs.get("attribute_mapping") or {}
        # Auto-detected OID wins over the seeded "email" friendly name.
        assert mapping["email"] == "urn:oid:0.9.2342.19200300.100.1.3"
