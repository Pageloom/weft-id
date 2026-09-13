"""Tests for OIDC upstream group claim handling (services.oidc_upstream.groups).

Covers the claim parser (value shapes, absent vs empty, hygiene), overage
detection, and the sync orchestration (base group always, claim sync only
when configured and present).
"""

from unittest.mock import patch

import pytest
from services.oidc_upstream import groups as mod

CONNECTION = {
    "id": "11111111-1111-1111-1111-111111111111",
    "name": "Acme OIDC",
    "group_claim_source": "groups",
    "group_claim_name_key": None,
}


# ---------------------------------------------------------------------------
# extract_group_names
# ---------------------------------------------------------------------------


class TestExtractGroupNames:
    def test_absent_claim_returns_none(self):
        assert mod.extract_group_names({"sub": "x"}, "groups") is None

    def test_empty_claim_name_returns_none(self):
        assert mod.extract_group_names({"groups": ["a"]}, "") is None

    def test_null_claim_returns_none(self):
        assert mod.extract_group_names({"groups": None}, "groups") is None

    def test_empty_list_is_empty_not_none(self):
        assert mod.extract_group_names({"groups": []}, "groups") == []

    def test_list_of_strings(self):
        claims = {"groups": ["admins", "engineering"]}
        assert mod.extract_group_names(claims, "groups") == ["admins", "engineering"]

    def test_bare_string_is_one_group(self):
        assert mod.extract_group_names({"groups": "admins"}, "groups") == ["admins"]

    def test_strips_dedupes_and_drops_empty(self):
        claims = {"groups": [" admins ", "admins", "", "   ", "ops"]}
        assert mod.extract_group_names(claims, "groups") == ["admins", "ops"]

    def test_list_of_objects_default_name_key(self):
        claims = {"groups": [{"id": "1", "name": "admins"}, {"id": "2", "name": "ops"}]}
        assert mod.extract_group_names(claims, "groups") == ["admins", "ops"]

    def test_list_of_objects_custom_name_key(self):
        claims = {"groups": [{"id": "1", "displayName": "Admins"}]}
        assert mod.extract_group_names(claims, "groups", "displayName") == ["Admins"]

    def test_blank_name_key_falls_back_to_default(self):
        claims = {"groups": [{"name": "admins"}]}
        assert mod.extract_group_names(claims, "groups", "   ") == ["admins"]

    def test_object_missing_key_is_skipped(self):
        claims = {"groups": [{"id": "1"}, {"name": "ops"}]}
        assert mod.extract_group_names(claims, "groups") == ["ops"]

    def test_integers_are_coerced_but_bools_skipped(self):
        claims = {"groups": [42, True, False, "ops"]}
        assert mod.extract_group_names(claims, "groups") == ["42", "ops"]

    def test_non_string_entries_skipped(self):
        claims = {"groups": [None, 1.5, ["nested"], "ops"]}
        assert mod.extract_group_names(claims, "groups") == ["ops"]

    def test_over_long_names_dropped(self):
        long_name = "x" * (mod.MAX_GROUP_NAME_LENGTH + 1)
        exact = "y" * mod.MAX_GROUP_NAME_LENGTH
        claims = {"groups": [long_name, exact]}
        assert mod.extract_group_names(claims, "groups") == [exact]

    def test_unsupported_shape_returns_none(self):
        assert mod.extract_group_names({"groups": {"a": 1}}, "groups") is None
        assert mod.extract_group_names({"groups": 7}, "groups") is None

    def test_namespaced_claim_name(self):
        claims = {"https://example.com/groups": ["a"]}
        assert mod.extract_group_names(claims, "https://example.com/groups") == ["a"]

    def test_caps_group_count(self):
        claims = {"groups": [f"g{i}" for i in range(mod.MAX_GROUPS_PER_SIGN_IN + 25)]}
        names = mod.extract_group_names(claims, "groups")
        assert names is not None
        assert len(names) == mod.MAX_GROUPS_PER_SIGN_IN
        assert names[0] == "g0"

    def test_entra_guids_used_verbatim(self):
        guid = "6a2a1f2e-8f1e-4a4d-9c3b-2f8a1d0e5b77"
        assert mod.extract_group_names({"groups": [guid]}, "groups") == [guid]


# ---------------------------------------------------------------------------
# has_group_claim_overage
# ---------------------------------------------------------------------------


class TestOverage:
    def test_detects_entra_overage_marker(self):
        claims = {"_claim_names": {"groups": "src1"}, "_claim_sources": {"src1": {}}}
        assert mod.has_group_claim_overage(claims, "groups") is True

    def test_marker_for_other_claim_is_not_overage(self):
        claims = {"_claim_names": {"roles": "src1"}}
        assert mod.has_group_claim_overage(claims, "groups") is False

    def test_no_marker(self):
        assert mod.has_group_claim_overage({"groups": []}, "groups") is False

    def test_non_dict_marker_ignored(self):
        assert mod.has_group_claim_overage({"_claim_names": "groups"}, "groups") is False


# ---------------------------------------------------------------------------
# sync_groups_from_claims
# ---------------------------------------------------------------------------


@pytest.fixture
def mocks():
    with (
        patch("services.oidc_upstream.groups.groups_service") as groups_service,
        patch("services.oidc_upstream.groups.log_event") as log_event,
    ):
        groups_service.sync_user_idp_groups.return_value = {
            "added": ["a"],
            "removed": [],
            "created": ["a"],
        }
        yield groups_service, log_event


class TestSyncGroupsFromClaims:
    def test_always_ensures_base_group_membership(self, mocks):
        groups_service, _ = mocks
        conn = {**CONNECTION, "group_claim_source": None}

        result = mod.sync_groups_from_claims("t1", "u1", "u@example.com", conn, {"sub": "x"})

        assert result is None
        groups_service.ensure_user_in_base_group.assert_called_once_with(
            "t1", "u1", "u@example.com", CONNECTION["id"], "Acme OIDC", source="oidc"
        )
        groups_service.sync_user_idp_groups.assert_not_called()

    def test_blank_claim_source_disables_sync(self, mocks):
        groups_service, _ = mocks
        conn = {**CONNECTION, "group_claim_source": "   "}

        assert mod.sync_groups_from_claims("t1", "u1", "e", conn, {"groups": ["a"]}) is None
        groups_service.sync_user_idp_groups.assert_not_called()

    def test_present_claim_runs_full_sync(self, mocks):
        groups_service, _ = mocks
        claims = {"groups": ["admins", "ops"]}

        result = mod.sync_groups_from_claims("t1", "u1", "u@example.com", CONNECTION, claims)

        assert result == {"added": ["a"], "removed": [], "created": ["a"]}
        groups_service.sync_user_idp_groups.assert_called_once_with(
            tenant_id="t1",
            user_id="u1",
            user_email="u@example.com",
            idp_id=CONNECTION["id"],
            idp_name="Acme OIDC",
            group_names=["admins", "ops"],
            source="oidc",
            sync_source="oidc_authentication",
        )

    def test_empty_list_syncs_to_no_groups(self, mocks):
        groups_service, _ = mocks

        mod.sync_groups_from_claims("t1", "u1", "e", CONNECTION, {"groups": []})

        kwargs = groups_service.sync_user_idp_groups.call_args.kwargs
        assert kwargs["group_names"] == []

    def test_absent_claim_leaves_memberships_alone(self, mocks):
        groups_service, log_event = mocks

        assert mod.sync_groups_from_claims("t1", "u1", "e", CONNECTION, {"sub": "x"}) is None
        groups_service.sync_user_idp_groups.assert_not_called()
        log_event.assert_not_called()

    def test_overage_logs_event_and_skips_sync(self, mocks):
        groups_service, log_event = mocks
        claims = {"_claim_names": {"groups": "src1"}}

        assert mod.sync_groups_from_claims("t1", "u1", "e", CONNECTION, claims) is None

        groups_service.sync_user_idp_groups.assert_not_called()
        log_event.assert_called_once()
        kwargs = log_event.call_args.kwargs
        assert kwargs["event_type"] == "oidc_group_claim_overage"
        assert kwargs["artifact_type"] == "oidc_idp_connection"
        assert kwargs["artifact_id"] == CONNECTION["id"]
        assert kwargs["metadata"]["claim"] == "groups"
        assert kwargs["metadata"]["user_id"] == "u1"

    def test_uses_connection_name_key_for_objects(self, mocks):
        groups_service, _ = mocks
        conn = {**CONNECTION, "group_claim_name_key": "displayName"}
        claims = {"groups": [{"displayName": "Admins"}]}

        mod.sync_groups_from_claims("t1", "u1", "e", conn, claims)

        kwargs = groups_service.sync_user_idp_groups.call_args.kwargs
        assert kwargs["group_names"] == ["Admins"]

    def test_sync_failure_propagates(self, mocks):
        groups_service, _ = mocks
        groups_service.sync_user_idp_groups.side_effect = RuntimeError("db down")

        with pytest.raises(RuntimeError):
            mod.sync_groups_from_claims("t1", "u1", "e", CONNECTION, {"groups": ["a"]})
