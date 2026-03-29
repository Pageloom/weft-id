"""Tests for compute_email_change_impact() service function.

Tests the SP assertion impact classification and IdP routing change
detection when a user's primary email would change.
"""

from constants.nameid_formats import (
    NAMEID_FORMAT_EMAIL,
    NAMEID_FORMAT_PERSISTENT,
    NAMEID_FORMAT_TRANSIENT,
    NAMEID_FORMAT_UNSPECIFIED,
)
from services import emails as emails_service

# =============================================================================
# compute_email_change_impact
# =============================================================================


def test_no_accessible_sps(test_tenant, test_user, mocker):
    """Impact with no accessible SPs returns empty list and no routing change."""
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[],
    )
    mocker.patch(
        "services.emails.check_routing_change",
        return_value=None,
    )

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@example.com"
    )

    assert result["sp_impacts"] == []
    assert result["routing_change"] is None
    assert result["summary"]["total_sp_count"] == 0
    assert result["summary"]["affected_sp_count"] == 0
    assert result["summary"]["unaffected_sp_count"] == 0


def test_email_format_sp_will_change(test_tenant, test_user, mocker):
    """SP with emailAddress NameID format is classified as will_change."""
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[
            {
                "id": "sp-1",
                "name": "Slack",
                "entity_id": "https://slack.com",
                "nameid_format": NAMEID_FORMAT_EMAIL,
            },
        ],
    )
    mocker.patch("services.emails.check_routing_change", return_value=None)

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@example.com"
    )

    assert len(result["sp_impacts"]) == 1
    sp = result["sp_impacts"][0]
    assert sp["sp_name"] == "Slack"
    assert sp["nameid_format_label"] == "emailAddress"
    assert sp["impact"] == "will_change"
    assert result["summary"]["affected_sp_count"] == 1
    assert result["summary"]["unaffected_sp_count"] == 0


def test_unspecified_format_sp_will_change(test_tenant, test_user, mocker):
    """SP with unspecified NameID format is classified as will_change."""
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[
            {
                "id": "sp-1",
                "name": "Jira",
                "entity_id": "https://jira.example.com",
                "nameid_format": NAMEID_FORMAT_UNSPECIFIED,
            },
        ],
    )
    mocker.patch("services.emails.check_routing_change", return_value=None)

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@example.com"
    )

    assert result["sp_impacts"][0]["impact"] == "will_change"
    assert result["sp_impacts"][0]["nameid_format_label"] == "unspecified"
    assert result["summary"]["affected_sp_count"] == 1


def test_persistent_format_not_affected(test_tenant, test_user, mocker):
    """SP with persistent NameID format is classified as not_affected."""
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[
            {
                "id": "sp-1",
                "name": "GitHub",
                "entity_id": "https://github.com",
                "nameid_format": NAMEID_FORMAT_PERSISTENT,
            },
        ],
    )
    mocker.patch("services.emails.check_routing_change", return_value=None)

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@example.com"
    )

    assert result["sp_impacts"][0]["impact"] == "not_affected"
    assert result["sp_impacts"][0]["nameid_format_label"] == "persistent"
    assert result["summary"]["affected_sp_count"] == 0
    assert result["summary"]["unaffected_sp_count"] == 1


def test_transient_format_not_affected(test_tenant, test_user, mocker):
    """SP with transient NameID format is classified as not_affected."""
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[
            {
                "id": "sp-1",
                "name": "Analytics",
                "entity_id": "https://analytics.example.com",
                "nameid_format": NAMEID_FORMAT_TRANSIENT,
            },
        ],
    )
    mocker.patch("services.emails.check_routing_change", return_value=None)

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@example.com"
    )

    assert result["sp_impacts"][0]["impact"] == "not_affected"
    assert result["sp_impacts"][0]["nameid_format_label"] == "transient"


def test_mixed_formats(test_tenant, test_user, mocker):
    """Mixed NameID formats are correctly classified."""
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[
            {
                "id": "sp-1",
                "name": "Slack",
                "entity_id": "e1",
                "nameid_format": NAMEID_FORMAT_EMAIL,
            },
            {
                "id": "sp-2",
                "name": "GitHub",
                "entity_id": "e2",
                "nameid_format": NAMEID_FORMAT_PERSISTENT,
            },
            {
                "id": "sp-3",
                "name": "Jira",
                "entity_id": "e3",
                "nameid_format": NAMEID_FORMAT_UNSPECIFIED,
            },
            {
                "id": "sp-4",
                "name": "Analytics",
                "entity_id": "e4",
                "nameid_format": NAMEID_FORMAT_TRANSIENT,
            },
        ],
    )
    mocker.patch("services.emails.check_routing_change", return_value=None)

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@example.com"
    )

    assert len(result["sp_impacts"]) == 4
    assert result["summary"]["affected_sp_count"] == 2
    assert result["summary"]["unaffected_sp_count"] == 2
    assert result["summary"]["total_sp_count"] == 4

    impacts_by_name = {sp["sp_name"]: sp["impact"] for sp in result["sp_impacts"]}
    assert impacts_by_name["Slack"] == "will_change"
    assert impacts_by_name["GitHub"] == "not_affected"
    assert impacts_by_name["Jira"] == "will_change"
    assert impacts_by_name["Analytics"] == "not_affected"


def test_routing_change_included(test_tenant, test_user, mocker):
    """IdP routing change from check_routing_change is included in result."""
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[],
    )
    routing_info = {"current_idp_name": "Okta", "new_idp_name": "Google Workspace"}
    mocker.patch("services.emails.check_routing_change", return_value=routing_info)

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@google.com"
    )

    assert result["routing_change"] == routing_info
    assert result["routing_change"]["current_idp_name"] == "Okta"
    assert result["routing_change"]["new_idp_name"] == "Google Workspace"


def test_no_routing_change(test_tenant, test_user, mocker):
    """No routing change when domain IdP matches current."""
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[],
    )
    mocker.patch("services.emails.check_routing_change", return_value=None)

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@same-domain.com"
    )

    assert result["routing_change"] is None


def test_sp_id_is_string(test_tenant, test_user, mocker):
    """SP ID in results is always a string (UUID handling)."""
    import uuid

    sp_uuid = uuid.uuid4()
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[
            {"id": sp_uuid, "name": "App", "entity_id": "e1", "nameid_format": NAMEID_FORMAT_EMAIL},
        ],
    )
    mocker.patch("services.emails.check_routing_change", return_value=None)

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@example.com"
    )

    assert result["sp_impacts"][0]["sp_id"] == str(sp_uuid)


def test_unknown_nameid_format_treated_as_affected(test_tenant, test_user, mocker):
    """Unknown or empty NameID format is treated as will_change (safe default)."""
    mocker.patch(
        "services.emails.database.sp_group_assignments.get_accessible_sps_with_nameid_for_user",
        return_value=[
            {"id": "sp-1", "name": "Legacy App", "entity_id": "e1", "nameid_format": ""},
        ],
    )
    mocker.patch("services.emails.check_routing_change", return_value=None)

    result = emails_service.compute_email_change_impact(
        test_tenant["id"], str(test_user["id"]), "new@example.com"
    )

    assert result["sp_impacts"][0]["impact"] == "will_change"
    assert result["sp_impacts"][0]["nameid_format_label"] == "unknown"
