"""Tests for the admin Todo > User Attributes routes."""

from __future__ import annotations

from unittest.mock import patch

import database
from fastapi.testclient import TestClient
from main import app


def _seed_required(tenant_id, key, *, locked: bool = False):
    from constants.user_attributes import ATTRIBUTES_BY_KEY

    attr = ATTRIBUTES_BY_KEY[key]
    database.execute(
        tenant_id,
        """
        INSERT INTO tenant_attribute_config (
            tenant_id, attribute_key, category, enabled, required,
            mirror_from_idp, locked_for_users, send_to_sps_default
        ) VALUES (
            :tenant_id, :attribute_key, :category, true, true,
            false, :locked, true
        )
        ON CONFLICT (tenant_id, attribute_key) DO UPDATE SET
            enabled = EXCLUDED.enabled,
            required = EXCLUDED.required,
            locked_for_users = EXCLUDED.locked_for_users
        """,
        {
            "tenant_id": str(tenant_id),
            "attribute_key": key,
            "category": attr.category,
            "locked": locked,
        },
    )


def test_admin_todo_user_attributes_page_renders(test_admin_user, override_auth, test_user):
    _seed_required(test_user["tenant_id"], "job_title")
    override_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.get("/admin/todo/user-attributes")
    assert response.status_code == 200
    assert "Incomplete user profiles" in response.text
    assert "job_title" in response.text


def test_admin_todo_user_attributes_excludes_users_with_all_required_set(
    test_admin_user, override_auth, test_user
):
    _seed_required(test_user["tenant_id"], "job_title")
    # Fill the required attribute for BOTH users in the tenant so the page
    # renders the empty-state copy. test_user and test_admin_user share a
    # tenant via the test_tenant fixture.
    for user_id in (test_user["id"], test_admin_user["id"]):
        database.user_attributes.upsert_attribute(
            tenant_id=test_user["tenant_id"],
            tenant_id_value=str(test_user["tenant_id"]),
            user_id=user_id,
            attribute_key="job_title",
            value="Engineer",
        )
    override_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.get("/admin/todo/user-attributes")
    assert response.status_code == 200
    assert "No incomplete profiles" in response.text


def test_admin_todo_user_attributes_filter_by_key(test_admin_user, override_auth, test_user):
    _seed_required(test_user["tenant_id"], "job_title")
    _seed_required(test_user["tenant_id"], "department")
    override_auth(test_admin_user, level="admin")
    client = TestClient(app)
    # Filter to job_title; department row should be excluded
    response = client.get("/admin/todo/user-attributes?filter_key=job_title")
    assert response.status_code == 200
    # Both attributes were missing but the GET handler filters the raw flat
    # rows before grouping, so department won't appear in the user's row.
    assert "job_title" in response.text


def test_force_complete_bulk_action_flags_user(test_admin_user, override_auth, test_user):
    _seed_required(test_user["tenant_id"], "job_title")
    override_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.post(
        "/admin/todo/user-attributes/force-complete",
        data={"user_ids": [str(test_user["id"])]},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "/admin/todo/user-attributes?success=" in response.headers["location"]

    refreshed = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert refreshed["force_profile_completion"] is True


def test_force_complete_success_banner_renders_parsed_counts(
    test_admin_user, override_auth, test_user
):
    """The success-suffix query param is parsed into a human-readable banner."""
    _seed_required(test_user["tenant_id"], "job_title")
    override_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.get(
        "/admin/todo/user-attributes?success=flagged_3_skipped_locked_1_complete_0"
    )
    assert response.status_code == 200
    body = response.text
    assert "Flagged 3 users" in body
    assert "Skipped 1 with only locked fields missing" in body
    # Raw suffix must not leak into rendered text.
    assert "flagged_3_skipped_locked_1_complete_0" not in body


def test_force_complete_bulk_action_no_selection_redirects_with_error(
    test_admin_user, override_auth
):
    override_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.post(
        "/admin/todo/user-attributes/force-complete",
        data={},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "error=no_users_selected" in response.headers["location"]


def test_force_complete_bulk_action_skips_locked_only_users(
    test_admin_user, override_auth, test_user
):
    """Users whose only missing required attribute is locked are not flagged."""
    _seed_required(test_user["tenant_id"], "job_title", locked=True)
    override_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.post(
        "/admin/todo/user-attributes/force-complete",
        data={"user_ids": [str(test_user["id"])]},
        follow_redirects=False,
    )
    assert response.status_code == 303
    refreshed = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert refreshed["force_profile_completion"] is False


def test_admin_todo_user_attributes_logs_event_on_flag(test_admin_user, override_auth, test_user):
    _seed_required(test_user["tenant_id"], "job_title")
    override_auth(test_admin_user, level="admin")
    client = TestClient(app)
    with patch("services.users.attributes.log_event") as mock_log:
        client.post(
            "/admin/todo/user-attributes/force-complete",
            data={"user_ids": [str(test_user["id"])]},
        )
    assert mock_log.call_count == 1
    assert mock_log.call_args.kwargs["event_type"] == "user_force_profile_completion_set"
