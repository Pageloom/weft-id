"""Tests for the Iteration 7 admin API endpoints under ``/api/v1/users``.

* ``GET /api/v1/users/incomplete-profiles``
* ``POST /api/v1/users/force-profile-completion``
"""

from __future__ import annotations

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


def test_incomplete_profiles_api_returns_rows(test_admin_user, test_user, override_api_auth):
    _seed_required(test_user["tenant_id"], "job_title")
    _seed_required(test_user["tenant_id"], "department", locked=True)
    override_api_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.get("/api/v1/users/incomplete-profiles")
    assert response.status_code == 200
    payload = response.json()
    user_rows = [row for row in payload if row["user_id"] == str(test_user["id"])]
    assert {row["attribute_key"] for row in user_rows} == {"job_title", "department"}
    locked_lookup = {row["attribute_key"]: row["locked"] for row in user_rows}
    assert locked_lookup == {"job_title": False, "department": True}


def test_incomplete_profiles_api_excludes_users_with_full_required(
    test_admin_user, test_user, override_api_auth
):
    _seed_required(test_user["tenant_id"], "job_title")
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    override_api_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.get("/api/v1/users/incomplete-profiles")
    assert response.status_code == 200
    user_ids = [row["user_id"] for row in response.json()]
    assert str(test_user["id"]) not in user_ids


def test_incomplete_profiles_api_requires_admin(test_user, override_api_auth):
    override_api_auth(test_user, level="user")
    client = TestClient(app)
    response = client.get("/api/v1/users/incomplete-profiles")
    # require_admin_api enforces the role; the exact status depends on the
    # platform's auth helper but it must not be 200 with the data.
    assert response.status_code in (401, 403)


def test_force_profile_completion_api_flags_user(test_admin_user, test_user, override_api_auth):
    _seed_required(test_user["tenant_id"], "job_title")
    override_api_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.post(
        "/api/v1/users/force-profile-completion",
        json={"user_ids": [str(test_user["id"])]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["flagged"] == [str(test_user["id"])]
    assert body["skipped_locked"] == []
    assert body["skipped_complete"] == []
    refreshed = database.users.get_user_by_id(test_user["tenant_id"], test_user["id"])
    assert refreshed["force_profile_completion"] is True


def test_force_profile_completion_api_skips_locked_only(
    test_admin_user, test_user, override_api_auth
):
    _seed_required(test_user["tenant_id"], "job_title", locked=True)
    override_api_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.post(
        "/api/v1/users/force-profile-completion",
        json={"user_ids": [str(test_user["id"])]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["flagged"] == []
    assert body["skipped_locked"] == [str(test_user["id"])]


def test_force_profile_completion_api_skips_complete_users(
    test_admin_user, test_user, override_api_auth
):
    _seed_required(test_user["tenant_id"], "job_title")
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    override_api_auth(test_admin_user, level="admin")
    client = TestClient(app)
    response = client.post(
        "/api/v1/users/force-profile-completion",
        json={"user_ids": [str(test_user["id"])]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["skipped_complete"] == [str(test_user["id"])]


def test_force_profile_completion_api_requires_admin(test_user, override_api_auth):
    override_api_auth(test_user, level="user")
    client = TestClient(app)
    response = client.post(
        "/api/v1/users/force-profile-completion",
        json={"user_ids": [str(test_user["id"])]},
    )
    assert response.status_code in (401, 403)
