"""Tests for the user attribute API endpoints (canonical + IdP-mirror).

Covers all 7 endpoints:
* GET    /api/v1/users/{user_id}/attributes
* PUT    /api/v1/users/{user_id}/attributes/{key}
* DELETE /api/v1/users/{user_id}/attributes/{key}
* GET    /api/v1/users/{user_id}/idp-attributes  (admin only)
* GET    /api/v1/me/attributes
* PUT    /api/v1/me/attributes/{key}
* DELETE /api/v1/me/attributes/{key}
"""

from __future__ import annotations

import pytest
from services.settings.attributes import (
    seed_tenant_attribute_config,
    update_tenant_attribute_config,
)


@pytest.fixture
def seeded_tenant(test_tenant):
    """Seed the 14-row attribute config for the test tenant."""
    seed_tenant_attribute_config(str(test_tenant["id"]))
    return test_tenant


@pytest.fixture
def super_admin_requesting_user(test_super_admin_user):
    """Build a RequestingUser dict from a super admin fixture."""
    return {
        "id": str(test_super_admin_user["id"]),
        "tenant_id": str(test_super_admin_user["tenant_id"]),
        "role": "super_admin",
        "email": test_super_admin_user["email"],
    }


def _enable_attribute(
    super_admin_requesting_user,
    attribute_key: str,
    *,
    locked: bool = False,
    required: bool = False,
):
    """Enable one attribute on the seeded tenant for write tests."""
    update_tenant_attribute_config(
        super_admin_requesting_user,
        attribute_key,
        enabled=True,
        required=required,
        mirror_from_idp=True,
        locked_for_users=locked,
        send_to_sps_default=True,
    )


# ---------------------------------------------------------------------------
# /api/v1/me/attributes (self-service)
# ---------------------------------------------------------------------------


def test_list_my_attributes_empty(
    client, test_tenant_host, seeded_tenant, oauth2_authorization_header
):
    """GET /me/attributes returns [] when no attributes are set."""
    response = client.get(
        "/api/v1/me/attributes",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 200
    assert response.json() == []


def test_list_my_attributes_unauthenticated(client, test_tenant_host, seeded_tenant):
    """Unauthenticated GET returns 401."""
    response = client.get(
        "/api/v1/me/attributes",
        headers={"Host": test_tenant_host},
    )
    assert response.status_code == 401


def test_set_my_attribute_member_writes_own(
    client,
    test_tenant_host,
    seeded_tenant,
    oauth2_authorization_header,
    super_admin_requesting_user,
):
    """Member can write their own non-locked attribute."""
    _enable_attribute(super_admin_requesting_user, "job_title")

    response = client.put(
        "/api/v1/me/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"value": "Engineer"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["attribute_key"] == "job_title"
    assert body["value"] == "Engineer"


def test_set_my_attribute_locked_returns_403_with_code(
    client,
    test_tenant_host,
    seeded_tenant,
    oauth2_authorization_header,
    super_admin_requesting_user,
):
    """Self-edit on a locked attribute returns 403 with error_code=attribute_locked."""
    _enable_attribute(super_admin_requesting_user, "job_title", locked=True)

    response = client.put(
        "/api/v1/me/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"value": "Engineer"},
    )
    assert response.status_code == 403
    body = response.json()
    # FastAPI wraps our structured detail under "detail".
    detail = body.get("detail")
    assert isinstance(detail, dict)
    assert detail.get("error_code") == "attribute_locked"


def test_set_my_attribute_unknown_key_returns_400(
    client,
    test_tenant_host,
    seeded_tenant,
    oauth2_authorization_header,
):
    """Unknown attribute key returns 400 (ValidationError)."""
    response = client.put(
        "/api/v1/me/attributes/no_such_key",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"value": "x"},
    )
    assert response.status_code == 400


def test_set_my_attribute_disabled_returns_400(
    client,
    test_tenant_host,
    seeded_tenant,
    oauth2_authorization_header,
):
    """Writing a known but not-enabled attribute returns 400 attribute_not_enabled."""
    response = client.put(
        "/api/v1/me/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"value": "Engineer"},
    )
    assert response.status_code == 400


def test_clear_my_attribute(
    client,
    test_tenant_host,
    seeded_tenant,
    oauth2_authorization_header,
    super_admin_requesting_user,
):
    """DELETE /me/attributes/{key} returns 204."""
    _enable_attribute(super_admin_requesting_user, "job_title")

    client.put(
        "/api/v1/me/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"value": "Engineer"},
    )
    response = client.delete(
        "/api/v1/me/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 204


def test_clear_my_attribute_locked_returns_403(
    client,
    test_tenant_host,
    seeded_tenant,
    oauth2_authorization_header,
    super_admin_requesting_user,
):
    """Self-clear on a locked attribute is forbidden."""
    _enable_attribute(super_admin_requesting_user, "job_title", locked=True)

    response = client.delete(
        "/api/v1/me/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 403


def test_set_my_attribute_blocked_when_profile_editing_disabled(
    client,
    test_tenant_host,
    seeded_tenant,
    oauth2_authorization_header,
    super_admin_requesting_user,
    mocker,
):
    """When tenant security disables self-edit, member writes are forbidden."""
    _enable_attribute(super_admin_requesting_user, "job_title")
    mocker.patch(
        "services.users.attributes.can_user_edit_profile",
        return_value=False,
    )

    response = client.put(
        "/api/v1/me/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={"value": "Engineer"},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# /api/v1/users/{user_id}/attributes (admin/cross-user)
# ---------------------------------------------------------------------------


def test_list_user_attributes_admin_can_read_other(
    client, test_tenant_host, seeded_tenant, test_user, oauth2_admin_authorization_header
):
    """Admin can read another user's attribute list."""
    response = client.get(
        f"/api/v1/users/{test_user['id']}/attributes",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 200
    assert response.json() == []


def test_list_user_attributes_member_blocked_on_other(
    client, test_tenant_host, seeded_tenant, test_admin_user, oauth2_authorization_header
):
    """Member cannot read another user's attribute list."""
    response = client.get(
        f"/api/v1/users/{test_admin_user['id']}/attributes",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 403


def test_set_user_attribute_admin_can_edit_locked(
    client,
    test_tenant_host,
    seeded_tenant,
    test_user,
    oauth2_admin_authorization_header,
    super_admin_requesting_user,
):
    """Admin can edit a locked attribute on another user."""
    _enable_attribute(super_admin_requesting_user, "job_title", locked=True)

    response = client.put(
        f"/api/v1/users/{test_user['id']}/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"value": "Director"},
    )
    assert response.status_code == 200
    assert response.json()["value"] == "Director"


def test_set_user_attribute_admin_works_when_self_edit_disabled(
    client,
    test_tenant_host,
    seeded_tenant,
    test_user,
    oauth2_admin_authorization_header,
    super_admin_requesting_user,
    mocker,
):
    """Admin writes still work even when allow_users_edit_profile=false."""
    _enable_attribute(super_admin_requesting_user, "job_title")
    mocker.patch(
        "services.users.attributes.can_user_edit_profile",
        return_value=False,
    )

    response = client.put(
        f"/api/v1/users/{test_user['id']}/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"value": "Lead"},
    )
    assert response.status_code == 200


def test_clear_user_attribute_admin_works(
    client,
    test_tenant_host,
    seeded_tenant,
    test_user,
    oauth2_admin_authorization_header,
    super_admin_requesting_user,
):
    """Admin DELETE returns 204."""
    _enable_attribute(super_admin_requesting_user, "job_title")
    client.put(
        f"/api/v1/users/{test_user['id']}/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={"value": "Engineer"},
    )
    response = client.delete(
        f"/api/v1/users/{test_user['id']}/attributes/job_title",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 204


# ---------------------------------------------------------------------------
# /api/v1/users/{user_id}/idp-attributes  (admin only)
# ---------------------------------------------------------------------------


def test_list_idp_attributes_admin_empty(
    client, test_tenant_host, seeded_tenant, test_user, oauth2_admin_authorization_header
):
    """Admin GET /idp-attributes returns [] when no IdP rows exist."""
    response = client.get(
        f"/api/v1/users/{test_user['id']}/idp-attributes",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )
    assert response.status_code == 200
    assert response.json() == []


def test_list_idp_attributes_member_forbidden(
    client, test_tenant_host, seeded_tenant, test_user, oauth2_authorization_header
):
    """Members cannot access /idp-attributes (admin only)."""
    response = client.get(
        f"/api/v1/users/{test_user['id']}/idp-attributes",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )
    assert response.status_code == 403
