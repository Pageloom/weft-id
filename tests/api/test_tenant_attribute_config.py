"""Tests for the /api/v1/tenant/attribute-config API endpoints."""

from __future__ import annotations

import pytest
from constants.user_attributes import ATTRIBUTE_KEYS, STANDARD_ATTRIBUTES
from services.settings.attributes import seed_tenant_attribute_config


@pytest.fixture
def seeded_tenant(test_tenant):
    """Seed the 14-row attribute config for the test tenant."""
    seed_tenant_attribute_config(str(test_tenant["id"]))
    return test_tenant


# ---------------------------------------------------------------------------
# GET /api/v1/tenant/attribute-config
# ---------------------------------------------------------------------------


def test_list_attribute_config_as_super_admin(
    client, test_tenant_host, seeded_tenant, oauth2_super_admin_authorization_header
):
    """Super admin can list the tenant's attribute configuration."""
    response = client.get(
        "/api/v1/tenant/attribute-config",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
    )

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == len(STANDARD_ATTRIBUTES)
    keys = {row["attribute_key"] for row in data}
    assert keys == ATTRIBUTE_KEYS
    for row in data:
        # Schema shape contract.
        assert {
            "attribute_key",
            "category",
            "enabled",
            "required",
            "mirror_from_idp",
            "locked_for_users",
            "send_to_sps_default",
            "updated_at",
        } <= set(row.keys())
        # Default seed values.
        assert row["enabled"] is False
        assert row["required"] is False
        assert row["mirror_from_idp"] is True
        assert row["locked_for_users"] is False
        assert row["send_to_sps_default"] is True


def test_list_attribute_config_as_admin_forbidden(
    client, test_tenant_host, seeded_tenant, oauth2_admin_authorization_header
):
    """Admin (non-super) cannot list attribute configuration."""
    response = client.get(
        "/api/v1/tenant/attribute-config",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
    )

    assert response.status_code == 403


def test_list_attribute_config_as_member_forbidden(
    client, test_tenant_host, seeded_tenant, oauth2_authorization_header
):
    """Regular members cannot list attribute configuration."""
    response = client.get(
        "/api/v1/tenant/attribute-config",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
    )

    assert response.status_code == 403


def test_list_attribute_config_unauthenticated(client, test_tenant_host):
    """Unauthenticated requests return 401."""
    response = client.get(
        "/api/v1/tenant/attribute-config",
        headers={"Host": test_tenant_host},
    )

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# PUT /api/v1/tenant/attribute-config/{attribute_key}
# ---------------------------------------------------------------------------


def test_update_attribute_config_as_super_admin(
    client, test_tenant_host, seeded_tenant, oauth2_super_admin_authorization_header
):
    """Super admin can update one attribute's flags."""
    response = client.put(
        "/api/v1/tenant/attribute-config/job_title",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={
            "enabled": True,
            "required": True,
            "mirror_from_idp": True,
            "locked_for_users": False,
            "send_to_sps_default": False,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["attribute_key"] == "job_title"
    assert data["enabled"] is True
    assert data["required"] is True
    assert data["mirror_from_idp"] is True
    assert data["locked_for_users"] is False
    assert data["send_to_sps_default"] is False


def test_update_attribute_config_as_admin_forbidden(
    client, test_tenant_host, seeded_tenant, oauth2_admin_authorization_header
):
    """Admin (non-super) cannot update attribute config."""
    response = client.put(
        "/api/v1/tenant/attribute-config/job_title",
        headers={"Host": test_tenant_host, **oauth2_admin_authorization_header},
        json={
            "enabled": True,
            "required": False,
            "mirror_from_idp": False,
            "locked_for_users": False,
            "send_to_sps_default": True,
        },
    )

    assert response.status_code == 403


def test_update_attribute_config_as_member_forbidden(
    client, test_tenant_host, seeded_tenant, oauth2_authorization_header
):
    """Regular members cannot update attribute config."""
    response = client.put(
        "/api/v1/tenant/attribute-config/job_title",
        headers={"Host": test_tenant_host, **oauth2_authorization_header},
        json={
            "enabled": True,
            "required": False,
            "mirror_from_idp": False,
            "locked_for_users": False,
            "send_to_sps_default": True,
        },
    )

    assert response.status_code == 403


def test_update_attribute_config_unauthenticated(client, test_tenant_host, seeded_tenant):
    """Unauthenticated requests return 401."""
    response = client.put(
        "/api/v1/tenant/attribute-config/job_title",
        headers={"Host": test_tenant_host},
        json={
            "enabled": True,
            "required": False,
            "mirror_from_idp": False,
            "locked_for_users": False,
            "send_to_sps_default": True,
        },
    )

    assert response.status_code == 401


def test_update_attribute_config_unknown_key_returns_400(
    client, test_tenant_host, seeded_tenant, oauth2_super_admin_authorization_header
):
    """Unknown attribute keys return a 400 ValidationError."""
    response = client.put(
        "/api/v1/tenant/attribute-config/no_such_key",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={
            "enabled": True,
            "required": False,
            "mirror_from_idp": False,
            "locked_for_users": False,
            "send_to_sps_default": True,
        },
    )

    assert response.status_code == 400


def test_update_attribute_config_missing_fields_returns_422(
    client, test_tenant_host, seeded_tenant, oauth2_super_admin_authorization_header
):
    """Pydantic rejects partial updates: all five flags are required."""
    response = client.put(
        "/api/v1/tenant/attribute-config/job_title",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={"enabled": True},
    )

    assert response.status_code == 422


def test_update_attribute_config_missing_seed_returns_404(
    client, test_tenant_host, test_tenant, oauth2_super_admin_authorization_header
):
    """Tenants whose config rows have not been seeded surface a 404."""
    # Note: do NOT seed. The tenant exists but has no config rows.
    response = client.put(
        "/api/v1/tenant/attribute-config/job_title",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={
            "enabled": True,
            "required": False,
            "mirror_from_idp": False,
            "locked_for_users": False,
            "send_to_sps_default": True,
        },
    )

    assert response.status_code == 404


def test_update_attribute_config_persists_across_requests(
    client, test_tenant_host, seeded_tenant, oauth2_super_admin_authorization_header
):
    """A PUT followed by GET reflects the saved flags."""
    put_resp = client.put(
        "/api/v1/tenant/attribute-config/department",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
        json={
            "enabled": True,
            "required": True,
            "mirror_from_idp": True,
            "locked_for_users": True,
            "send_to_sps_default": True,
        },
    )
    assert put_resp.status_code == 200

    list_resp = client.get(
        "/api/v1/tenant/attribute-config",
        headers={"Host": test_tenant_host, **oauth2_super_admin_authorization_header},
    )
    assert list_resp.status_code == 200
    rows = {r["attribute_key"]: r for r in list_resp.json()}
    assert rows["department"]["enabled"] is True
    assert rows["department"]["required"] is True
    assert rows["department"]["mirror_from_idp"] is True
    assert rows["department"]["locked_for_users"] is True
    assert rows["department"]["send_to_sps_default"] is True
