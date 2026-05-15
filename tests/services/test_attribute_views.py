"""Tests for services.users.attribute_views (template view builders).

Covers the three builders that compose tenant attribute config, user
canonical values, and per-IdP snapshots into structures the profile and
admin user-detail templates render directly.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import database
from services.exceptions import ServiceError
from services.types import RequestingUser
from services.users.attribute_views import (
    build_attribute_groups_for_admin,
    build_attribute_groups_for_self,
    build_idp_attribute_panel,
)

# ---------------------------------------------------------------------------
# Helpers (mirrors test_user_attributes_service.py / test_apply_attribute_form_updates.py)
# ---------------------------------------------------------------------------


def _seed_config(
    tenant_id,
    *,
    enabled: bool = True,
    required: bool = False,
    mirror_from_idp: bool = False,
    locked_for_users: bool = False,
    send_to_sps_default: bool = True,
    keys=("job_title", "department", "city"),
):
    from constants.user_attributes import ATTRIBUTES_BY_KEY

    for key in keys:
        attr = ATTRIBUTES_BY_KEY[key]
        database.execute(
            tenant_id,
            """
            INSERT INTO tenant_attribute_config (
                tenant_id, attribute_key, category, enabled, required,
                mirror_from_idp, locked_for_users, send_to_sps_default
            ) VALUES (
                :tenant_id, :attribute_key, :category, :enabled, :required,
                :mirror_from_idp, :locked_for_users, :send_to_sps_default
            )
            ON CONFLICT (tenant_id, attribute_key) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                required = EXCLUDED.required,
                mirror_from_idp = EXCLUDED.mirror_from_idp,
                locked_for_users = EXCLUDED.locked_for_users,
                send_to_sps_default = EXCLUDED.send_to_sps_default
            """,
            {
                "tenant_id": str(tenant_id),
                "attribute_key": key,
                "category": attr.category,
                "enabled": enabled,
                "required": required,
                "mirror_from_idp": mirror_from_idp,
                "locked_for_users": locked_for_users,
                "send_to_sps_default": send_to_sps_default,
            },
        )


def _make_idp(tenant_id, user_id):
    return database.fetchone(
        tenant_id,
        """
        INSERT INTO saml_identity_providers (
            tenant_id, name, provider_type, entity_id, sso_url,
            certificate_pem, sp_entity_id, created_by
        ) VALUES (
            :tenant_id, :name, 'generic', :entity_id,
            'https://idp.example.com/sso', 'cert-placeholder',
            'https://sp.example.com', :created_by
        ) RETURNING id
        """,
        {
            "tenant_id": tenant_id,
            "name": f"IdP {uuid4().hex[:6]}",
            "entity_id": f"https://idp-{uuid4().hex[:8]}.example.com",
            "created_by": user_id,
        },
    )


def _admin_requester(test_user) -> RequestingUser:
    return RequestingUser(
        id=str(test_user["id"]),
        tenant_id=str(test_user["tenant_id"]),
        role="admin",
    )


def _member_requester(test_user) -> RequestingUser:
    return RequestingUser(
        id=str(test_user["id"]),
        tenant_id=str(test_user["tenant_id"]),
        role="member",
    )


# ---------------------------------------------------------------------------
# build_attribute_groups_for_self
# ---------------------------------------------------------------------------


def test_build_self_returns_empty_when_no_config(test_user):
    """No tenant config rows means no attributes are surfaced."""
    requester = _member_requester(test_user)
    assert build_attribute_groups_for_self(requester) == []


def test_build_self_groups_enabled_attributes_by_category(test_user):
    """Enabled attributes are grouped by category with friendly labels."""
    _seed_config(
        test_user["tenant_id"],
        keys=("job_title", "department", "city"),
        locked_for_users=False,
    )
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )

    groups = build_attribute_groups_for_self(_member_requester(test_user))

    keys = {g["key"] for g in groups}
    assert keys == {"professional", "location"}

    by_key = {g["key"]: g for g in groups}
    assert by_key["professional"]["label"] == "Professional"
    prof_items = {a["key"]: a for a in by_key["professional"]["attributes"]}
    assert prof_items["job_title"]["value"] == "Engineer"
    assert prof_items["job_title"]["locked"] is False
    assert prof_items["department"]["value"] == ""


def test_build_self_skips_disabled_attributes(test_user):
    """Disabled attributes never appear on the self profile."""
    _seed_config(test_user["tenant_id"], keys=("job_title",), enabled=False)
    _seed_config(test_user["tenant_id"], keys=("city",), enabled=True)

    groups = build_attribute_groups_for_self(_member_requester(test_user))

    keys = {g["key"] for g in groups}
    assert keys == {"location"}


def test_build_self_surfaces_locked_flag(test_user):
    """Locked attributes are shown with locked=True for read-only rendering."""
    _seed_config(test_user["tenant_id"], keys=("job_title",), locked_for_users=True)

    groups = build_attribute_groups_for_self(_member_requester(test_user))
    job_title = groups[0]["attributes"][0]
    assert job_title["key"] == "job_title"
    assert job_title["locked"] is True


def test_build_self_swallows_config_service_error(test_user):
    """A ServiceError reading config returns empty groups, not a 500."""
    with patch(
        "services.users.attribute_views.settings_service.list_tenant_attribute_config",
        side_effect=ServiceError("boom", code="bad"),
    ):
        assert build_attribute_groups_for_self(_member_requester(test_user)) == []


def test_build_self_swallows_user_attributes_service_error(test_user):
    """A ServiceError reading user values returns empty groups, not a 500."""
    _seed_config(test_user["tenant_id"], keys=("job_title",))
    with patch(
        "services.users.list_user_attributes",
        side_effect=ServiceError("boom", code="bad"),
    ):
        groups = build_attribute_groups_for_self(_member_requester(test_user))
    # Config came through, values default to "".
    job_title = groups[0]["attributes"][0]
    assert job_title["value"] == ""


# ---------------------------------------------------------------------------
# build_attribute_groups_for_admin
# ---------------------------------------------------------------------------


def test_build_admin_surfaces_mirror_from_idp_flag(test_user):
    """Admin variant exposes mirror_from_idp so the template can label rows."""
    _seed_config(
        test_user["tenant_id"],
        keys=("job_title",),
        mirror_from_idp=True,
        locked_for_users=True,
    )
    admin = _admin_requester(test_user)

    groups = build_attribute_groups_for_admin(admin, str(test_user["id"]))

    job_title = groups[0]["attributes"][0]
    assert job_title["mirror_from_idp"] is True
    assert job_title["locked"] is True


def test_build_admin_includes_locked_attributes(test_user):
    """Admin sees locked attributes (regardless of lock state) for editing."""
    _seed_config(test_user["tenant_id"], keys=("job_title",), locked_for_users=True)
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Director",
    )

    groups = build_attribute_groups_for_admin(_admin_requester(test_user), str(test_user["id"]))

    item = groups[0]["attributes"][0]
    assert item["value"] == "Director"
    assert item["locked"] is True


def test_build_admin_skips_disabled_attributes(test_user):
    """Disabled attributes are filtered out even for admin."""
    _seed_config(test_user["tenant_id"], keys=("job_title",), enabled=False)

    groups = build_attribute_groups_for_admin(_admin_requester(test_user), str(test_user["id"]))
    assert groups == []


# ---------------------------------------------------------------------------
# build_idp_attribute_panel
# ---------------------------------------------------------------------------


def test_build_idp_panel_empty_when_no_idp_rows(test_user):
    """No IdP-mirror rows means no panel."""
    admin = _admin_requester(test_user)
    assert build_idp_attribute_panel(admin, str(test_user["id"])) == []


def test_build_idp_panel_groups_by_idp_with_mirror_badges(test_user):
    """Rows are grouped per IdP; mirror flag follows tenant config."""
    _seed_config(test_user["tenant_id"], keys=("job_title",), mirror_from_idp=True)
    _seed_config(test_user["tenant_id"], keys=("department",), mirror_from_idp=False)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    from services.users.attributes import apply_idp_attributes

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer", "department": "Platform"},
        actor_user_id=str(test_user["id"]),
    )

    panel = build_idp_attribute_panel(_admin_requester(test_user), str(test_user["id"]))

    assert len(panel) == 1
    group = panel[0]
    assert group["idp_id"] == str(idp["id"])
    assert group["idp_name"].startswith("IdP ")

    by_key = {row["attribute_key"]: row for row in group["attributes"]}
    assert by_key["job_title"]["value"] == "Engineer"
    assert by_key["job_title"]["mirrored_into_profile"] is True
    assert by_key["department"]["value"] == "Platform"
    assert by_key["department"]["mirrored_into_profile"] is False


def test_build_idp_panel_tags_unknown_idp(test_user):
    """If the IdP record is missing, the row is labeled 'Unknown IdP'."""
    _seed_config(test_user["tenant_id"], keys=("job_title",), mirror_from_idp=True)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    from services.users.attributes import apply_idp_attributes

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
        actor_user_id=str(test_user["id"]),
    )

    with patch(
        "services.users.attribute_views.database.saml.get_identity_provider",
        return_value=None,
    ):
        panel = build_idp_attribute_panel(_admin_requester(test_user), str(test_user["id"]))

    assert panel[0]["idp_name"] == "Unknown IdP"


def test_build_idp_panel_swallows_idp_attribute_service_error(test_user):
    """ServiceError reading IdP rows returns empty list, not a 500."""
    with patch(
        "services.users.list_user_idp_attributes",
        side_effect=ServiceError("boom", code="bad"),
    ):
        panel = build_idp_attribute_panel(_admin_requester(test_user), str(test_user["id"]))
    assert panel == []


def test_build_idp_panel_swallows_config_service_error(test_user):
    """ServiceError reading tenant config still produces a panel; mirror flags default False."""
    _seed_config(test_user["tenant_id"], keys=("job_title",), mirror_from_idp=True)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    from services.users.attributes import apply_idp_attributes

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
        actor_user_id=str(test_user["id"]),
    )

    with patch(
        "services.users.attribute_views.settings_service.list_tenant_attribute_config",
        side_effect=ServiceError("boom", code="bad"),
    ):
        panel = build_idp_attribute_panel(_admin_requester(test_user), str(test_user["id"]))

    assert len(panel) == 1
    assert panel[0]["attributes"][0]["mirrored_into_profile"] is False
