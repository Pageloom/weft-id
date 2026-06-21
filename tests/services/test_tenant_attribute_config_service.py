"""Tests for services.settings.attributes (tenant attribute config service)."""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import database
import pytest
from constants.user_attributes import ATTRIBUTE_KEYS, STANDARD_ATTRIBUTES
from services.exceptions import ForbiddenError, NotFoundError, ValidationError
from services.settings.attributes import (
    list_tenant_attribute_config,
    seed_tenant_attribute_config,
    update_tenant_attribute_config,
)
from services.types import RequestingUser


def _super(tenant_id, user_id=None):
    return RequestingUser(
        id=user_id or str(uuid4()),
        tenant_id=str(tenant_id),
        role="super_admin",
    )


# ---------------------------------------------------------------------------
# seed_tenant_attribute_config
# ---------------------------------------------------------------------------


def test_seed_inserts_all_fourteen_rows(test_tenant):
    inserted = seed_tenant_attribute_config(str(test_tenant["id"]))
    assert inserted == 14

    rows = database.tenant_attribute_config.list_config(test_tenant["id"])
    assert {r["attribute_key"] for r in rows} == ATTRIBUTE_KEYS

    # All flags default sane.
    for r in rows:
        assert r["enabled"] is False
        assert r["required"] is False
        assert r["mirror_from_idp"] is True
        assert r["locked_for_users"] is False
        assert r["send_to_sps_default"] is True
        # Secure default: user-edited values are NOT propagated to SPs.
        assert r["allow_self_sourced_to_sp"] is False


def test_seed_is_idempotent(test_tenant):
    first = seed_tenant_attribute_config(str(test_tenant["id"]))
    second = seed_tenant_attribute_config(str(test_tenant["id"]))
    assert first == 14
    assert second == 0


def test_provision_tenant_seeds_attribute_config():
    """The CLI's provision_tenant path must seed config rows."""
    from dev.tenants import provision_tenant

    subdomain = f"seed-{uuid4().hex[:8]}"
    try:
        provision_tenant(subdomain, f"Seed Test {subdomain}")
        tenant = database.fetchone(
            database.UNSCOPED,
            "SELECT id FROM tenants WHERE subdomain = :s",
            {"s": subdomain},
        )
        assert tenant is not None
        rows = database.tenant_attribute_config.list_config(tenant["id"])
        assert len(rows) == len(STANDARD_ATTRIBUTES)
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE subdomain = :s",
            {"s": subdomain},
        )


# ---------------------------------------------------------------------------
# list / update
# ---------------------------------------------------------------------------


def test_list_tenant_attribute_config_super_admin_succeeds(test_tenant):
    seed_tenant_attribute_config(str(test_tenant["id"]))
    rows = list_tenant_attribute_config(_super(test_tenant["id"]))
    assert len(rows) == 14


def test_list_tenant_attribute_config_member_allowed(test_tenant):
    """Iter 7 relaxed: members need to read tenant attribute config to render
    their own profile editing UI (force_profile_completion gate would otherwise
    be inescapable for non-admin users).
    """
    seed_tenant_attribute_config(str(test_tenant["id"]))
    member = RequestingUser(id=str(uuid4()), tenant_id=str(test_tenant["id"]), role="member")
    rows = list_tenant_attribute_config(member)
    assert len(rows) == 14


def test_list_tenant_attribute_config_admin_allowed(test_tenant):
    """Iter 7 relaxed: any authenticated user in the tenant can read."""
    seed_tenant_attribute_config(str(test_tenant["id"]))
    admin = RequestingUser(id=str(uuid4()), tenant_id=str(test_tenant["id"]), role="admin")
    rows = list_tenant_attribute_config(admin)
    assert len(rows) == 14


def test_update_tenant_attribute_config_super_admin_succeeds(test_tenant):
    seed_tenant_attribute_config(str(test_tenant["id"]))
    requester = _super(test_tenant["id"])

    updated = update_tenant_attribute_config(
        requester,
        "job_title",
        enabled=True,
        required=True,
        mirror_from_idp=True,
        locked_for_users=True,
        send_to_sps_default=False,
    )
    assert updated["enabled"] is True
    assert updated["required"] is True
    assert updated["mirror_from_idp"] is True
    assert updated["locked_for_users"] is True
    assert updated["send_to_sps_default"] is False


def test_update_tenant_attribute_config_persists_allow_self_sourced(test_tenant):
    """The allow_self_sourced_to_sp flag round-trips and shows in the diff."""
    seed_tenant_attribute_config(str(test_tenant["id"]))
    requester = _super(test_tenant["id"])

    with patch("services.settings.attributes.log_event") as mock_log:
        updated = update_tenant_attribute_config(
            requester,
            "job_title",
            enabled=True,
            required=False,
            mirror_from_idp=True,
            locked_for_users=False,
            send_to_sps_default=True,
            allow_self_sourced_to_sp=True,
        )
    assert updated["allow_self_sourced_to_sp"] is True
    changes = mock_log.call_args.kwargs["metadata"]["changes"]
    assert changes["allow_self_sourced_to_sp"] == {"old": False, "new": True}


def test_update_tenant_attribute_config_emits_event_with_changes(test_tenant):
    seed_tenant_attribute_config(str(test_tenant["id"]))
    requester = _super(test_tenant["id"])

    with patch("services.settings.attributes.log_event") as mock_log:
        update_tenant_attribute_config(
            requester,
            "job_title",
            enabled=True,
            required=False,
            mirror_from_idp=False,
            locked_for_users=False,
            send_to_sps_default=True,
        )
    assert mock_log.call_count == 1
    args = mock_log.call_args
    assert args.kwargs["event_type"] == "tenant_attribute_config_updated"
    assert args.kwargs["metadata"]["attribute_key"] == "job_title"
    assert "enabled" in args.kwargs["metadata"]["changes"]


def test_update_tenant_attribute_config_no_event_when_unchanged(test_tenant):
    seed_tenant_attribute_config(str(test_tenant["id"]))
    requester = _super(test_tenant["id"])

    # Default flags written again -- no diff.
    with patch("services.settings.attributes.log_event") as mock_log:
        update_tenant_attribute_config(
            requester,
            "job_title",
            enabled=False,
            required=False,
            mirror_from_idp=True,
            locked_for_users=False,
            send_to_sps_default=True,
        )
    mock_log.assert_not_called()


def test_update_tenant_attribute_config_unknown_key_raises(test_tenant):
    seed_tenant_attribute_config(str(test_tenant["id"]))
    requester = _super(test_tenant["id"])
    with pytest.raises(ValidationError):
        update_tenant_attribute_config(
            requester,
            "no_such_key",
            enabled=True,
            required=False,
            mirror_from_idp=False,
            locked_for_users=False,
            send_to_sps_default=True,
        )


def test_update_tenant_attribute_config_missing_row_raises(test_tenant):
    """If the tenant was never seeded, surface a clear NotFoundError."""
    requester = _super(test_tenant["id"])
    with pytest.raises(NotFoundError):
        update_tenant_attribute_config(
            requester,
            "job_title",
            enabled=True,
            required=False,
            mirror_from_idp=False,
            locked_for_users=False,
            send_to_sps_default=True,
        )


def test_update_tenant_attribute_config_admin_forbidden(test_tenant):
    seed_tenant_attribute_config(str(test_tenant["id"]))
    admin = RequestingUser(id=str(uuid4()), tenant_id=str(test_tenant["id"]), role="admin")
    with pytest.raises(ForbiddenError):
        update_tenant_attribute_config(
            admin,
            "job_title",
            enabled=True,
            required=False,
            mirror_from_idp=False,
            locked_for_users=False,
            send_to_sps_default=True,
        )
