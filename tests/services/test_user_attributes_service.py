"""Tests for services.users.attributes (two-space attribute service)."""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import database
import pytest
from services.exceptions import (
    ForbiddenError,
    NotFoundError,
    ValidationError,
)
from services.types import RequestingUser
from services.users.attributes import (
    apply_idp_attributes,
    clear_user_attribute,
    get_user_attribute,
    list_user_attributes,
    list_user_idp_attributes,
    set_user_attribute,
)

# ---------------------------------------------------------------------------
# Helpers
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
    """Insert default tenant_attribute_config rows the test depends on."""
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


def _make_requester(test_user, role: str = "member") -> RequestingUser:
    return RequestingUser(
        id=str(test_user["id"]),
        tenant_id=str(test_user["tenant_id"]),
        role=role,
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


# ---------------------------------------------------------------------------
# set_user_attribute
# ---------------------------------------------------------------------------


def test_set_user_attribute_self_succeeds_when_enabled(test_user):
    _seed_config(test_user["tenant_id"])
    requester = _make_requester(test_user, role="member")

    row = set_user_attribute(requester, str(test_user["id"]), "job_title", "Engineer")
    assert row["value"] == "Engineer"


def test_set_user_attribute_disabled_attribute_raises(test_user):
    _seed_config(test_user["tenant_id"], enabled=False)
    requester = _make_requester(test_user, role="member")

    with pytest.raises(ValidationError) as exc:
        set_user_attribute(requester, str(test_user["id"]), "job_title", "Engineer")
    assert exc.value.code == "attribute_not_enabled"


def test_set_user_attribute_unknown_key_raises(test_user):
    requester = _make_requester(test_user, role="member")
    with pytest.raises(ValidationError) as exc:
        set_user_attribute(requester, str(test_user["id"]), "not_a_real_key", "value")
    assert exc.value.code == "unknown_attribute_key"


def test_set_user_attribute_locked_user_self_forbidden(test_user):
    _seed_config(test_user["tenant_id"], locked_for_users=True)
    requester = _make_requester(test_user, role="member")
    with pytest.raises(ForbiddenError) as exc:
        set_user_attribute(requester, str(test_user["id"]), "job_title", "Engineer")
    assert exc.value.code == "attribute_locked"


def test_set_user_attribute_locked_admin_succeeds(test_user):
    _seed_config(test_user["tenant_id"], locked_for_users=True)
    admin = RequestingUser(
        id=str(uuid4()),  # different user
        tenant_id=str(test_user["tenant_id"]),
        role="admin",
    )
    row = set_user_attribute(admin, str(test_user["id"]), "job_title", "Engineer")
    assert row["value"] == "Engineer"


def test_set_user_attribute_invalid_value_raises(test_user):
    """Serialization errors (bad country code, etc.) bubble up."""
    _seed_config(test_user["tenant_id"], keys=("country",))
    requester = _make_requester(test_user, role="member")
    with pytest.raises(Exception):
        # 'not-a-country' fails the 2-letter ISO check.
        set_user_attribute(requester, str(test_user["id"]), "country", "not-a-country")


def test_set_user_attribute_logs_event_with_cause_self_edit(test_user):
    _seed_config(test_user["tenant_id"])
    requester = _make_requester(test_user, role="member")

    with patch("services.users.attributes.log_event") as mock_log:
        set_user_attribute(requester, str(test_user["id"]), "job_title", "Engineer")

    assert mock_log.call_count == 1
    metadata = mock_log.call_args.kwargs["metadata"]
    assert metadata["cause"] == "self_edit"
    assert metadata["idp_id"] is None
    assert metadata["changes"]["job_title"]["new"] == "Engineer"


def test_set_user_attribute_logs_event_with_cause_admin_edit(test_user):
    _seed_config(test_user["tenant_id"])
    admin = RequestingUser(
        id=str(uuid4()),
        tenant_id=str(test_user["tenant_id"]),
        role="admin",
    )
    with patch("services.users.attributes.log_event") as mock_log:
        set_user_attribute(admin, str(test_user["id"]), "job_title", "Engineer")

    assert mock_log.call_args.kwargs["metadata"]["cause"] == "admin_edit"


def test_set_user_attribute_no_event_when_unchanged(test_user):
    _seed_config(test_user["tenant_id"])
    requester = _make_requester(test_user, role="member")
    set_user_attribute(requester, str(test_user["id"]), "job_title", "Engineer")

    with patch("services.users.attributes.log_event") as mock_log:
        set_user_attribute(requester, str(test_user["id"]), "job_title", "Engineer")
    mock_log.assert_not_called()


# ---------------------------------------------------------------------------
# clear_user_attribute
# ---------------------------------------------------------------------------


def test_clear_user_attribute_locked_user_forbidden(test_user):
    _seed_config(test_user["tenant_id"], locked_for_users=True)
    # Pre-seed a row via direct DB so the lock is what blocks deletion.
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    requester = _make_requester(test_user, role="member")
    with pytest.raises(ForbiddenError) as exc:
        clear_user_attribute(requester, str(test_user["id"]), "job_title")
    assert exc.value.code == "attribute_locked"


def test_clear_user_attribute_admin_succeeds(test_user):
    _seed_config(test_user["tenant_id"])
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    admin = RequestingUser(id=str(uuid4()), tenant_id=str(test_user["tenant_id"]), role="admin")
    assert clear_user_attribute(admin, str(test_user["id"]), "job_title") is True
    assert (
        database.user_attributes.get_attribute(
            test_user["tenant_id"], str(test_user["id"]), "job_title"
        )
        is None
    )


def test_clear_user_attribute_returns_false_when_missing(test_user):
    _seed_config(test_user["tenant_id"])
    requester = _make_requester(test_user, role="member")
    assert clear_user_attribute(requester, str(test_user["id"]), "job_title") is False


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def test_list_user_attributes_self_allowed(test_user):
    _seed_config(test_user["tenant_id"])
    database.user_attributes.upsert_attribute(
        tenant_id=test_user["tenant_id"],
        tenant_id_value=str(test_user["tenant_id"]),
        user_id=test_user["id"],
        attribute_key="job_title",
        value="Engineer",
    )
    requester = _make_requester(test_user, role="member")
    rows = list_user_attributes(requester, str(test_user["id"]))
    assert len(rows) == 1


def test_list_user_attributes_other_user_member_forbidden(test_user):
    _seed_config(test_user["tenant_id"])
    requester = RequestingUser(
        id=str(uuid4()),
        tenant_id=str(test_user["tenant_id"]),
        role="member",
    )
    with pytest.raises(ForbiddenError):
        list_user_attributes(requester, str(test_user["id"]))


def test_get_user_attribute_returns_none_when_missing(test_user):
    requester = _make_requester(test_user, role="member")
    assert get_user_attribute(requester, str(test_user["id"]), "job_title") is None


def test_list_user_idp_attributes_admin_only(test_user):
    member = _make_requester(test_user, role="member")
    with pytest.raises(ForbiddenError):
        list_user_idp_attributes(member, str(test_user["id"]))

    admin = RequestingUser(id=str(uuid4()), tenant_id=str(test_user["tenant_id"]), role="admin")
    rows = list_user_idp_attributes(admin, str(test_user["id"]))
    assert rows == []


# ---------------------------------------------------------------------------
# apply_idp_attributes
# ---------------------------------------------------------------------------


def test_apply_idp_attributes_unknown_idp_raises(test_user):
    _seed_config(test_user["tenant_id"])
    bogus_idp_id = str(uuid4())
    with pytest.raises(NotFoundError) as exc:
        apply_idp_attributes(
            tenant_id=str(test_user["tenant_id"]),
            user_id=str(test_user["id"]),
            idp_id=bogus_idp_id,
            attributes={"job_title": "Engineer"},
            actor_user_id=str(test_user["id"]),
        )
    assert exc.value.code == "idp_not_found"


def test_apply_idp_attributes_writes_idp_mirror_always(test_user):
    """Even when mirror_from_idp=false, IdP-mirror table receives the snapshot."""
    _seed_config(test_user["tenant_id"], mirror_from_idp=False)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
        actor_user_id=str(test_user["id"]),
    )

    idp_rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], str(test_user["id"]), str(idp["id"])
    )
    assert len(idp_rows) == 1
    assert idp_rows[0]["attribute_key"] == "job_title"

    # And mirror_from_idp=false means user_attributes is NOT touched.
    canonical = database.user_attributes.list_attributes(
        test_user["tenant_id"], str(test_user["id"])
    )
    assert canonical == []


def test_apply_idp_attributes_mirrors_when_flag_on(test_user):
    """mirror_from_idp=true causes upsert into user_attributes."""
    _seed_config(test_user["tenant_id"], mirror_from_idp=True)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
        actor_user_id=str(test_user["id"]),
    )
    canonical = database.user_attributes.list_attributes(
        test_user["tenant_id"], str(test_user["id"])
    )
    assert len(canonical) == 1
    assert canonical[0]["value"] == "Engineer"


def test_apply_idp_attributes_mirrors_only_flagged_keys(test_user):
    """Only keys with enabled+mirror flow into user_attributes."""
    # job_title is mirrored; department is enabled but not mirrored;
    # city is disabled.
    from constants.user_attributes import ATTRIBUTES_BY_KEY

    for key, enabled, mirror in [
        ("job_title", True, True),
        ("department", True, False),
        ("city", False, False),
    ]:
        attr = ATTRIBUTES_BY_KEY[key]
        database.execute(
            test_user["tenant_id"],
            """
            INSERT INTO tenant_attribute_config (
                tenant_id, attribute_key, category, enabled, required,
                mirror_from_idp, locked_for_users, send_to_sps_default
            ) VALUES (
                :tenant_id, :attribute_key, :category, :enabled, false,
                :mirror, false, true
            )
            ON CONFLICT (tenant_id, attribute_key) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                mirror_from_idp = EXCLUDED.mirror_from_idp
            """,
            {
                "tenant_id": str(test_user["tenant_id"]),
                "attribute_key": key,
                "category": attr.category,
                "enabled": enabled,
                "mirror": mirror,
            },
        )
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={
            "job_title": "Engineer",
            "department": "Platform",
            "city": "NYC",
        },
        actor_user_id=str(test_user["id"]),
    )

    canonical_keys = {
        r["attribute_key"]
        for r in database.user_attributes.list_attributes(
            test_user["tenant_id"], str(test_user["id"])
        )
    }
    assert canonical_keys == {"job_title"}

    # IdP-mirror table holds all sent keys regardless.
    idp_keys = {
        r["attribute_key"]
        for r in database.user_idp_attributes.list_attributes_for_idp(
            test_user["tenant_id"], str(test_user["id"]), str(idp["id"])
        )
    }
    assert idp_keys == {"job_title", "department", "city"}


def test_apply_idp_attributes_emits_event_when_canonical_changed(test_user):
    _seed_config(test_user["tenant_id"], mirror_from_idp=True)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    with patch("services.users.attributes.log_event") as mock_log:
        apply_idp_attributes(
            tenant_id=str(test_user["tenant_id"]),
            user_id=str(test_user["id"]),
            idp_id=str(idp["id"]),
            attributes={"job_title": "Engineer"},
            actor_user_id=str(test_user["id"]),
        )

    assert mock_log.call_count == 1
    metadata = mock_log.call_args.kwargs["metadata"]
    assert metadata["cause"] == "idp_mirror"
    assert metadata["idp_id"] == str(idp["id"])
    assert "job_title" in metadata["changes"]


def test_apply_idp_attributes_no_event_when_canonical_unchanged(test_user):
    """Re-running with the same value emits no event (mirror stays in sync)."""
    _seed_config(test_user["tenant_id"], mirror_from_idp=True)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
        actor_user_id=str(test_user["id"]),
    )

    with patch("services.users.attributes.log_event") as mock_log:
        apply_idp_attributes(
            tenant_id=str(test_user["tenant_id"]),
            user_id=str(test_user["id"]),
            idp_id=str(idp["id"]),
            attributes={"job_title": "Engineer"},
            actor_user_id=str(test_user["id"]),
        )
    mock_log.assert_not_called()


def test_apply_idp_attributes_no_event_when_only_mirror_table_changes(test_user):
    """Mirror-off tenants don't emit user_profile_updated when IdP attrs change."""
    _seed_config(test_user["tenant_id"], mirror_from_idp=False)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    with patch("services.users.attributes.log_event") as mock_log:
        apply_idp_attributes(
            tenant_id=str(test_user["tenant_id"]),
            user_id=str(test_user["id"]),
            idp_id=str(idp["id"]),
            attributes={"job_title": "Engineer"},
            actor_user_id=str(test_user["id"]),
        )
    mock_log.assert_not_called()


def test_apply_idp_attributes_drops_unknown_keys(test_user):
    """Unknown keys in the attribute dict are silently dropped."""
    _seed_config(test_user["tenant_id"], mirror_from_idp=True)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer", "unknown_key": "ignored"},
        actor_user_id=str(test_user["id"]),
    )
    idp_keys = {
        r["attribute_key"]
        for r in database.user_idp_attributes.list_attributes_for_idp(
            test_user["tenant_id"], str(test_user["id"]), str(idp["id"])
        )
    }
    assert idp_keys == {"job_title"}


def test_apply_idp_attributes_replaces_snapshot_per_idp(test_user):
    """Each call replaces the IdP-mirror set for that IdP (delete + insert)."""
    _seed_config(test_user["tenant_id"], mirror_from_idp=False)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer", "department": "Platform"},
        actor_user_id=str(test_user["id"]),
    )
    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Senior Engineer"},
        actor_user_id=str(test_user["id"]),
    )
    keys = {
        r["attribute_key"]
        for r in database.user_idp_attributes.list_attributes_for_idp(
            test_user["tenant_id"], str(test_user["id"]), str(idp["id"])
        )
    }
    assert keys == {"job_title"}


def test_apply_idp_attributes_empty_dict_clears_snapshot(test_user):
    """Empty attributes dict drops all IdP-mirror rows; no canonical change; no event."""
    _seed_config(test_user["tenant_id"], mirror_from_idp=True)
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"job_title": "Engineer"},
        actor_user_id=str(test_user["id"]),
    )

    with patch("services.users.attributes.log_event") as mock_log:
        apply_idp_attributes(
            tenant_id=str(test_user["tenant_id"]),
            user_id=str(test_user["id"]),
            idp_id=str(idp["id"]),
            attributes={},
            actor_user_id=str(test_user["id"]),
        )

    # IdP-mirror snapshot for this IdP is now empty.
    idp_rows = database.user_idp_attributes.list_attributes_for_idp(
        test_user["tenant_id"], str(test_user["id"]), str(idp["id"])
    )
    assert idp_rows == []
    # Canonical user_attributes is preserved (mirror is one-way; clearing the
    # snapshot is not a "remove from canonical" signal).
    canonical = database.user_attributes.list_attributes(
        test_user["tenant_id"], str(test_user["id"])
    )
    assert len(canonical) == 1
    # No event because canonical didn't change.
    mock_log.assert_not_called()


def test_apply_idp_attributes_drops_malformed_values(test_user):
    """Bad serialization (e.g. invalid country code) drops the key, others land."""
    _seed_config(
        test_user["tenant_id"],
        mirror_from_idp=False,
        keys=("job_title", "country"),
    )
    idp = _make_idp(test_user["tenant_id"], test_user["id"])

    apply_idp_attributes(
        tenant_id=str(test_user["tenant_id"]),
        user_id=str(test_user["id"]),
        idp_id=str(idp["id"]),
        attributes={"country": "not-a-country", "job_title": "Engineer"},
        actor_user_id=str(test_user["id"]),
    )

    keys = {
        r["attribute_key"]
        for r in database.user_idp_attributes.list_attributes_for_idp(
            test_user["tenant_id"], str(test_user["id"]), str(idp["id"])
        )
    }
    assert keys == {"job_title"}


def test_apply_idp_attributes_cross_tenant_idp_rejected(test_user):
    """An IdP that belongs to another tenant must raise NotFoundError."""
    other_subdomain = f"foreign-{uuid4().hex[:8]}"
    database.execute(
        database.UNSCOPED,
        "INSERT INTO tenants (subdomain, name) VALUES (:s, :n)",
        {"s": other_subdomain, "n": "Foreign"},
    )
    other = database.fetchone(
        database.UNSCOPED,
        "SELECT id FROM tenants WHERE subdomain = :s",
        {"s": other_subdomain},
    )
    assert other is not None

    # Create a user in the foreign tenant so the IdP has a created_by.
    from tests.conftest import TEST_PASSWORD_HASH

    foreign_user = database.fetchone(
        other["id"],
        """
        INSERT INTO users (tenant_id, password_hash, first_name, last_name, role)
        VALUES (:tenant_id, :pw, 'F', 'U', 'admin')
        RETURNING id
        """,
        {"tenant_id": str(other["id"]), "pw": TEST_PASSWORD_HASH},
    )
    other_idp = database.fetchone(
        other["id"],
        """
        INSERT INTO saml_identity_providers (
            tenant_id, name, provider_type, entity_id, sso_url,
            certificate_pem, sp_entity_id, created_by
        ) VALUES (
            :tenant_id, 'foreign-idp', 'generic', :entity_id,
            'https://idp.example.com/sso', 'cert', 'https://sp.example.com',
            :created_by
        ) RETURNING id
        """,
        {
            "tenant_id": str(other["id"]),
            "entity_id": f"https://idp-{uuid4().hex[:8]}.example.com",
            "created_by": foreign_user["id"],
        },
    )

    _seed_config(test_user["tenant_id"], mirror_from_idp=False)
    try:
        with pytest.raises(NotFoundError) as exc:
            apply_idp_attributes(
                tenant_id=str(test_user["tenant_id"]),
                user_id=str(test_user["id"]),
                idp_id=str(other_idp["id"]),
                attributes={"job_title": "Engineer"},
                actor_user_id=str(test_user["id"]),
            )
        assert exc.value.code == "idp_not_found"
    finally:
        database.execute(
            database.UNSCOPED,
            "DELETE FROM tenants WHERE id = :id",
            {"id": other["id"]},
        )


# ---------------------------------------------------------------------------
# Tenant policy + cross-user authorization
# ---------------------------------------------------------------------------


def test_set_user_attribute_self_blocked_when_profile_editing_disabled(test_user):
    """`allow_users_edit_profile=false` blocks self edits; admin still succeeds."""
    _seed_config(test_user["tenant_id"])
    requester = _make_requester(test_user, role="member")

    with patch("services.users.attributes.can_user_edit_profile", return_value=False):
        with pytest.raises(ForbiddenError) as exc:
            set_user_attribute(requester, str(test_user["id"]), "job_title", "Engineer")
        assert exc.value.code == "profile_editing_disabled"

        admin = RequestingUser(
            id=str(uuid4()),
            tenant_id=str(test_user["tenant_id"]),
            role="admin",
        )
        # Admin path bypasses the tenant flag entirely.
        row = set_user_attribute(admin, str(test_user["id"]), "job_title", "Engineer")
        assert row["value"] == "Engineer"


def test_set_user_attribute_cross_user_member_forbidden(test_user):
    """A member acting on a different user's profile is rejected."""
    _seed_config(test_user["tenant_id"])
    foreign_member = RequestingUser(
        id=str(uuid4()),
        tenant_id=str(test_user["tenant_id"]),
        role="member",
    )
    with pytest.raises(ForbiddenError) as exc:
        set_user_attribute(foreign_member, str(test_user["id"]), "job_title", "Engineer")
    assert exc.value.code == "forbidden"
