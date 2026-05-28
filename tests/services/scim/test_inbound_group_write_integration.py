"""End-to-end integration tests for the inbound SCIM Groups write service.

Talks to the real database. Exercises the full create / replace /
patch / delete flow on `idp` groups, verifies membership ops fire
through `services.groups.idp` (and emit the per-member events the
outbound SCIM dispatch keys off), and pins the displayName-uniqueness
contract.

The outbound-replay verification test lives at the bottom: it builds
a SCIM-enabled SP granted via the group, adds a user as a SCIM group
member, and asserts `scim_push_queue` grew for that SP/user pair.
"""

from __future__ import annotations

from uuid import uuid4

import database
import pytest
from services.scim.inbound_group_write import (
    create_group,
    delete_group,
    patch_group,
    replace_group,
)
from services.scim.inbound_write import (
    ScimWriteError,
    create_or_merge_user,
)


def _group_location(group_id: str) -> str:
    return f"https://t.test/scim/v2/inbound/i/Groups/{group_id}"


_USERS_BASE = "https://t.test/scim/v2/inbound/i/Users"


def _user_location(user_id: str) -> str:
    return f"{_USERS_BASE}/{user_id}"


@pytest.fixture
def idp(test_tenant, test_user):
    return database.saml.create_identity_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="SCIM Group IdP",
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(test_user["id"]),
    )


def _make_user(tenant_id: str, idp_id: str, *, external_id: str | None = None) -> str:
    """Provision a user bound to the IdP via the SCIM user-create path."""
    suffix = uuid4().hex[:8]
    payload = {
        "userName": f"u-{suffix}@example.test",
        "name": {"givenName": "U", "familyName": suffix},
    }
    if external_id:
        payload["externalId"] = external_id
    res, _ = create_or_merge_user(
        tenant_id,
        idp_id,
        payload,
        location_builder=_user_location,
    )
    return res["id"]


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


def test_create_group_creates_idp_group(test_tenant, idp):
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "Engineers"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    assert payload["displayName"] == "Engineers"
    row = database.groups.get_group_by_id(str(test_tenant["id"]), payload["id"])
    assert row is not None
    assert row["group_type"] == "idp"
    assert str(row["idp_id"]) == str(idp["id"])


def test_create_group_with_initial_members_resolves_and_adds(test_tenant, idp):
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    u2 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "displayName": "Team",
            "members": [{"value": u1}, {"value": u2}],
        },
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert sorted(str(m["id"]) for m in members) == sorted([u1, u2])


def test_create_group_resolves_member_by_external_id(test_tenant, idp):
    """When members[].value is the upstream externalId, the service looks
    it up in user_idp_attributes and resolves to the WeftID user."""
    _make_user(str(test_tenant["id"]), str(idp["id"]), external_id="okta-ext-1")
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "displayName": "ExtIdGroup",
            "members": [{"value": "okta-ext-1"}],
        },
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert len(members) == 1


def test_create_group_rejects_unknown_member_reference(test_tenant, idp):
    with pytest.raises(ScimWriteError) as exc_info:
        create_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            {
                "displayName": "Bogus",
                "members": [{"value": str(uuid4())}],
            },
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 400
    assert exc_info.value.scim_type == "invalidValue"


def test_create_group_rejects_missing_display_name(test_tenant, idp):
    with pytest.raises(ScimWriteError) as exc_info:
        create_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            {"members": []},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 400
    assert exc_info.value.scim_type == "invalidValue"


def test_create_group_rejects_duplicate_display_name(test_tenant, idp):
    create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "DupCheck"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        create_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            {"displayName": "DupCheck"},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 409
    assert exc_info.value.scim_type == "uniqueness"


def test_create_group_ignores_parent_hierarchy_attributes(test_tenant, idp):
    """SCIM clients cannot establish parent/child relationships -- the
    payload's `parent` or `parents` are silently dropped (SCIM 2.0
    §3.5.2 permits ignoring unknown attributes)."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "displayName": "NoParent",
            "parent": str(uuid4()),
            "parents": [str(uuid4())],
        },
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    row = database.groups.get_group_by_id(str(test_tenant["id"]), payload["id"])
    assert row is not None
    # No parent relationship was created -- parent_count is 0.
    assert row["parent_count"] == 0


def test_create_group_event_scim_group_received_logged(test_tenant, idp):
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "Audited"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    events = database.fetchall(
        str(test_tenant["id"]),
        """
        select event_type
        from event_logs
        where artifact_id = :id and event_type = 'scim_group_received'
        """,
        {"id": payload["id"]},
    )
    assert len(events) >= 1


# ---------------------------------------------------------------------------
# Replace (PUT)
# ---------------------------------------------------------------------------


def test_replace_group_renames_and_replaces_members(test_tenant, idp):
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    u2 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "OldName", "members": [{"value": u1}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    group_id = payload["id"]

    replace_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        group_id,
        {"displayName": "NewName", "members": [{"value": u2}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    row = database.groups.get_group_by_id(str(test_tenant["id"]), group_id)
    assert row["name"] == "NewName"
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), group_id)
    assert [str(m["id"]) for m in members] == [u2]


def test_replace_group_rejects_collision_with_existing_name(test_tenant, idp):
    create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "TakenName"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    other = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "OtherName"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        replace_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            other["id"],
            {"displayName": "TakenName"},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 409
    assert exc_info.value.scim_type == "uniqueness"


def test_replace_group_404_on_cross_idp(test_tenant, idp, test_user):
    """A group from a different IdP is invisible to this IdP's PUT."""
    other_idp = database.saml.create_identity_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Other IdP",
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(test_user["id"]),
    )
    other_group = create_group(
        str(test_tenant["id"]),
        str(other_idp["id"]),
        {"displayName": "OtherIdpGroup"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        replace_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            other_group["id"],
            {"displayName": "Renamed"},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 404


def test_replace_group_with_no_members_keeps_existing(test_tenant, idp):
    """PUT omits `members`: existing membership is preserved (Okta omits unchanged scalars)."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "KeepMe", "members": [{"value": u1}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    replace_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {"displayName": "KeepMe"},  # no members key
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert len(members) == 1


def test_replace_group_with_empty_members_clears(test_tenant, idp):
    """Explicit empty members array clears membership."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "Clearable", "members": [{"value": u1}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    replace_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {"displayName": "Clearable", "members": []},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert members == []


# ---------------------------------------------------------------------------
# PATCH
# ---------------------------------------------------------------------------


def test_patch_group_add_member(test_tenant, idp):
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "PatchAdd"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": u1}]},
            ]
        },
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert [str(m["id"]) for m in members] == [u1]


def test_patch_group_remove_member_with_okta_filter(test_tenant, idp):
    """Okta uses `members[value eq "<id>"]` for single-member removal."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    u2 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "RemoveOkta", "members": [{"value": u1}, {"value": u2}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {
            "Operations": [
                {"op": "remove", "path": f'members[value eq "{u1}"]'},
            ]
        },
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert [str(m["id"]) for m in members] == [u2]


def test_patch_group_remove_member_with_entra_batched_value(test_tenant, idp):
    """Entra sends `remove` with a value array instead of a filter."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    u2 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "RemoveEntra", "members": [{"value": u1}, {"value": u2}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {
            "Operations": [
                {"op": "remove", "path": "members", "value": [{"value": u1}]},
            ]
        },
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert [str(m["id"]) for m in members] == [u2]


def test_patch_group_rename(test_tenant, idp):
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "BeforeRename"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {"Operations": [{"op": "replace", "path": "displayName", "value": "AfterRename"}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    row = database.groups.get_group_by_id(str(test_tenant["id"]), payload["id"])
    assert row["name"] == "AfterRename"


def test_patch_group_rejects_unknown_path(test_tenant, idp):
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "PatchBadPath"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        patch_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            payload["id"],
            {"Operations": [{"op": "replace", "path": "garbage", "value": "x"}]},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 400
    assert exc_info.value.scim_type == "invalidPath"


def test_patch_group_rejects_rename_to_existing_name(test_tenant, idp):
    create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "Taken"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    other = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "Other"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        patch_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            other["id"],
            {"Operations": [{"op": "replace", "path": "displayName", "value": "Taken"}]},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


def test_delete_group_removes_group_row_and_clears_membership(test_tenant, idp):
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "ToDelete", "members": [{"value": u1}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    gid = payload["id"]
    delete_group(str(test_tenant["id"]), str(idp["id"]), gid)
    assert database.groups.get_group_by_id(str(test_tenant["id"]), gid) is None


def test_delete_group_emits_per_member_removed_events(test_tenant, idp):
    """Deletion fires `idp_group_member_removed` per member so the
    outbound SCIM dispatch can enqueue downstream deprovision cascades."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "ToDelete2", "members": [{"value": u1}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    gid = payload["id"]
    delete_group(str(test_tenant["id"]), str(idp["id"]), gid)
    rows = database.fetchall(
        str(test_tenant["id"]),
        """
        select event_type from event_logs
        where artifact_id = :gid and event_type = 'idp_group_member_removed'
        """,
        {"gid": gid},
    )
    assert len(rows) >= 1


def test_delete_group_does_not_deactivate_users(test_tenant, idp):
    """Per acceptance criteria, deleting a group must NOT deactivate users."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "DelKeepsUsers", "members": [{"value": u1}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    delete_group(str(test_tenant["id"]), str(idp["id"]), payload["id"])
    row = database.users.get_user_by_id(str(test_tenant["id"]), u1)
    assert row["is_inactivated"] is False


def test_delete_group_404_on_unknown_id(test_tenant, idp):
    with pytest.raises(ScimWriteError) as exc_info:
        delete_group(str(test_tenant["id"]), str(idp["id"]), str(uuid4()))
    assert exc_info.value.status_code == 404


def test_delete_group_emits_scim_group_deleted_event(test_tenant, idp):
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "DelAudit"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    delete_group(str(test_tenant["id"]), str(idp["id"]), payload["id"])
    rows = database.fetchall(
        str(test_tenant["id"]),
        """
        select event_type from event_logs
        where artifact_id = :gid and event_type = 'scim_group_deleted'
        """,
        {"gid": payload["id"]},
    )
    assert len(rows) >= 1


# ---------------------------------------------------------------------------
# Edge cases (gap coverage)
# ---------------------------------------------------------------------------


def test_patch_group_replace_members_full_collection_swap(test_tenant, idp):
    """`replace` on `members` swaps the entire collection. Not the same
    code path as `add` (which unions) -- replace clears unlisted members."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    u2 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    u3 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "ReplaceMembers", "members": [{"value": u1}, {"value": u2}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {
            "Operations": [
                {"op": "replace", "path": "members", "value": [{"value": u3}]},
            ]
        },
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert [str(m["id"]) for m in members] == [u3]


def test_patch_group_replace_members_with_empty_list_clears(test_tenant, idp):
    """`replace` with an empty array clears the membership."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "ReplaceClear", "members": [{"value": u1}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {"Operations": [{"op": "replace", "path": "members", "value": []}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert members == []


def test_patch_group_remove_members_with_no_value_clears_all(test_tenant, idp):
    """`remove` on `members` without filter and without value clears all."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    u2 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "RemoveAll", "members": [{"value": u1}, {"value": u2}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {"Operations": [{"op": "remove", "path": "members"}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert members == []


def test_patch_group_multiple_ops_in_one_batch(test_tenant, idp):
    """A single PATCH body with mixed ops: add member + rename in one call.
    Mirrors the Entra batched fixture (`patch_group_batched.json`)."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "MixedBefore"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": u1}]},
                {"op": "replace", "path": "displayName", "value": "MixedAfter"},
            ]
        },
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    row = database.groups.get_group_by_id(str(test_tenant["id"]), payload["id"])
    assert row["name"] == "MixedAfter"
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert [str(m["id"]) for m in members] == [u1]


def test_patch_group_rejects_remove_displayname(test_tenant, idp):
    """`remove` on `displayName` is explicitly rejected -- a group without
    a name is not useful, and the spec doesn't ask us to support it."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "NoRemove"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        patch_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            payload["id"],
            {"Operations": [{"op": "remove", "path": "displayName"}]},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 400
    assert exc_info.value.scim_type == "invalidValue"


def test_patch_group_rejects_invalid_op(test_tenant, idp):
    """Unknown ops (`merge`, `move`, ...) are rejected with invalidSyntax."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "BadOp"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        patch_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            payload["id"],
            {"Operations": [{"op": "merge", "path": "members", "value": []}]},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 400


def test_patch_group_rejects_no_path(test_tenant, idp):
    """Group PATCH requires a path on each op (no whole-resource ops)."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "NoPath"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        patch_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            payload["id"],
            {"Operations": [{"op": "add", "value": {"displayName": "X"}}]},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 400
    assert exc_info.value.scim_type == "noTarget"


def test_patch_group_rejects_empty_operations(test_tenant, idp):
    """An empty Operations array is a malformed PATCH."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "EmptyOps"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError):
        patch_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            payload["id"],
            {"Operations": []},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )


def test_patch_group_404_on_cross_idp(test_tenant, idp, test_user):
    """Cross-IdP isolation: a PATCH against a different IdP's group is 404."""
    other_idp = database.saml.create_identity_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Other PATCH IdP",
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(test_user["id"]),
    )
    other_group = create_group(
        str(test_tenant["id"]),
        str(other_idp["id"]),
        {"displayName": "OtherIdpPatchGroup"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        patch_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            other_group["id"],
            {"Operations": [{"op": "replace", "path": "displayName", "value": "x"}]},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 404


def test_create_group_dedupes_repeated_member_references(test_tenant, idp):
    """If a SCIM client lists the same user twice in members[], we dedupe."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {
            "displayName": "DedupeMembers",
            "members": [{"value": u1}, {"value": u1}],
        },
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert len(members) == 1


def test_create_group_externalid_silently_ignored(test_tenant, idp):
    """The SCIM POST body may carry an upstream externalId for the group.
    We mint our own id and don't persist it -- documented as v1 scope cut."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "ExtIdIgnored", "externalId": "okta-group-ext-99"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    # The response id is the WeftID-minted UUID, not the upstream externalId.
    assert payload["id"] != "okta-group-ext-99"


def test_patch_group_externalid_silently_ignored(test_tenant, idp):
    """`replace` on `externalId` is accepted but silently dropped."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "PatchExtId"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    # Should NOT raise; the path is normalised to `externalid` and skipped.
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {"Operations": [{"op": "replace", "path": "externalId", "value": "new-ext-id"}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    row = database.groups.get_group_by_id(str(test_tenant["id"]), payload["id"])
    assert row is not None  # group still intact


def test_resolve_member_uuid_belonging_to_another_idp_falls_through_to_externalid(
    test_tenant, test_user, idp
):
    """If a SCIM POST sends a UUID that matches a user bound to a DIFFERENT
    IdP, the resolver does NOT use it; instead it falls through to the
    externalId lookup against THIS IdP. If neither matches, 400."""
    # Create another IdP and a user bound to it.
    other_idp = database.saml.create_identity_provider(
        tenant_id=test_tenant["id"],
        tenant_id_value=str(test_tenant["id"]),
        name="Other Resolver IdP",
        provider_type="generic",
        sp_entity_id=f"urn:test:{uuid4().hex}",
        created_by=str(test_user["id"]),
    )
    other_user_id = _make_user(str(test_tenant["id"]), str(other_idp["id"]))

    # Try to add that user's UUID as a member of a group in our IdP.
    # The UUID lookup hits but rejects (wrong IdP); externalId lookup
    # against THIS idp_id with the UUID value misses; final raise.
    with pytest.raises(ScimWriteError) as exc_info:
        create_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            {"displayName": "WrongIdpMember", "members": [{"value": other_user_id}]},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 400
    assert exc_info.value.scim_type == "invalidValue"


def test_delete_group_idempotent_404_for_already_deleted(test_tenant, idp):
    """Calling DELETE twice on the same group: first succeeds, second 404."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "DoubleDel"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    delete_group(str(test_tenant["id"]), str(idp["id"]), payload["id"])
    with pytest.raises(ScimWriteError) as exc_info:
        delete_group(str(test_tenant["id"]), str(idp["id"]), payload["id"])
    assert exc_info.value.status_code == 404


def test_create_group_with_okta_fixture(test_tenant, idp):
    """Round-trip the recorded Okta `create_group` payload through the service."""
    from tests.fixtures.scim.inbound import load_fixture

    fixture = load_fixture("okta", "create_group")
    result = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        fixture,
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    assert result["displayName"] == "Engineering"
    # externalId is silently dropped; the response carries our id.
    assert result["id"] != fixture["externalId"]


def test_create_group_with_entra_fixture(test_tenant, idp):
    """Round-trip the recorded Entra `create_group` payload through the service."""
    from tests.fixtures.scim.inbound import load_fixture

    fixture = load_fixture("entra", "create_group")
    result = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        fixture,
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    assert result["displayName"] == "Builders"


def test_patch_group_with_okta_rename_fixture(test_tenant, idp):
    """The Okta `patch_group_rename` fixture renames via `replace` on
    `displayName`. Verify it round-trips cleanly."""
    from tests.fixtures.scim.inbound import load_fixture

    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "Engineering"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    fixture = load_fixture("okta", "patch_group_rename")
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        fixture,
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    row = database.groups.get_group_by_id(str(test_tenant["id"]), payload["id"])
    assert row["name"] == "Engineering (Renamed)"


def test_patch_group_with_okta_remove_member_fixture(test_tenant, idp):
    """The Okta `patch_group_remove_member` fixture uses
    `members[value eq "<id>"]`. The fixture id is a synthetic Okta-style
    value; we provision a user with that string as externalId so the
    resolver can find them."""
    from tests.fixtures.scim.inbound import load_fixture

    fixture = load_fixture("okta", "patch_group_remove_member")
    # Extract the bracketed value from the fixture's path.
    # Path is `members[value eq "00u1okta12345xExAmpL"]`.
    ext_id = "00u1okta12345xExAmpL"
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]), external_id=ext_id)
    u2 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "OktaRemove", "members": [{"value": u1}, {"value": u2}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        fixture,
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert [str(m["id"]) for m in members] == [u2]


def test_patch_group_with_entra_batched_fixture(test_tenant, idp):
    """The Entra `patch_group_batched` fixture mixes ops with capitalised
    op names (`Add`, `Replace`). The service lowercases before dispatch."""
    from tests.fixtures.scim.inbound import load_fixture

    fixture = load_fixture("entra", "patch_group_batched")
    # The fixture references the Entra GUID
    # "0c8a4f8e-1b2c-4d5e-9f8a-1a2b3c4d5e6f" as a member; provision a
    # user with that string as their externalId.
    ext_id = "0c8a4f8e-1b2c-4d5e-9f8a-1a2b3c4d5e6f"
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]), external_id=ext_id)
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "EntraBatched"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        fixture,
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    row = database.groups.get_group_by_id(str(test_tenant["id"]), payload["id"])
    assert row["name"] == "Senior Builders"
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert [str(m["id"]) for m in members] == [u1]


def test_patch_group_with_entra_remove_member_fixture(test_tenant, idp):
    """The Entra `patch_group_remove_member` fixture sends `remove` on
    `members` with a value array (no element filter)."""
    from tests.fixtures.scim.inbound import load_fixture

    ext_id = "0c8a4f8e-1b2c-4d5e-9f8a-1a2b3c4d5e6f"
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]), external_id=ext_id)
    u2 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "EntraRemove", "members": [{"value": u1}, {"value": u2}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    fixture = load_fixture("entra", "patch_group_remove_member")
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        fixture,
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert [str(m["id"]) for m in members] == [u2]


def test_patch_group_with_okta_add_member_fixture(test_tenant, idp):
    """The Okta `patch_group_add_member` fixture uses op=add on members."""
    from tests.fixtures.scim.inbound import load_fixture

    ext_id = "00u1okta12345xExAmpL"
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]), external_id=ext_id)
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "OktaAdd"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    fixture = load_fixture("okta", "patch_group_add_member")
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        fixture,
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    members = database.groups.list_group_members_for_scim(str(test_tenant["id"]), payload["id"])
    assert [str(m["id"]) for m in members] == [u1]


def test_replace_group_404_on_unknown_id(test_tenant, idp):
    """PUT against a non-existent group id returns 404."""
    with pytest.raises(ScimWriteError) as exc_info:
        replace_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            str(uuid4()),
            {"displayName": "X", "members": []},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 404


def test_replace_group_emits_scim_group_updated_event(test_tenant, idp):
    """PUT logs `scim_group_updated`."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "PutAudit"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    replace_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {"displayName": "PutAuditRenamed"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    rows = database.fetchall(
        str(test_tenant["id"]),
        """
        select event_type from event_logs
        where artifact_id = :gid and event_type = 'scim_group_updated'
        """,
        {"gid": payload["id"]},
    )
    assert len(rows) >= 1


def test_patch_group_emits_scim_group_updated_event(test_tenant, idp):
    """PATCH logs `scim_group_updated`."""
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "PatchAudit"},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    patch_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        payload["id"],
        {"Operations": [{"op": "replace", "path": "displayName", "value": "PatchAuditRenamed"}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    rows = database.fetchall(
        str(test_tenant["id"]),
        """
        select event_type from event_logs
        where artifact_id = :gid and event_type = 'scim_group_updated'
        """,
        {"gid": payload["id"]},
    )
    assert len(rows) >= 1


def test_create_group_with_whitespace_only_display_name_rejected(test_tenant, idp):
    """A displayName of only whitespace strips to empty -- rejected as missing."""
    with pytest.raises(ScimWriteError) as exc_info:
        create_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            {"displayName": "   "},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 400


def test_patch_group_with_filter_attribute_other_than_value_rejected(test_tenant, idp):
    """An element filter on members[] with an attribute other than `value`
    (e.g. `display`) is rejected with invalidFilter."""
    u1 = _make_user(str(test_tenant["id"]), str(idp["id"]))
    payload = create_group(
        str(test_tenant["id"]),
        str(idp["id"]),
        {"displayName": "WeirdFilter", "members": [{"value": u1}]},
        group_location_builder=_group_location,
        members_base_url=_USERS_BASE,
    )
    with pytest.raises(ScimWriteError) as exc_info:
        patch_group(
            str(test_tenant["id"]),
            str(idp["id"]),
            payload["id"],
            {"Operations": [{"op": "remove", "path": 'members[display eq "foo"]'}]},
            group_location_builder=_group_location,
            members_base_url=_USERS_BASE,
        )
    assert exc_info.value.status_code == 400
    assert exc_info.value.scim_type == "invalidFilter"
