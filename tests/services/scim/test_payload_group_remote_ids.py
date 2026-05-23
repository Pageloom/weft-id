"""Group payload builder behavior under the remote-id mapping contract.

Covers the changes introduced by the `sp_scim_remote_ids` iteration:

- When the worker provides a `remote_id_lookup`, the builder uses the
  receiver's canonical id for `members[].value` and `$ref`.
- Members without a mapping are SKIPPED (not pushed with a WeftID UUID
  the receiver cannot resolve) and a warning is logged.
- An empty `remote_id_lookup={}` is the "first-push" case for a group
  whose members haven't been POSTed yet: members are all skipped, group
  payload is emitted with an empty `members` array (spec-permitted).
- When the lookup is `None`, the builder falls back to the pre-mapping
  behavior (uses WeftID UUIDs) -- preserves backwards compatibility
  with existing tests that don't pass a lookup.
"""

from __future__ import annotations

import logging

from services.scim.payload import build_group_resource

GROUP = {"id": "g-1", "name": "Engineers"}
MEMBERS = [
    {"id": "user-a", "email": "a@example.com", "first_name": "A", "last_name": "Alpha"},
    {"id": "user-b", "email": "b@example.com", "first_name": "B", "last_name": "Beta"},
]


def test_lookup_none_uses_weftid_ids_as_before() -> None:
    """Backwards-compat path: no lookup -> use WeftID UUIDs."""
    payload = build_group_resource(GROUP, MEMBERS)
    assert [m["value"] for m in payload["members"]] == ["user-a", "user-b"]
    assert [m["$ref"] for m in payload["members"]] == ["Users/user-a", "Users/user-b"]


def test_lookup_with_all_members_uses_remote_ids() -> None:
    """Happy path: every member has a mapping -> payload uses remote_ids."""
    payload = build_group_resource(
        GROUP,
        MEMBERS,
        remote_id_lookup={"user-a": "ra", "user-b": "rb"},
    )
    assert [m["value"] for m in payload["members"]] == ["ra", "rb"]
    assert [m["$ref"] for m in payload["members"]] == ["Users/ra", "Users/rb"]


def test_lookup_with_missing_members_skips_and_warns(caplog) -> None:
    """A member with no mapping is skipped and a warning is logged.

    This is the bug fix: emitting a WeftID UUID where the receiver
    expects its own id silently drops the member at the receiver's
    resolver. Skipping is the safe alternative -- the next push (after
    the user is POSTed and mapped) will include the member.
    """
    with caplog.at_level(logging.WARNING, logger="services.scim.payload"):
        payload = build_group_resource(
            GROUP,
            MEMBERS,
            remote_id_lookup={"user-a": "ra"},  # user-b missing
        )
    assert [m["value"] for m in payload["members"]] == ["ra"]
    # Warning mentions both the group and the skipped user, with a hint
    # about the cause so admins can reason about it from the log.
    skipped_msgs = [r.message for r in caplog.records if "user-b" in r.message]
    assert skipped_msgs, "expected a warning naming the skipped member"
    assert "no remote_id mapping" in skipped_msgs[0]


def test_empty_lookup_skips_all_members(caplog) -> None:
    """First-push-of-everything case: no mappings yet -> empty members."""
    with caplog.at_level(logging.WARNING, logger="services.scim.payload"):
        payload = build_group_resource(GROUP, MEMBERS, remote_id_lookup={})
    assert payload["members"] == []
    # One warning per skipped member.
    skip_warnings = [r for r in caplog.records if "no remote_id mapping" in r.message]
    assert len(skip_warnings) == 2


def test_payload_shape_unchanged_aside_from_member_ids() -> None:
    """The Group resource envelope is the same regardless of lookup."""
    payload = build_group_resource(
        GROUP,
        MEMBERS,
        remote_id_lookup={"user-a": "ra", "user-b": "rb"},
    )
    assert payload["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    assert payload["externalId"] == "g-1"
    assert payload["displayName"] == "Engineers"


def test_member_display_unaffected_by_mapping() -> None:
    """Display strings are derived from the WeftID member dict, not the
    remote_id. Receivers that show a display name see "First Last"
    regardless of which id the worker references."""
    payload = build_group_resource(
        GROUP,
        MEMBERS,
        remote_id_lookup={"user-a": "ra", "user-b": "rb"},
    )
    displays = [m.get("display") for m in payload["members"]]
    assert displays == ["A Alpha", "B Beta"]
