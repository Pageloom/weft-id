"""Snapshot tests for SCIM 2.0 Group payload construction."""

from __future__ import annotations

from services.scim.payload import GROUP_SCHEMA, build_group_resource


def test_empty_group_emits_empty_members_array() -> None:
    payload = build_group_resource({"id": "g-1", "name": "Empties"}, members=[])
    assert payload == {
        "schemas": [GROUP_SCHEMA],
        "externalId": "g-1",
        "displayName": "Empties",
        "members": [],
    }


def test_group_with_named_members_includes_display() -> None:
    payload = build_group_resource(
        {"id": "g-2", "name": "Engineers"},
        members=[
            {
                "id": "u-1",
                "email": "a@example.com",
                "first_name": "Alice",
                "last_name": "Anders",
            },
            {
                "id": "u-2",
                "email": "b@example.com",
                "first_name": "Bob",
            },
        ],
    )
    assert payload["members"] == [
        {
            "value": "u-1",
            "$ref": "Users/u-1",
            "display": "Alice Anders",
        },
        {
            "value": "u-2",
            "$ref": "Users/u-2",
            "display": "Bob",
        },
    ]


def test_member_without_name_falls_back_to_email_display() -> None:
    payload = build_group_resource(
        {"id": "g-3", "name": "Anonymous"},
        members=[{"id": "u-3", "email": "anon@example.com"}],
    )
    assert payload["members"][0] == {
        "value": "u-3",
        "$ref": "Users/u-3",
        "display": "anon@example.com",
    }


def test_member_without_name_or_email_omits_display() -> None:
    payload = build_group_resource(
        {"id": "g-4", "name": "MinMembers"},
        members=[{"id": "u-4"}],
    )
    assert payload["members"][0] == {
        "value": "u-4",
        "$ref": "Users/u-4",
    }
    assert "display" not in payload["members"][0]


def test_group_id_is_stringified() -> None:
    payload = build_group_resource({"id": 42, "name": "Numeric"}, members=[{"id": 99}])
    assert payload["externalId"] == "42"
    assert payload["members"][0]["value"] == "99"
    assert payload["members"][0]["$ref"] == "Users/99"


def test_large_group_preserves_member_order() -> None:
    members = [{"id": f"u-{i}", "email": f"u{i}@example.com"} for i in range(100)]
    payload = build_group_resource({"id": "g-big", "name": "Big"}, members=members)
    assert len(payload["members"]) == 100
    assert [m["value"] for m in payload["members"]] == [f"u-{i}" for i in range(100)]
    # First and last spot-check
    assert payload["members"][0]["display"] == "u0@example.com"
    assert payload["members"][-1]["display"] == "u99@example.com"


def test_group_schema_is_exactly_core_group() -> None:
    payload = build_group_resource({"id": "g-x", "name": "S"}, members=[])
    assert payload["schemas"] == [GROUP_SCHEMA]
