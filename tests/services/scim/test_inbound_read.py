"""Tests for the inbound SCIM read service projections.

These verify the dict-shape transforms in `services.scim.inbound_read`
without going near FastAPI. DB calls are mocked.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

from services.scim import inbound_read


def _user_row(**overrides):
    base = {
        "id": uuid4(),
        "first_name": "Alice",
        "last_name": "Example",
        "is_inactivated": False,
        "is_anonymized": False,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "saml_idp_id": uuid4(),
        "email": "alice@x.test",
    }
    base.update(overrides)
    return base


def _group_row(**overrides):
    base = {
        "id": uuid4(),
        "name": "Engineers",
        "idp_id": uuid4(),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# list_users
# ---------------------------------------------------------------------------


def test_list_users_builds_resources_with_meta_location():
    rows = [_user_row()]
    with (
        patch("database.users.list_users_for_idp", return_value=rows) as listf,
        patch("database.users.count_users_for_idp", return_value=1),
    ):
        payloads, total = inbound_read.list_users(
            "tenant",
            "idp",
            user_name="alice@x.test",
            start_index=1,
            count=10,
            location_builder=lambda uid: f"https://x/Users/{uid}",
        )
    assert total == 1
    payload = payloads[0]
    assert payload["userName"] == "alice@x.test"
    assert payload["active"] is True
    assert payload["meta"]["location"].startswith("https://x/Users/")
    # The DB layer received the filter kwargs.
    assert listf.call_args.kwargs["user_name"] == "alice@x.test"


def test_list_users_inactivated_user_active_false():
    row = _user_row(is_inactivated=True)
    with (
        patch("database.users.list_users_for_idp", return_value=[row]),
        patch("database.users.count_users_for_idp", return_value=1),
    ):
        payloads, _ = inbound_read.list_users("t", "i")
    assert payloads[0]["active"] is False


def test_list_users_no_name_omits_name_block():
    row = _user_row(first_name=None, last_name=None)
    with (
        patch("database.users.list_users_for_idp", return_value=[row]),
        patch("database.users.count_users_for_idp", return_value=1),
    ):
        payloads, _ = inbound_read.list_users("t", "i")
    assert "name" not in payloads[0]
    assert "displayName" not in payloads[0]


def test_list_users_username_falls_back_to_id_when_no_email():
    row = _user_row(email=None)
    with (
        patch("database.users.list_users_for_idp", return_value=[row]),
        patch("database.users.count_users_for_idp", return_value=1),
    ):
        payloads, _ = inbound_read.list_users("t", "i")
    # SCIM `userName` is required; if no email is available, use the id.
    assert payloads[0]["userName"] == str(row["id"])
    assert "emails" not in payloads[0]


# ---------------------------------------------------------------------------
# get_user
# ---------------------------------------------------------------------------


def test_get_user_returns_none_when_not_bound_to_idp():
    with patch("database.users.get_user_for_idp", return_value=None):
        result = inbound_read.get_user("t", "i", "u", location="https://x/Users/u")
    assert result is None


def test_get_user_includes_emails_when_email_present():
    row = _user_row()
    with patch("database.users.get_user_for_idp", return_value=row):
        payload = inbound_read.get_user("t", "i", str(row["id"]), location="https://x/Users/X")
    assert payload is not None
    assert payload["emails"] == [{"value": "alice@x.test", "type": "work", "primary": True}]


# ---------------------------------------------------------------------------
# list_groups
# ---------------------------------------------------------------------------


def test_list_groups_serialises_members_with_refs():
    grp = _group_row()
    member = {
        "id": uuid4(),
        "first_name": "Bob",
        "last_name": "Builder",
        "email": "bob@x.test",
    }
    with (
        patch("database.groups.list_groups_for_idp", return_value=[grp]),
        patch("database.groups.count_groups_for_idp", return_value=1),
        patch("database.groups.list_group_members_for_scim", return_value=[member]),
    ):
        payloads, total = inbound_read.list_groups(
            "t",
            "i",
            group_location_builder=lambda gid: f"https://x/Groups/{gid}",
            members_base_url="https://x/Users",
        )
    assert total == 1
    payload = payloads[0]
    assert payload["displayName"] == "Engineers"
    assert payload["members"] == [
        {
            "value": str(member["id"]),
            "$ref": f"https://x/Users/{member['id']}",
            "type": "User",
            "display": "Bob Builder",
        }
    ]


def test_list_groups_member_without_name_uses_email_as_display():
    grp = _group_row()
    member = {
        "id": uuid4(),
        "first_name": None,
        "last_name": None,
        "email": "noname@x.test",
    }
    with (
        patch("database.groups.list_groups_for_idp", return_value=[grp]),
        patch("database.groups.count_groups_for_idp", return_value=1),
        patch("database.groups.list_group_members_for_scim", return_value=[member]),
    ):
        payloads, _ = inbound_read.list_groups(
            "t",
            "i",
            group_location_builder=lambda gid: f"x/{gid}",
            members_base_url="x/Users",
        )
    assert payloads[0]["members"][0]["display"] == "noname@x.test"


def test_get_group_returns_none_when_not_bound_to_idp():
    with patch("database.groups.get_group_for_idp", return_value=None):
        assert (
            inbound_read.get_group(
                "t", "i", "g", location="https://x/Groups/g", members_base_url="https://x/Users"
            )
            is None
        )
