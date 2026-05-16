"""Snapshot tests for SCIM 2.0 User payload construction.

Asserts spec-correct shape (RFC 7643). The dict-equality checks here are the
contract: any payload change that breaks them is a behavior change a quirk
module (or a future explicit decision) needs to absorb.
"""

from __future__ import annotations

from services.scim.payload import (
    ENTERPRISE_USER_SCHEMA,
    USER_SCHEMA,
    build_user_resource,
)


def test_minimal_user_active_emits_required_fields_only() -> None:
    payload = build_user_resource({"id": "u-1", "email": "alice@example.com"})
    assert payload == {
        "schemas": [USER_SCHEMA],
        "externalId": "u-1",
        "userName": "alice@example.com",
        "active": True,
        "emails": [{"value": "alice@example.com", "primary": True, "type": "work"}],
    }


def test_user_with_first_and_last_name_emits_name_block() -> None:
    payload = build_user_resource(
        {
            "id": "u-2",
            "email": "bob@example.com",
            "first_name": "Bob",
            "last_name": "Builder",
        }
    )
    assert payload["name"] == {
        "givenName": "Bob",
        "familyName": "Builder",
        "formatted": "Bob Builder",
    }
    assert payload["displayName"] == "Bob Builder"


def test_user_with_only_first_name_skips_family_name() -> None:
    payload = build_user_resource({"id": "u-3", "email": "c@example.com", "first_name": "Cee"})
    assert payload["name"] == {"givenName": "Cee", "formatted": "Cee"}
    assert "familyName" not in payload["name"]
    assert payload["displayName"] == "Cee"


def test_user_with_only_last_name_skips_given_name() -> None:
    payload = build_user_resource({"id": "u-4", "email": "d@example.com", "last_name": "Solo"})
    assert payload["name"] == {"familyName": "Solo", "formatted": "Solo"}
    assert "givenName" not in payload["name"]


def test_user_with_no_name_fields_omits_name_block() -> None:
    payload = build_user_resource({"id": "u-5", "email": "e@example.com"})
    assert "name" not in payload
    assert "displayName" not in payload


def test_inactivated_user_emits_active_false() -> None:
    payload = build_user_resource(
        {
            "id": "u-6",
            "email": "inactive@example.com",
            "is_inactivated": True,
        }
    )
    assert payload["active"] is False


def test_explicit_active_flag_is_honored_when_no_inactivated() -> None:
    payload = build_user_resource({"id": "u-7", "email": "x@example.com", "active": False})
    assert payload["active"] is False


def test_is_inactivated_takes_precedence_over_active() -> None:
    """If both fields are present, `is_inactivated` wins (it's authoritative)."""
    payload = build_user_resource(
        {
            "id": "u-8",
            "email": "y@example.com",
            "is_inactivated": False,
            "active": False,
        }
    )
    assert payload["active"] is True


def test_default_active_when_no_status_fields() -> None:
    payload = build_user_resource({"id": "u-9", "email": "z@example.com"})
    assert payload["active"] is True


def test_enterprise_extension_emitted_when_provided() -> None:
    payload = build_user_resource(
        {"id": "u-10", "email": "ent@example.com"},
        enterprise={
            "employeeNumber": "E-1234",
            "department": "Engineering",
            "manager": {"value": "u-99", "displayName": "Mgr"},
        },
    )
    assert ENTERPRISE_USER_SCHEMA in payload["schemas"]
    assert payload[ENTERPRISE_USER_SCHEMA] == {
        "employeeNumber": "E-1234",
        "department": "Engineering",
        "manager": {"value": "u-99", "displayName": "Mgr"},
    }


def test_enterprise_extension_omitted_when_none() -> None:
    payload = build_user_resource({"id": "u-11", "email": "ent2@example.com"})
    assert ENTERPRISE_USER_SCHEMA not in payload["schemas"]
    assert ENTERPRISE_USER_SCHEMA not in payload


def test_enterprise_extension_omitted_when_empty_dict() -> None:
    payload = build_user_resource(
        {"id": "u-12", "email": "ent3@example.com"},
        enterprise={},
    )
    assert ENTERPRISE_USER_SCHEMA not in payload["schemas"]
    assert ENTERPRISE_USER_SCHEMA not in payload


def test_user_id_is_stringified() -> None:
    """UUID-shaped ids work even when the caller passes them as objects."""
    payload = build_user_resource({"id": 12345, "email": "n@example.com"})
    assert payload["externalId"] == "12345"


def test_emails_array_includes_primary_and_type() -> None:
    payload = build_user_resource({"id": "u-13", "email": "primary@example.com"})
    assert payload["emails"] == [{"value": "primary@example.com", "primary": True, "type": "work"}]


def test_full_active_user_with_enterprise_extension_snapshot() -> None:
    payload = build_user_resource(
        {
            "id": "u-full",
            "email": "full@example.com",
            "first_name": "Full",
            "last_name": "Example",
            "is_inactivated": False,
        },
        enterprise={"department": "Sales"},
    )
    assert payload == {
        "schemas": [USER_SCHEMA, ENTERPRISE_USER_SCHEMA],
        "externalId": "u-full",
        "userName": "full@example.com",
        "active": True,
        "emails": [{"value": "full@example.com", "primary": True, "type": "work"}],
        "name": {
            "givenName": "Full",
            "familyName": "Example",
            "formatted": "Full Example",
        },
        "displayName": "Full Example",
        ENTERPRISE_USER_SCHEMA: {"department": "Sales"},
    }
