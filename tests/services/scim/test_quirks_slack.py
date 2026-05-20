"""Slack quirk-module tests against recorded fixtures.

Exercises `app/services/scim/quirks/slack.py` against the synthetic fixtures
in `tests/fixtures/scim/slack/fixtures.json`. The fixtures are the contract:
any quirk behavior change that breaks them must update the fixture too.

Covers:
- User payload pass-through (matches the builder's spec-correct shape).
- Group payload transform strips `$ref` from member entries.
- PATCH ops transform strips `$ref` from value entries.
- `interpret_error` surfaces `Retry-After` for 429.
- 5xx falls through to the generic classifier.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from services.scim.payload import build_group_resource, build_user_resource
from services.scim.quirks import slack

_FIXTURES_PATH = (
    Path(__file__).parent.parent.parent / "fixtures" / "scim" / "slack" / "fixtures.json"
)


@pytest.fixture(scope="module")
def fixtures() -> dict:
    with _FIXTURES_PATH.open() as f:
        return json.load(f)


def test_user_create_payload_matches_builder_output(fixtures: dict) -> None:
    """The builder output for a fully-populated user matches the fixture."""
    expected = fixtures["user_create"]["request"]["body"]
    built = build_user_resource(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "email": "jdoe@example.com",
            "first_name": "Jane",
            "last_name": "Doe",
        }
    )
    transformed = slack.transform_user_payload(built)
    assert transformed == expected


def test_user_update_payload_for_inactivated_user(fixtures: dict) -> None:
    expected = fixtures["user_update"]["request"]["body"]
    built = build_user_resource(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "email": "jdoe@example.com",
            "first_name": "Jane",
            "last_name": "Doe",
            "is_inactivated": True,
        }
    )
    transformed = slack.transform_user_payload(built)
    assert transformed == expected


def test_group_create_drops_ref_from_members(fixtures: dict) -> None:
    """Slack transform must strip `$ref` from each member entry."""
    before = fixtures["group_create"]["request"]["body_before_transform"]
    after = fixtures["group_create"]["request"]["body_after_transform"]
    assert slack.transform_group_payload(before) == after


def test_group_create_from_builder_matches_after_transform(fixtures: dict) -> None:
    """Building from the payload module then applying Slack transform yields
    the expected wire shape."""
    after = fixtures["group_create"]["request"]["body_after_transform"]
    built = build_group_resource(
        {"id": "22222222-2222-2222-2222-222222222222", "name": "Engineering"},
        [
            {
                "id": "W01ABC23DEF",
                "first_name": "Jane",
                "last_name": "Doe",
            }
        ],
    )
    transformed = slack.transform_group_payload(built)
    # The builder emits $ref; transform strips it. After transform the
    # member entries should not contain $ref.
    for member in transformed["members"]:
        assert "$ref" not in member
    # And the result matches the recorded after-transform fixture (modulo
    # the user id we use here vs the fixture's pre-recorded one).
    assert transformed["displayName"] == after["displayName"]
    assert transformed["externalId"] == after["externalId"]


def test_group_payload_without_members_is_unchanged() -> None:
    payload = {"displayName": "Empty", "schemas": ["urn:..."]}
    assert slack.transform_group_payload(payload) == payload


def test_group_payload_with_non_dict_members_is_unchanged() -> None:
    """Defensive: members must be a list of dicts; bogus input passes through."""
    payload = {"displayName": "X", "members": "not-a-list"}
    assert slack.transform_group_payload(payload) == payload


def test_patch_ops_add_strips_ref_from_value_entries(fixtures: dict) -> None:
    before = fixtures["group_member_add"]["request"]["ops_before_transform"]
    after = fixtures["group_member_add"]["request"]["ops_after_transform"]
    assert slack.transform_patch_ops(before) == after


def test_patch_ops_remove_already_lacks_ref_passes_through(fixtures: dict) -> None:
    before = fixtures["group_member_remove"]["request"]["ops_before_transform"]
    after = fixtures["group_member_remove"]["request"]["ops_after_transform"]
    assert slack.transform_patch_ops(before) == after


def test_patch_ops_non_list_value_is_left_alone() -> None:
    ops = [{"op": "replace", "path": "active", "value": False}]
    assert slack.transform_patch_ops(ops) == ops


def test_interpret_error_429_surfaces_retry_after(fixtures: dict) -> None:
    fx = fixtures["error_rate_limited"]
    response = httpx.Response(
        fx["response"]["status"],
        headers=fx["response"]["headers"],
        json=fx["response"]["body"],
    )
    retryable, reason = slack.interpret_error(response)
    assert retryable is fx["expected_classification"]["retryable"]
    assert fx["expected_classification"]["reason_contains"] in reason


def test_interpret_error_429_without_retry_after_still_retryable() -> None:
    response = httpx.Response(429)
    retryable, reason = slack.interpret_error(response)
    assert retryable is True
    assert "429" in reason


def test_interpret_error_5xx_delegates_to_generic(fixtures: dict) -> None:
    fx = fixtures["error_server_error"]
    response = httpx.Response(fx["response"]["status"], json=fx["response"]["body"])
    retryable, reason = slack.interpret_error(response)
    assert retryable is True
    assert "503" in reason


def test_interpret_error_4xx_delegates_to_generic_permanent() -> None:
    response = httpx.Response(400)
    retryable, reason = slack.interpret_error(response)
    assert retryable is False
    assert "400" in reason


def test_user_payload_uses_only_core_user_urn_no_slack_extension() -> None:
    """Slack accepts the spec-correct core URN; no Slack-specific extension URN
    should be added by the transform."""
    built = build_user_resource(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "email": "jdoe@example.com",
            "first_name": "Jane",
            "last_name": "Doe",
        }
    )
    transformed = slack.transform_user_payload(built)
    assert transformed["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    for key in transformed:
        assert not key.startswith("urn:scim:schemas:extension:slack:"), (
            f"Slack transform must not synthesize a Slack extension URN; found {key!r}"
        )
