"""Atlassian quirk-module tests against recorded fixtures.

Exercises `app/services/scim/quirks/atlassian.py` against the synthetic
fixtures in `tests/fixtures/scim/atlassian/fixtures.json`.

Covers:
- User payload pass-through.
- Group payload trims leading/trailing whitespace in `displayName`.
- PATCH ops with empty `value` arrays are filtered out before send.
- `interpret_error` classifies 404 as permanent-but-not-an-incident
  (resource already absent).
- Other 4xx and 5xx fall through to the generic classifier.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from services.scim.payload import build_user_resource
from services.scim.quirks import atlassian

_FIXTURES_PATH = (
    Path(__file__).parent.parent.parent / "fixtures" / "scim" / "atlassian" / "fixtures.json"
)


@pytest.fixture(scope="module")
def fixtures() -> dict:
    with _FIXTURES_PATH.open() as f:
        return json.load(f)


def test_user_create_payload_matches_builder_output(fixtures: dict) -> None:
    expected = fixtures["user_create"]["request"]["body"]
    built = build_user_resource(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "email": "jdoe@example.com",
            "first_name": "Jane",
            "last_name": "Doe",
        }
    )
    transformed = atlassian.transform_user_payload(built)
    assert transformed == expected


def test_group_payload_trims_display_name(fixtures: dict) -> None:
    before = fixtures["group_create"]["request"]["body_before_transform"]
    after = fixtures["group_create"]["request"]["body_after_transform"]
    assert atlassian.transform_group_payload(before) == after


def test_group_payload_no_whitespace_pass_through() -> None:
    payload = {"displayName": "Engineering", "members": []}
    assert atlassian.transform_group_payload(payload) == payload


def test_group_payload_non_string_display_name_pass_through() -> None:
    payload = {"displayName": None, "members": []}
    assert atlassian.transform_group_payload(payload) == payload


def test_group_payload_non_dict_pass_through() -> None:
    assert atlassian.transform_group_payload("not-a-dict") == "not-a-dict"  # type: ignore[arg-type]


def test_patch_ops_drops_empty_value_arrays(fixtures: dict) -> None:
    fx = fixtures["group_patch_with_empty_value_gets_dropped"]
    assert atlassian.transform_patch_ops(fx["ops_before_transform"]) == fx["ops_after_transform"]


def test_patch_ops_add_with_real_value_passes_through(fixtures: dict) -> None:
    before = fixtures["group_member_add"]["request"]["ops_before_transform"]
    after = fixtures["group_member_add"]["request"]["ops_after_transform"]
    assert atlassian.transform_patch_ops(before) == after


def test_patch_ops_remove_with_real_value_passes_through(fixtures: dict) -> None:
    before = fixtures["group_member_remove"]["request"]["ops_before_transform"]
    after = fixtures["group_member_remove"]["request"]["ops_after_transform"]
    assert atlassian.transform_patch_ops(before) == after


def test_patch_ops_scalar_value_left_alone() -> None:
    """Ops whose `value` is not a list (e.g., active=False) survive the filter."""
    ops = [{"op": "replace", "path": "active", "value": False}]
    assert atlassian.transform_patch_ops(ops) == ops


def test_patch_ops_non_list_input_returned_unchanged() -> None:
    assert atlassian.transform_patch_ops("nope") == "nope"  # type: ignore[arg-type]


def test_interpret_error_404_on_delete_is_absent_already_deprovisioned(fixtures: dict) -> None:
    """Atlassian 404 on DELETE for an already-deprovisioned user is `absent`
    (success-like) under the new generic policy. The fixture predates the
    policy change so we read the response shape from it but assert against
    the current contract directly."""
    fx = fixtures["error_already_deprovisioned"]
    response = httpx.Response(fx["response"]["status"], json=fx["response"]["body"])
    disposition, reason = atlassian.interpret_error(response, "DELETE")
    assert disposition == "absent"
    assert "404" in reason


def test_interpret_error_404_on_put_is_permanent(fixtures: dict) -> None:
    """A 404 on PUT remains permanent; the worker handles stale-id
    invalidation upstream of the client call."""
    fx = fixtures["error_already_deprovisioned"]
    response = httpx.Response(fx["response"]["status"], json=fx["response"]["body"])
    disposition, _reason = atlassian.interpret_error(response, "PUT")
    assert disposition == "permanent"


def test_interpret_error_400_delegates_to_generic(fixtures: dict) -> None:
    fx = fixtures["error_bad_request"]
    response = httpx.Response(fx["response"]["status"], json=fx["response"]["body"])
    disposition, reason = atlassian.interpret_error(response, "POST")
    expected_disposition = (
        "permanent" if not fx["expected_classification"]["retryable"] else "retryable"
    )
    assert disposition == expected_disposition
    assert fx["expected_classification"]["reason_contains"] in reason


def test_interpret_error_429_delegates_to_generic_retryable() -> None:
    response = httpx.Response(429)
    disposition, reason = atlassian.interpret_error(response, "POST")
    assert disposition == "retryable"
    assert "429" in reason


def test_interpret_error_5xx_delegates_to_generic_retryable() -> None:
    response = httpx.Response(502)
    disposition, reason = atlassian.interpret_error(response, "POST")
    assert disposition == "retryable"
    assert "502" in reason


def test_user_payload_pass_through_tolerates_partial_meta() -> None:
    """Atlassian responses sometimes omit `meta.resourceType`; the transform
    must be a no-op on the user payload regardless of meta shape."""
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": "u-1",
        "userName": "j@example.com",
        "active": True,
        "meta": {"created": "2026-05-20T00:00:00Z", "lastModified": "2026-05-20T00:00:00Z"},
    }
    assert atlassian.transform_user_payload(payload) == payload
