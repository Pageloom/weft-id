"""GitHub Enterprise Cloud quirk-module tests against recorded fixtures.

Exercises `app/services/scim/quirks/github.py` against the synthetic fixtures
in `tests/fixtures/scim/github/fixtures.json`.

Covers:
- User payload pass-through (matches the builder's spec-correct shape).
- Group payload pass-through (GitHub accepts spec-correct group shape).
- PATCH `remove` ops get rewritten to filter-path syntax.
- PATCH `add` ops pass through unchanged.
- `interpret_error` classifies 409 `uniqueness` as permanent.
- `interpret_error` classifies 403 + `x-ratelimit-remaining: 0` as retryable.
- Plain 403 without rate-limit header stays permanent.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from services.scim.payload import build_user_resource
from services.scim.quirks import github

_FIXTURES_PATH = (
    Path(__file__).parent.parent.parent / "fixtures" / "scim" / "github" / "fixtures.json"
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
    transformed = github.transform_user_payload(built)
    assert transformed == expected


def test_group_payload_pass_through(fixtures: dict) -> None:
    expected = fixtures["group_create"]["request"]["body"]
    assert github.transform_group_payload(expected) == expected


def test_patch_add_is_pass_through(fixtures: dict) -> None:
    before = fixtures["group_member_add"]["request"]["ops_before_transform"]
    after = fixtures["group_member_add"]["request"]["ops_after_transform"]
    assert github.transform_patch_ops(before) == after


def test_patch_remove_rewrites_to_filter_path(fixtures: dict) -> None:
    """Single-value remove gets converted to `members[value eq "id"]` syntax."""
    before = fixtures["group_member_remove"]["request"]["ops_before_transform"]
    after = fixtures["group_member_remove"]["request"]["ops_after_transform"]
    assert github.transform_patch_ops(before) == after


def test_patch_remove_multiple_users_emits_one_op_per_user(fixtures: dict) -> None:
    """A remove with two value entries expands to two ops."""
    fx = fixtures["group_member_remove_multiple"]["request"]
    assert github.transform_patch_ops(fx["ops_before_transform"]) == fx["ops_after_transform"]


def test_patch_remove_with_quote_in_id_escapes_it() -> None:
    """Quote characters in user ids must be escaped to keep the filter valid."""
    ops = [
        {
            "op": "remove",
            "path": "members",
            "value": [{"value": 'tricky"id'}],
        }
    ]
    rewritten = github.transform_patch_ops(ops)
    assert rewritten == [{"op": "remove", "path": r'members[value eq "tricky\"id"]'}]


def test_patch_remove_already_filtered_path_passes_through() -> None:
    """Idempotency: if a caller already provided the filter path, leave it alone."""
    ops = [{"op": "remove", "path": 'members[value eq "u-1"]'}]
    assert github.transform_patch_ops(ops) == ops


def test_patch_remove_empty_value_array_passes_through_unchanged() -> None:
    """A remove with an empty value list has no users to rewrite, so the
    transform leaves it alone. GitHub will return 400 on the empty array;
    that's the SP's problem, not ours."""
    ops = [{"op": "remove", "path": "members", "value": []}]
    assert github.transform_patch_ops(ops) == ops


def test_interpret_error_uniqueness_409_is_permanent(fixtures: dict) -> None:
    fx = fixtures["error_uniqueness"]
    response = httpx.Response(fx["response"]["status"], json=fx["response"]["body"])
    retryable, reason = github.interpret_error(response)
    assert retryable is fx["expected_classification"]["retryable"]
    assert fx["expected_classification"]["reason_contains"] in reason


def test_interpret_error_403_rate_limit_is_retryable(fixtures: dict) -> None:
    fx = fixtures["error_rate_limit_via_403"]
    response = httpx.Response(
        fx["response"]["status"],
        headers=fx["response"]["headers"],
        json=fx["response"]["body"],
    )
    retryable, reason = github.interpret_error(response)
    assert retryable is fx["expected_classification"]["retryable"]
    assert fx["expected_classification"]["reason_contains"] in reason


def test_interpret_error_403_without_rate_header_is_permanent(fixtures: dict) -> None:
    fx = fixtures["error_forbidden_no_rate_header"]
    response = httpx.Response(fx["response"]["status"], json=fx["response"]["body"])
    retryable, reason = github.interpret_error(response)
    assert retryable is fx["expected_classification"]["retryable"]
    assert fx["expected_classification"]["reason_contains"] in reason


def test_interpret_error_enriches_reason_with_scim_type() -> None:
    """A 4xx with scimType not already in the reason gets enriched."""
    response = httpx.Response(
        400,
        json={"scimType": "invalidValue", "detail": "bad data"},
    )
    retryable, reason = github.interpret_error(response)
    assert retryable is False
    assert "invalidValue" in reason


def test_interpret_error_5xx_retryable() -> None:
    response = httpx.Response(503)
    retryable, reason = github.interpret_error(response)
    assert retryable is True
    assert "503" in reason


def test_interpret_error_429_retryable() -> None:
    response = httpx.Response(429)
    retryable, reason = github.interpret_error(response)
    assert retryable is True


def test_interpret_error_409_without_uniqueness_falls_through() -> None:
    """A 409 with a different scimType should still be permanent but not labeled
    as `uniqueness`."""
    response = httpx.Response(409, json={"scimType": "mutability", "detail": "cannot mutate"})
    retryable, reason = github.interpret_error(response)
    assert retryable is False
    assert "uniqueness" not in reason
    assert "mutability" in reason


def test_worker_never_calls_put_on_groups() -> None:
    """Pin the contract: GitHub rejects PUT /Groups/<id> with 405. The worker
    today only POSTs and DELETEs Groups -- it never PUTs. If a future change
    introduces a Group PUT path, this test fails loudly so the GitHub quirk
    gets a real PUT-handling transform before regressing GitHub tenants."""
    from services.scim import client as scim_client

    worker_source = Path("app/services/scim/worker.py").read_text()
    # The worker calls scim_client.push_group / delete_group; both go through
    # POST and DELETE respectively. No PUT on Groups is allowed.
    assert "put_group" not in worker_source, (
        "Worker introduced a PUT-on-Groups call path; GitHub quirk must add "
        "a transform to rewrite that into PATCH before this lands."
    )
    # The client module itself must not expose a put_group function until a
    # vendor-aware PUT-on-Groups path exists.
    assert not hasattr(scim_client, "put_group"), (
        "scim_client.put_group introduced; GitHub quirk needs a transform first."
    )
