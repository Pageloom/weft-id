"""GitLab quirk-module tests against recorded fixtures.

Exercises `app/services/scim/quirks/gitlab.py` against the synthetic fixtures
in `tests/fixtures/scim/gitlab/fixtures.json`.

Covers:
- User payload transform asserts `externalId` is set (SAML NameID coupling).
- Group payload pass-through.
- PATCH ops pass-through (no GitLab-specific rewriting needed).
- `interpret_error` enriches 502 with `proxy_error` label.
- `interpret_error` classifies 403 license errors as permanent.
- Plain 403 and 5xx fall through to the generic classifier.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from services.scim.payload import build_user_resource
from services.scim.quirks import gitlab

_FIXTURES_PATH = (
    Path(__file__).parent.parent.parent / "fixtures" / "scim" / "gitlab" / "fixtures.json"
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
    transformed = gitlab.transform_user_payload(built)
    assert transformed == expected


def test_user_payload_missing_external_id_raises() -> None:
    """GitLab requires externalId; we surface that as a KeyError locally."""
    payload = {"userName": "x@example.com", "emails": []}
    with pytest.raises(KeyError):
        gitlab.transform_user_payload(payload)


def test_user_payload_empty_external_id_raises() -> None:
    payload = {"externalId": "", "userName": "x@example.com"}
    with pytest.raises(KeyError):
        gitlab.transform_user_payload(payload)


def test_user_payload_non_dict_pass_through() -> None:
    assert gitlab.transform_user_payload("not-a-dict") == "not-a-dict"  # type: ignore[arg-type]


def test_group_create_pass_through(fixtures: dict) -> None:
    expected = fixtures["group_create"]["request"]["body"]
    assert gitlab.transform_group_payload(expected) == expected


def test_patch_add_pass_through(fixtures: dict) -> None:
    before = fixtures["group_member_add"]["request"]["ops_before_transform"]
    after = fixtures["group_member_add"]["request"]["ops_after_transform"]
    assert gitlab.transform_patch_ops(before) == after


def test_patch_remove_pass_through(fixtures: dict) -> None:
    before = fixtures["group_member_remove"]["request"]["ops_before_transform"]
    after = fixtures["group_member_remove"]["request"]["ops_after_transform"]
    assert gitlab.transform_patch_ops(before) == after


def test_interpret_error_502_is_retryable_with_proxy_label(fixtures: dict) -> None:
    fx = fixtures["error_proxy_502"]
    response = httpx.Response(fx["response"]["status"], text=fx["response"]["body"])
    retryable, reason = gitlab.interpret_error(response)
    assert retryable is fx["expected_classification"]["retryable"]
    assert fx["expected_classification"]["reason_contains"] in reason


def test_interpret_error_license_403_is_permanent(fixtures: dict) -> None:
    fx = fixtures["error_license"]
    response = httpx.Response(fx["response"]["status"], json=fx["response"]["body"])
    retryable, reason = gitlab.interpret_error(response)
    assert retryable is fx["expected_classification"]["retryable"]
    assert fx["expected_classification"]["reason_contains"] in reason


def test_interpret_error_generic_403_delegates_to_generic(fixtures: dict) -> None:
    fx = fixtures["error_generic_403"]
    response = httpx.Response(fx["response"]["status"], json=fx["response"]["body"])
    retryable, reason = gitlab.interpret_error(response)
    assert retryable is fx["expected_classification"]["retryable"]
    assert fx["expected_classification"]["reason_contains"] in reason


def test_interpret_error_500_delegates_to_generic(fixtures: dict) -> None:
    fx = fixtures["error_server_500"]
    response = httpx.Response(fx["response"]["status"], json=fx["response"]["body"])
    retryable, reason = gitlab.interpret_error(response)
    assert retryable is True
    assert "500" in reason


def test_interpret_error_429_delegates_to_generic_retryable() -> None:
    response = httpx.Response(429)
    retryable, reason = gitlab.interpret_error(response)
    assert retryable is True
    assert "429" in reason


def test_interpret_error_400_delegates_to_generic_permanent() -> None:
    response = httpx.Response(400)
    retryable, reason = gitlab.interpret_error(response)
    assert retryable is False
    assert "400" in reason


def test_interpret_error_403_with_non_string_detail_falls_through() -> None:
    """A 403 body whose detail isn't a string shouldn't crash the lookup."""
    response = httpx.Response(403, json={"detail": {"nested": "thing"}})
    retryable, reason = gitlab.interpret_error(response)
    assert retryable is False
    assert "403" in reason
