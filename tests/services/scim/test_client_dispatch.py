"""Quirk-dispatch wiring tests.

Covers:
- `get_quirk_module` returns the right module per `scim_kind`
- Unknown `scim_kind` logs a warning and falls back to `generic`
- Empty / None `scim_kind` falls back to `generic` (with warning)
- The four stub vendor modules expose the full quirk contract
- The client calls `transform_*` on the resolved module before send
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest
from services.scim import client as scim_client
from services.scim.quirks import (
    atlassian,
    generic,
    get_quirk_module,
    github,
    gitlab,
    slack,
)

_QUIRK_FUNCS = [
    "transform_user_payload",
    "transform_group_payload",
    "transform_patch_ops",
    "interpret_error",
]


class _FakeClient:
    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        return self._response

    def close(self) -> None:  # pragma: no cover
        pass


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scim_client.time, "sleep", lambda _s: None)


def test_known_kinds_resolve_to_their_modules() -> None:
    assert get_quirk_module("generic") is generic
    assert get_quirk_module("slack") is slack
    assert get_quirk_module("github") is github
    assert get_quirk_module("atlassian") is atlassian
    assert get_quirk_module("gitlab") is gitlab


def test_unknown_kind_logs_warning_and_returns_generic(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="services.scim.quirks"):
        module = get_quirk_module("made-up-vendor")
    assert module is generic
    assert any("made-up-vendor" in record.getMessage() for record in caplog.records)


def test_none_kind_logs_warning_and_returns_generic(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="services.scim.quirks"):
        module = get_quirk_module(None)
    assert module is generic
    assert any(caplog.records)


def test_empty_string_kind_returns_generic_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="services.scim.quirks"):
        module = get_quirk_module("")
    assert module is generic
    assert any(caplog.records)


@pytest.mark.parametrize(
    "module",
    [generic, slack, github, atlassian, gitlab],
    ids=["generic", "slack", "github", "atlassian", "gitlab"],
)
def test_quirk_module_implements_full_contract(module: Any) -> None:
    for fn in _QUIRK_FUNCS:
        assert callable(getattr(module, fn, None)), f"{module.__name__} missing {fn}"


def test_generic_interpret_error_classifies_5xx_retryable() -> None:
    retryable, reason = generic.interpret_error(httpx.Response(503))
    assert retryable is True
    assert "503" in reason


def test_generic_interpret_error_classifies_4xx_permanent() -> None:
    retryable, reason = generic.interpret_error(httpx.Response(400))
    assert retryable is False
    assert "400" in reason


def test_generic_interpret_error_classifies_429_retryable() -> None:
    retryable, reason = generic.interpret_error(httpx.Response(429))
    assert retryable is True
    assert "429" in reason


def test_generic_transform_user_payload_is_identity() -> None:
    """An SP with `scim_kind='generic'` produces spec-correct payloads
    unchanged (acceptance criterion for the generic path)."""
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": "u-1",
        "userName": "j@example.com",
        "active": True,
        "emails": [{"value": "j@example.com", "primary": True, "type": "work"}],
    }
    assert generic.transform_user_payload(payload) == payload


def test_generic_transform_group_payload_is_identity() -> None:
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "externalId": "g-1",
        "displayName": "Engineers",
        "members": [{"value": "u-1", "$ref": "Users/u-1", "display": "Jane"}],
    }
    assert generic.transform_group_payload(payload) == payload


def test_generic_transform_patch_ops_is_identity() -> None:
    ops = [
        {"op": "add", "path": "members", "value": [{"value": "u-1"}]},
        {"op": "remove", "path": "members", "value": [{"value": "u-2"}]},
    ]
    assert generic.transform_patch_ops(ops) == ops


def test_client_invokes_quirk_transform_for_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`push_user` should call `transform_user_payload` on the chosen module."""
    fake = _FakeClient(httpx.Response(201, json={"id": "ext-1"}))
    captured: dict[str, Any] = {}

    def fake_transform(payload: dict) -> dict:
        captured["payload"] = payload
        return {"externalId": "rewritten"}

    monkeypatch.setattr(slack, "transform_user_payload", fake_transform)

    scim_client.push_user(
        {
            "scim_target_url": "https://example.test/scim/v2",
            "scim_kind": "slack",
        },
        {"externalId": "u-1"},
        token="t",
        http_client=fake,
    )

    assert captured["payload"] == {"externalId": "u-1"}
    assert fake.calls[0]["kwargs"]["json"] == {"externalId": "rewritten"}


def test_client_invokes_quirk_transform_for_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient(httpx.Response(201, json={"id": "ext-g"}))
    captured: dict[str, Any] = {}

    def fake_transform(payload: dict) -> dict:
        captured["payload"] = payload
        return {"displayName": "rewritten"}

    monkeypatch.setattr(github, "transform_group_payload", fake_transform)

    scim_client.push_group(
        {
            "scim_target_url": "https://example.test/scim/v2",
            "scim_kind": "github",
        },
        {"displayName": "Engineers"},
        token="t",
        http_client=fake,
    )

    assert captured["payload"] == {"displayName": "Engineers"}
    assert fake.calls[0]["kwargs"]["json"] == {"displayName": "rewritten"}


def test_unknown_kind_routes_through_generic_at_the_client(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """End-to-end: unknown kind logs and uses generic's interpret_error."""
    fake = _FakeClient(httpx.Response(503))
    with caplog.at_level(logging.WARNING, logger="services.scim.quirks"):
        result = scim_client.push_user(
            {
                "scim_target_url": "https://example.test/scim/v2",
                "scim_kind": "completely-made-up",
            },
            {"externalId": "u-1"},
            token="t",
            http_client=fake,
        )
    assert any(caplog.records)
    # Three attempts, all 503 -> retryable
    assert result.status == "retryable"
    assert result.http_status == 503


def test_quirk_interpret_error_can_downgrade_5xx_to_permanent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A quirk module returning (False, ...) on a 503 makes it permanent."""
    fake = _FakeClient(httpx.Response(503))

    def grumpy_interpret(response: httpx.Response) -> tuple[bool, str]:
        return False, "vendor says: never retry 503"

    monkeypatch.setattr(atlassian, "interpret_error", grumpy_interpret)

    result = scim_client.push_user(
        {
            "scim_target_url": "https://example.test/scim/v2",
            "scim_kind": "atlassian",
        },
        {"externalId": "u-1"},
        token="t",
        http_client=fake,
    )
    assert result.status == "permanent"
    assert result.reason == "vendor says: never retry 503"
    # Single attempt -- permanent short-circuits the retry loop.
    assert len(fake.calls) == 1
