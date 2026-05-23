"""Transport-level retry tests for the SCIM client.

Covers:
- 5xx retried, then succeeds
- Network error retried, then succeeds
- 4xx returns immediately (no retry)
- 429 retried (rate-limit handling lives in the generic quirk)
- All attempts exhausted -> retryable result with last error captured
- 201 with id body -> scim_id parsed out
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import httpx
import pytest
from services.scim import client as scim_client


class _FakeClient:
    """Minimal stand-in for httpx.Client.

    Yields successive responses (or raises successive exceptions) from a
    queue. Each entry is either an `httpx.Response` to return or a
    `BaseException` to raise.
    """

    def __init__(self, results: Iterable[Any]) -> None:
        self._results = list(results)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        if not self._results:
            raise AssertionError("FakeClient exhausted")
        item = self._results.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def close(self) -> None:  # pragma: no cover - never called by tests
        pass


def _resp(status: int, body: dict | None = None) -> httpx.Response:
    if body is None:
        return httpx.Response(status)
    return httpx.Response(status, json=body)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace `time.sleep` so the test suite doesn't actually wait 5 seconds."""
    monkeypatch.setattr(scim_client.time, "sleep", lambda _s: None)


SP = {
    "scim_target_url": "https://example.test/scim/v2",
    "scim_kind": "generic",
}


def test_2xx_first_try_returns_success() -> None:
    fake = _FakeClient([_resp(201, {"id": "ext-1"})])
    result = scim_client.push_user(
        SP,
        {"externalId": "u-1"},
        token="t",
        http_client=fake,
    )
    assert result.status == "success"
    assert result.http_status == 201
    assert result.scim_id == "ext-1"
    assert len(fake.calls) == 1


def test_5xx_then_success_after_retry() -> None:
    fake = _FakeClient(
        [
            _resp(500, {"detail": "boom"}),
            _resp(201, {"id": "ext-2"}),
        ]
    )
    result = scim_client.push_user(SP, {"externalId": "u-1"}, token="t", http_client=fake)
    assert result.status == "success"
    assert result.scim_id == "ext-2"
    assert len(fake.calls) == 2


def test_network_error_then_success() -> None:
    fake = _FakeClient(
        [
            httpx.ConnectError("connection refused"),
            _resp(200, {"id": "ext-3"}),
        ]
    )
    result = scim_client.push_group(SP, {"displayName": "g"}, token="t", http_client=fake)
    assert result.status == "success"
    assert len(fake.calls) == 2


def test_4xx_returns_immediately_without_retry() -> None:
    fake = _FakeClient([_resp(400, {"detail": "bad"})])
    result = scim_client.push_user(SP, {"externalId": "u-1"}, token="t", http_client=fake)
    assert result.status == "permanent"
    assert result.http_status == 400
    assert result.reason and "400" in result.reason
    assert len(fake.calls) == 1


def test_404_on_delete_is_absent_no_retry() -> None:
    """404 on DELETE: the resource is already gone -- treated as success-like
    `absent` so deprovisioning rows the receiver never saw drain cleanly."""
    fake = _FakeClient([_resp(404)])
    result = scim_client.delete_user(SP, "ext-x", token="t", http_client=fake)
    assert result.status == "absent"
    assert result.http_status == 404
    assert result.reason and "already_absent" in result.reason
    assert len(fake.calls) == 1


def test_404_on_put_is_permanent_no_retry() -> None:
    """404 on PUT remains permanent at the client layer; worker handles
    stale-id invalidation before the call returns to the caller."""
    fake = _FakeClient([_resp(404)])
    result = scim_client.put_user(SP, "ext-x", {"externalId": "u-1"}, token="t", http_client=fake)
    assert result.status == "permanent"
    assert result.http_status == 404
    assert len(fake.calls) == 1


def test_429_is_retryable() -> None:
    fake = _FakeClient(
        [
            _resp(429, {"detail": "slow down"}),
            _resp(200, {"id": "ok"}),
        ]
    )
    result = scim_client.push_user(SP, {"externalId": "u-1"}, token="t", http_client=fake)
    assert result.status == "success"
    assert len(fake.calls) == 2


def test_all_attempts_5xx_returns_retryable() -> None:
    fake = _FakeClient(
        [
            _resp(503),
            _resp(502),
            _resp(500, {"detail": "still bad"}),
        ]
    )
    result = scim_client.push_user(SP, {"externalId": "u-1"}, token="t", http_client=fake)
    assert result.status == "retryable"
    assert result.http_status == 500
    assert result.reason and "500" in result.reason
    assert len(fake.calls) == 3


def test_all_attempts_network_error_returns_retryable_with_no_status() -> None:
    fake = _FakeClient(
        [
            httpx.ReadTimeout("read timeout"),
            httpx.ConnectError("connection error"),
            httpx.ReadTimeout("read timeout"),
        ]
    )
    result = scim_client.push_group(SP, {"displayName": "g"}, token="t", http_client=fake)
    assert result.status == "retryable"
    assert result.http_status is None
    assert result.reason and "network_error" in result.reason
    assert len(fake.calls) == 3


def test_max_three_attempts_does_not_overrun() -> None:
    fake = _FakeClient(
        [
            _resp(500),
            _resp(500),
            _resp(500),
            _resp(200),  # never reached
        ]
    )
    result = scim_client.push_user(SP, {"externalId": "u-1"}, token="t", http_client=fake)
    assert result.status == "retryable"
    assert len(fake.calls) == 3  # exactly 3, not 4


def test_request_carries_bearer_token_and_scim_content_type() -> None:
    fake = _FakeClient([_resp(201, {"id": "x"})])
    scim_client.push_user(SP, {"externalId": "u-1"}, token="secret-token", http_client=fake)
    headers = fake.calls[0]["kwargs"]["headers"]
    assert headers["Authorization"] == "Bearer secret-token"
    assert headers["Content-Type"] == "application/scim+json"
    assert headers["Accept"] == "application/scim+json"


def test_target_url_joins_correctly_with_trailing_slash() -> None:
    fake = _FakeClient([_resp(201, {"id": "x"})])
    sp = {
        "scim_target_url": "https://example.test/scim/v2/",
        "scim_kind": "generic",
    }
    scim_client.push_user(sp, {"externalId": "u-1"}, token="t", http_client=fake)
    assert fake.calls[0]["url"] == "https://example.test/scim/v2/Users"


def test_target_url_joins_correctly_without_trailing_slash() -> None:
    fake = _FakeClient([_resp(201, {"id": "x"})])
    sp = {
        "scim_target_url": "https://example.test/scim/v2",
        "scim_kind": "generic",
    }
    scim_client.push_group(sp, {"displayName": "g"}, token="t", http_client=fake)
    assert fake.calls[0]["url"] == "https://example.test/scim/v2/Groups"


def test_delete_user_url_includes_external_id() -> None:
    fake = _FakeClient([_resp(204)])
    scim_client.delete_user(SP, "ext-42", token="t", http_client=fake)
    assert fake.calls[0]["method"] == "DELETE"
    assert fake.calls[0]["url"].endswith("/Users/ext-42")


def test_delete_group_url_includes_external_id() -> None:
    fake = _FakeClient([_resp(204)])
    scim_client.delete_group(SP, "ext-g-7", token="t", http_client=fake)
    assert fake.calls[0]["method"] == "DELETE"
    assert fake.calls[0]["url"].endswith("/Groups/ext-g-7")


def test_204_no_content_succeeds_with_none_scim_id() -> None:
    fake = _FakeClient([_resp(204)])
    result = scim_client.delete_user(SP, "ext-42", token="t", http_client=fake)
    assert result.status == "success"
    assert result.http_status == 204
    assert result.scim_id is None


def test_success_response_without_json_body_does_not_crash() -> None:
    fake = _FakeClient([httpx.Response(200, text="not json {{{")])
    result = scim_client.push_user(SP, {"externalId": "u-1"}, token="t", http_client=fake)
    assert result.status == "success"
    assert result.scim_id is None


def test_success_response_with_non_string_id_yields_none() -> None:
    """If a SP returns `"id": 12345` (non-spec), we don't crash, we just skip it."""
    fake = _FakeClient([_resp(200, {"id": 12345})])
    result = scim_client.push_user(SP, {"externalId": "u-1"}, token="t", http_client=fake)
    assert result.status == "success"
    assert result.scim_id is None


def test_success_response_with_non_dict_json_body_yields_none() -> None:
    """If a SP returns a JSON array (non-spec), we don't crash, just skip the id."""
    fake = _FakeClient([httpx.Response(200, json=["not", "a", "dict"])])
    result = scim_client.push_user(SP, {"externalId": "u-1"}, token="t", http_client=fake)
    assert result.status == "success"
    assert result.scim_id is None
