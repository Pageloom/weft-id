"""Tests for `services.scim._sanitise.redact_bearer`.

The sanitiser sits between quirk-module `interpret_error` output and the
sync-log / queue `error` columns. Any echoed `Authorization: Bearer ...`
header in a downstream SP's response body must be redacted before we
write it to our own logs.
"""

from __future__ import annotations

import httpx
from services.scim import client as scim_client
from services.scim._sanitise import redact_bearer


def test_redact_bearer_strips_authorization_header_form():
    """Canonical `Authorization: Bearer <token>` is fully redacted."""
    text = "permanent 401: Authorization: Bearer abc123 unauthorized"
    out = redact_bearer(text)
    assert out is not None
    assert "abc123" not in out
    assert "[REDACTED]" in out


def test_redact_bearer_strips_bare_bearer_form():
    """`Bearer <token>` without the `Authorization:` prefix is also redacted."""
    text = "received bearer XYZ-token-123 in body"
    out = redact_bearer(text)
    assert out is not None
    assert "XYZ-token-123" not in out
    assert "[REDACTED]" in out


def test_redact_bearer_case_insensitive():
    """`AUTHORIZATION: bEaReR token` (mixed case) is still scrubbed."""
    text = "AUTHORIZATION: bEaReR shouty-token"
    out = redact_bearer(text)
    assert out is not None
    assert "shouty-token" not in out


def test_redact_bearer_multiline_body():
    """A bearer header buried in a multi-line body is found and scrubbed."""
    text = (
        "HTTP/1.1 500 Internal Server Error\n"
        "Date: Mon, 01 Jan 2026 00:00:00 GMT\n"
        "Authorization: Bearer secret-token-987\n"
        "Content-Type: application/scim+json\n"
        "\n"
        '{"error": "oops"}\n'
    )
    out = redact_bearer(text)
    assert out is not None
    assert "secret-token-987" not in out
    assert "[REDACTED]" in out
    # The surrounding lines should remain intact.
    assert "Content-Type: application/scim+json" in out
    assert '{"error": "oops"}' in out


def test_redact_bearer_pass_through_unchanged():
    """A reason string with no bearer token is returned verbatim."""
    text = "permanent 400: malformed json"
    assert redact_bearer(text) == text


def test_redact_bearer_handles_none():
    """`None` reason (rare success path artifact) passes through as None."""
    assert redact_bearer(None) is None


def test_redact_bearer_handles_empty_string():
    """An empty reason returns an empty reason -- no exception."""
    assert redact_bearer("") == ""


def test_redact_bearer_multiple_occurrences():
    """Multiple bearer occurrences in one string are all redacted."""
    text = "first Bearer aaa, then Authorization: Bearer bbb, end"
    out = redact_bearer(text)
    assert out is not None
    assert "aaa" not in out
    assert "bbb" not in out
    assert out.count("[REDACTED]") == 2


# -- Integration with the SCIM client transport layer -------------------------


class _OneShotClient:
    """Yields a single response when `request` is called."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    def request(self, *args, **kwargs) -> httpx.Response:  # noqa: ARG002
        return self._response

    def close(self) -> None:  # pragma: no cover - never called
        pass


class _EchoingQuirk:
    """Stand-in quirk module whose `interpret_error` echoes the response body.

    Mirrors the worst-case misbehaving-SP scenario the sanitiser exists
    for: a downstream SP returning the inbound Authorization header
    inside its error body, and a (hypothetical) quirk that copies that
    body into the reason string. The real quirks shipped today do NOT do
    this -- the generic quirk returns `client_error (HTTP <code>)` -- so
    this fake is the only way to exercise the integration boundary
    without rewriting a quirk module just for the test.
    """

    @staticmethod
    def interpret_error(response: httpx.Response) -> tuple[bool, str]:
        return False, response.text


def test_client_classify_response_redacts_quirk_reason():
    """A quirk that echoes a Bearer header in its reason is sanitised before
    the worker sees the `PushResult`.

    The scrub happens inside `_classify_response`, between the quirk
    callback and the result the worker writes to the sync-log / queue
    columns. This is the integration boundary the sanitiser protects.
    """
    body = "auth failed -- got Authorization: Bearer leaked-token-abc in your call"
    response = httpx.Response(400, text=body)

    result = scim_client._send_with_retry(  # noqa: SLF001
        "POST",
        "https://example.com/scim/Users",
        token="our-own-secret",  # not echoed in the (fake) response
        json_body={"x": 1},
        quirk=_EchoingQuirk,
        http_client=_OneShotClient(response),
    )

    assert result.status == "permanent"
    assert result.reason is not None
    assert "leaked-token-abc" not in result.reason
    assert "[REDACTED]" in result.reason
