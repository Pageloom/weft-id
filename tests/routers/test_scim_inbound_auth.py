"""Tests for the inbound SCIM bearer-token authentication dependency.

All failure paths must produce the SAME SCIM 401 envelope:
- No `Authorization` header.
- Malformed header (no `Bearer ` prefix).
- Bearer with no token body.
- Unknown token hash.
- Revoked token.
- Token bound to a different IdP than the URL specifies.

Same body + same status -> an unauthenticated probe cannot
distinguish "no token" from "wrong tenant", which would otherwise
leak the existence of IdP / tenant ids.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from unittest.mock import patch
from uuid import uuid4

import pytest
import settings


@pytest.fixture
def api_host():
    return f"test.{settings.BASE_DOMAIN}"


@pytest.fixture(autouse=True)
def mock_tenant_lookup():
    with patch("dependencies.database") as mock_db:
        mock_db.tenants.get_tenant_by_subdomain.return_value = {
            "id": str(uuid4()),
            "subdomain": "test",
        }
        yield


@pytest.fixture
def reset_rate_limit():
    """Reset the SCIM auth rate-limit bucket between tests.

    Using the TestClient's `127.0.0.1` IP, the bucket persists across
    requests in a single test session. The 60/min limit is generous
    but we still want each test to start clean.
    """
    from utils.ratelimit import ratelimit as rl

    rl.reset("scim_inbound_auth:ip:{ip}", ip="testclient")
    yield
    rl.reset("scim_inbound_auth:ip:{ip}", ip="testclient")


def _hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _users_path(idp_id: str) -> str:
    """Pick an authenticated endpoint to exercise -- /Users is the simplest."""
    return f"/scim/v2/inbound/{idp_id}/Users"


def _assert_same_401(resp):
    """All auth failures: same status, same body shape, same detail."""
    assert resp.status_code == 401
    body = resp.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert body["status"] == "401"
    assert body["detail"] == "Authentication required"
    assert resp.headers.get("WWW-Authenticate", "").startswith("Bearer")
    # Same body shape regardless of failure mode -- no tenancy leak.
    assert "scimType" not in body or body["scimType"] is None


# ---------------------------------------------------------------------------
# Header missing / malformed
# ---------------------------------------------------------------------------


def test_missing_authorization_header(client, api_host, reset_rate_limit):
    idp = str(uuid4())
    resp = client.get(_users_path(idp), headers={"host": api_host})
    _assert_same_401(resp)


def test_malformed_authorization_header(client, api_host, reset_rate_limit):
    idp = str(uuid4())
    resp = client.get(
        _users_path(idp),
        headers={"host": api_host, "Authorization": "Basic abc:def"},
    )
    _assert_same_401(resp)


def test_empty_bearer_token(client, api_host, reset_rate_limit):
    idp = str(uuid4())
    resp = client.get(
        _users_path(idp),
        headers={"host": api_host, "Authorization": "Bearer "},
    )
    _assert_same_401(resp)


def test_oversized_bearer_token_rejected_before_hash(client, api_host, reset_rate_limit):
    """A token over the length ceiling is rejected before the sha256/DB lookup.

    Bounding the pre-auth path keeps an oversized Authorization header from
    driving hashing + a DB query proportional to attacker-controlled input.
    """
    idp = str(uuid4())
    oversized = "x" * 600  # > _MAX_BEARER_TOKEN_LEN (512)
    with patch("database.scim_inbound_tokens.get_by_hash") as get_by_hash:
        resp = client.get(
            _users_path(idp),
            headers={"host": api_host, "Authorization": f"Bearer {oversized}"},
        )
    _assert_same_401(resp)
    get_by_hash.assert_not_called()


# ---------------------------------------------------------------------------
# Unknown / revoked / wrong-IdP
# ---------------------------------------------------------------------------


def test_unknown_token_hash(client, api_host, reset_rate_limit):
    idp = str(uuid4())
    with patch("database.scim_inbound_tokens.get_by_hash", return_value=None):
        resp = client.get(
            _users_path(idp),
            headers={"host": api_host, "Authorization": "Bearer wid_inbound_unknown"},
        )
    _assert_same_401(resp)


def test_revoked_token(client, api_host, reset_rate_limit):
    idp = str(uuid4())
    plaintext = "wid_inbound_revoked"
    row = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "idp_id": idp,
        "name": "Revoked",
        "created_by_user_id": str(uuid4()),
        "created_at": datetime.now(UTC),
        "revoked_at": datetime.now(UTC),
        "last_used_at": None,
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=row),
        patch("database.scim_inbound_tokens.touch_last_used") as touch,
    ):
        resp = client.get(
            _users_path(idp),
            headers={"host": api_host, "Authorization": f"Bearer {plaintext}"},
        )
    _assert_same_401(resp)
    touch.assert_not_called()


def test_token_for_wrong_idp(client, api_host, reset_rate_limit):
    """Token belongs to IdP A but the URL is for IdP B -- reject as if unknown."""
    url_idp = str(uuid4())
    token_idp = str(uuid4())
    plaintext = "wid_inbound_wrongidp"
    row = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "idp_id": token_idp,
        "name": "Other",
        "created_by_user_id": str(uuid4()),
        "created_at": datetime.now(UTC),
        "revoked_at": None,
        "last_used_at": None,
    }
    with patch("database.scim_inbound_tokens.get_by_hash", return_value=row):
        resp = client.get(
            _users_path(url_idp),
            headers={"host": api_host, "Authorization": f"Bearer {plaintext}"},
        )
    _assert_same_401(resp)


# ---------------------------------------------------------------------------
# Happy path: lookup keyed by hash, last_used touched.
# ---------------------------------------------------------------------------


def test_valid_token_authenticates_and_touches_last_used(client, api_host, reset_rate_limit):
    idp = str(uuid4())
    tenant = str(uuid4())
    plaintext = "wid_inbound_validtoken"
    expected_hash = _hash(plaintext)
    row = {
        "id": str(uuid4()),
        "tenant_id": tenant,
        "idp_id": idp,
        "name": "OK",
        "created_by_user_id": str(uuid4()),
        "created_at": datetime.now(UTC),
        "revoked_at": None,
        "last_used_at": None,
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=row) as get_by_hash,
        patch("database.scim_inbound_tokens.touch_last_used") as touch,
        patch("services.scim.inbound_read.list_users", return_value=([], 0)),
    ):
        resp = client.get(
            _users_path(idp),
            headers={"host": api_host, "Authorization": f"Bearer {plaintext}"},
        )
    assert resp.status_code == 200
    # Hash lookup uses the correct digest.
    assert get_by_hash.call_args.args[1] == expected_hash
    touch.assert_called_once()


def test_touch_failure_does_not_block_request(client, api_host, reset_rate_limit):
    """A DB blip on `touch_last_used` is observability, not authorisation."""
    idp = str(uuid4())
    plaintext = "wid_inbound_touchfail"
    row = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "idp_id": idp,
        "name": "OK",
        "created_by_user_id": str(uuid4()),
        "created_at": datetime.now(UTC),
        "revoked_at": None,
        "last_used_at": None,
    }
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=row),
        patch("database.scim_inbound_tokens.touch_last_used", side_effect=RuntimeError("blip")),
        patch("services.scim.inbound_read.list_users", return_value=([], 0)),
    ):
        resp = client.get(
            _users_path(idp),
            headers={"host": api_host, "Authorization": f"Bearer {plaintext}"},
        )
    # Request still completes; the touch failure is logged but not raised.
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Rate-limiting on auth attempts
# ---------------------------------------------------------------------------


def test_rate_limit_returns_scim_429(client, api_host, reset_rate_limit):
    """The bearer-auth bucket returns a SCIM 429 with Retry-After."""
    from services.exceptions import RateLimitError

    idp = str(uuid4())
    with patch(
        "api_dependencies.ratelimit.prevent",
        side_effect=RateLimitError(message="rate limited", limit=60, timespan=60, retry_after=60),
    ):
        resp = client.get(
            _users_path(idp),
            headers={"host": api_host, "Authorization": "Bearer wid_inbound_anything"},
        )
    assert resp.status_code == 429
    body = resp.json()
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert body["status"] == "429"
    assert resp.headers.get("Retry-After") == "60"


# ---------------------------------------------------------------------------
# Byte-identical envelopes across auth-failure modes
#
# The prompt's iteration 2 invariants explicitly call out: auth failures
# must NEVER leak tenant / IdP identity. Wrong-tenant token and unknown
# token must return byte-identical bodies and headers. The existing
# per-mode tests share an `_assert_same_401` helper but never compare
# the responses to each other -- this test pins that invariant directly.
# ---------------------------------------------------------------------------


def test_all_auth_failures_produce_identical_envelopes(client, api_host, reset_rate_limit):
    """No-token, unknown-token, revoked-token, wrong-IdP-token: same body + headers.

    A client distinguishing these states could probe for the existence
    of specific token hashes or IdP / tenant ids without ever holding a
    valid credential. The whole point of the uniform-failure pattern in
    `_raise_scim_auth_error` is to make that distinction invisible.
    """
    url_idp = str(uuid4())
    other_idp = str(uuid4())
    revoked_row = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "idp_id": url_idp,
        "name": "Revoked",
        "created_by_user_id": str(uuid4()),
        "created_at": datetime.now(UTC),
        "revoked_at": datetime.now(UTC),
        "last_used_at": None,
    }
    wrong_idp_row = {
        "id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "idp_id": other_idp,
        "name": "Other",
        "created_by_user_id": str(uuid4()),
        "created_at": datetime.now(UTC),
        "revoked_at": None,
        "last_used_at": None,
    }

    # No header.
    no_header = client.get(_users_path(url_idp), headers={"host": api_host})

    # Malformed header.
    malformed = client.get(
        _users_path(url_idp),
        headers={"host": api_host, "Authorization": "Basic abc:def"},
    )

    # Unknown token hash.
    with patch("database.scim_inbound_tokens.get_by_hash", return_value=None):
        unknown = client.get(
            _users_path(url_idp),
            headers={"host": api_host, "Authorization": "Bearer wid_inbound_unknown"},
        )

    # Revoked token.
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=revoked_row),
        patch("database.scim_inbound_tokens.touch_last_used"),
    ):
        revoked = client.get(
            _users_path(url_idp),
            headers={"host": api_host, "Authorization": "Bearer wid_inbound_revoked"},
        )

    # Token bound to a different IdP than the URL.
    with patch("database.scim_inbound_tokens.get_by_hash", return_value=wrong_idp_row):
        wrong_idp = client.get(
            _users_path(url_idp),
            headers={"host": api_host, "Authorization": "Bearer wid_inbound_wrongidp"},
        )

    responses = [no_header, malformed, unknown, revoked, wrong_idp]
    # Same body across the board.
    bodies = [r.json() for r in responses]
    for body in bodies[1:]:
        assert body == bodies[0]
    # Same WWW-Authenticate header (no per-mode differentiation).
    auth_headers = [r.headers.get("WWW-Authenticate") for r in responses]
    assert all(h == auth_headers[0] for h in auth_headers[1:])


def test_get_by_hash_uses_unscoped_lookup(client, api_host, reset_rate_limit):
    """The token-hash lookup must be UNSCOPED -- the request tenant isn't known yet.

    The unique hash index on `scim_inbound_tokens.token_hash` (iteration
    1's migration) is what blocks the cross-tenant collision risk that
    would otherwise come from an UNSCOPED lookup. If a future refactor
    accidentally scoped this call to `get_tenant_id_from_request`, the
    bearer-token flow would silently break for any URL whose subdomain
    doesn't own the token's IdP. This test pins the call shape.
    """
    import database

    idp = str(uuid4())
    with (
        patch("database.scim_inbound_tokens.get_by_hash", return_value=None) as get_by_hash,
    ):
        client.get(
            _users_path(idp),
            headers={"host": api_host, "Authorization": "Bearer wid_inbound_anything"},
        )
    # First positional arg is the tenant scope -- must be UNSCOPED.
    assert get_by_hash.call_args.args[0] is database.UNSCOPED
