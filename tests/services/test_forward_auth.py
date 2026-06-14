"""Tests for services.forward_auth (token issue + single-use redemption).

Integration tests against a real database: ``issue_authorization_token`` records
a nonce and ``redeem_authorization_token`` consumes it atomically. The key
property is end-to-end single-use: a token redeems exactly once.
"""

import time
from datetime import UTC, datetime, timedelta

import database
from services import forward_auth as svc
from utils import forward_auth as fa


def _issue(tenant_id, *, domain="acme-corp.com", app_id="app-1", rd="/dash"):
    return svc.issue_authorization_token(
        user_id="user-1",
        tenant_id=str(tenant_id),
        domain=domain,
        app_id=app_id,
        rd=rd,
    )


# -- issue --------------------------------------------------------------------


def test_issue_records_nonce(test_tenant):
    tid = test_tenant["id"]
    token = _issue(tid, domain="issue.com")

    payload = fa.verify_authorization_token(token, expected_domain="issue.com")
    assert payload is not None

    # The nonce was persisted (consuming it succeeds).
    consumed = database.forward_auth_nonces.consume_nonce(
        database.UNSCOPED, payload["nonce"], "issue.com"
    )
    assert consumed is not None
    assert str(consumed["tenant_id"]) == str(tid)


# -- redeem: happy path -------------------------------------------------------


def test_redeem_succeeds_once(test_tenant):
    tid = test_tenant["id"]
    token = _issue(tid, domain="once.com", app_id="grafana", rd="/d")

    redeemed = svc.redeem_authorization_token(token, expected_domain="once.com")

    assert redeemed is not None
    assert redeemed["sub"] == "user-1"
    assert redeemed["app"] == "grafana"
    assert redeemed["rd"] == "/d"
    assert str(redeemed["tid"]) == str(tid)


# -- redeem: replay / double-spend --------------------------------------------


def test_redeem_twice_is_rejected(test_tenant):
    """End-to-end single-use: the second redemption fails (nonce consumed)."""
    tid = test_tenant["id"]
    token = _issue(tid, domain="replay.com")

    first = svc.redeem_authorization_token(token, expected_domain="replay.com")
    second = svc.redeem_authorization_token(token, expected_domain="replay.com")

    assert first is not None
    assert second is None


# -- redeem: stateless rejections still apply ---------------------------------


def test_redeem_rejects_bad_signature_without_touching_nonce(test_tenant):
    tid = test_tenant["id"]
    token = _issue(tid, domain="sig.com")
    payload = fa.verify_authorization_token(token, expected_domain="sig.com")
    assert payload is not None

    # Forge a different MAC -> stateless verify fails before any consume.
    payload_b64, _ = token.split(".", 1)
    forged = f"{payload_b64}.{fa._b64url_encode(b'forged-mac')}"
    assert svc.redeem_authorization_token(forged, expected_domain="sig.com") is None

    # The real nonce is untouched -> the genuine token still redeems.
    assert svc.redeem_authorization_token(token, expected_domain="sig.com") is not None


def test_redeem_rejects_cross_domain_without_consuming(test_tenant):
    """A cross-domain redemption fails AND does not spend the nonce."""
    tid = test_tenant["id"]
    token = _issue(tid, domain="real.com")

    # Wrong domain -> stateless domain check fails; nonce not consumed.
    assert svc.redeem_authorization_token(token, expected_domain="evil.com") is None

    # The token still works for its real domain.
    assert svc.redeem_authorization_token(token, expected_domain="real.com") is not None


def test_redeem_rejects_expired(test_tenant, monkeypatch):
    tid = test_tenant["id"]
    # Mint with an already-past clock so the token is born expired.
    monkeypatch.setattr(time, "time", lambda: 1_000_000.0)
    token = svc.issue_authorization_token(
        user_id="u",
        tenant_id=str(tid),
        domain="exp.com",
        app_id="a",
        rd="/",
        ttl_seconds=1,
    )
    monkeypatch.setattr(time, "time", lambda: 1_000_100.0)
    assert svc.redeem_authorization_token(token, expected_domain="exp.com") is None


def test_redeem_unknown_nonce_rejected(test_tenant):
    """A validly-signed token whose nonce was never recorded is rejected."""
    tid = test_tenant["id"]
    # Mint a token WITHOUT recording its nonce (bypass the service).
    token = fa.mint_authorization_token(
        user_id="u",
        tenant_id=str(tid),
        domain="ghost.com",
        app_id="a",
        rd="/",
        nonce=fa.generate_nonce(),
    )
    assert svc.redeem_authorization_token(token, expected_domain="ghost.com") is None


def test_redeem_fails_closed_on_tenant_mismatch(test_tenant):
    """The fail-closed branch in redeem (token tid != stored nonce tenant).

    The token HMAC normally guarantees ``tid`` matches the nonce row's tenant
    (both come from the same mint). This forces the mismatch: the nonce is
    recorded under tenant A, but a token validly signed with the real token key
    claims ``tid`` = some other tenant. Redemption must return None even though
    the signature, expiry, and domain all check out.
    """
    tid_a = str(test_tenant["id"])
    other_tid = "00000000-0000-0000-0000-000000000001"  # any non-matching id
    nonce = fa.generate_nonce()

    # Record the nonce under tenant A's scope.
    database.forward_auth_nonces.create_nonce(
        test_tenant["id"],
        tid_a,
        nonce,
        "mismatch.com",
        datetime.now(UTC) + timedelta(seconds=60),
    )
    # Mint a genuinely-signed token whose bound tid is NOT tenant A.
    token = fa.mint_authorization_token(
        user_id="u",
        tenant_id=other_tid,
        domain="mismatch.com",
        app_id="a",
        rd="/",
        nonce=nonce,
    )

    assert svc.redeem_authorization_token(token, expected_domain="mismatch.com") is None

    # The mismatched redemption still BURNS the nonce (it is deleted before the
    # tenant check), so a retry cannot reuse it -- fail closed, no lingering row.
    assert (
        database.forward_auth_nonces.consume_nonce(database.UNSCOPED, nonce, "mismatch.com") is None
    )


def test_redeem_does_not_verify_with_cookie_key(test_tenant):
    """A value signed with the cookie key (or any non-token key) cannot redeem.

    Defends key separation at the service boundary: even if an attacker could
    obtain a cookie-signed blob, it must not be redeemable as an authorization
    token. The nonce store is never touched because stateless verify fails first.
    """
    tid = str(test_tenant["id"])
    nonce = fa.generate_nonce()
    database.forward_auth_nonces.create_nonce(
        test_tenant["id"],
        tid,
        nonce,
        "keysep.com",
        datetime.now(UTC) + timedelta(seconds=60),
    )
    # Build a token-shaped payload but sign it with the COOKIE key.
    import json

    payload_b64 = fa._b64url_encode(
        json.dumps(
            {
                "v": 1,
                "sub": "u",
                "tid": tid,
                "dom": "keysep.com",
                "app": "a",
                "rd": "/",
                "nonce": nonce,
                "exp": int(time.time()) + 60,
            },
            sort_keys=True,
        ).encode()
    )
    forged = f"{payload_b64}.{fa._sign(fa._cookie_key, payload_b64)}"

    assert svc.redeem_authorization_token(forged, expected_domain="keysep.com") is None
    # The genuine nonce is untouched -> a properly-signed token still redeems.
    genuine = fa.mint_authorization_token(
        user_id="u", tenant_id=tid, domain="keysep.com", app_id="a", rd="/", nonce=nonce
    )
    assert svc.redeem_authorization_token(genuine, expected_domain="keysep.com") is not None
