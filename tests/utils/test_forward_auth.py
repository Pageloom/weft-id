"""Adversarial unit tests for the forward-auth crypto primitives.

Covers signed authorization tokens and per-domain forward-auth cookies in
``utils.forward_auth``. These are pure-crypto (no DB), so the nonce single-use
guarantee is tested at the service/DB layer; here we hammer signing, expiry, and
domain-binding.
"""

import base64
import json
import time

from utils import forward_auth as fa

# -- helpers ------------------------------------------------------------------


def _mint(**overrides):
    kwargs = {
        "user_id": "user-1",
        "tenant_id": "tenant-1",
        "domain": "acme-corp.com",
        "app_id": "app-1",
        "rd": "https://grafana.acme-corp.com/dash",
        "nonce": "n0nce",
    }
    kwargs.update(overrides)
    return fa.mint_authorization_token(**kwargs)


def _tamper_payload(token: str, mutate) -> str:
    """Rewrite the token's JSON payload but keep the original (now-stale) MAC."""
    payload_b64, mac = token.split(".", 1)
    payload = json.loads(fa._b64url_decode(payload_b64).decode())
    mutate(payload)
    new_b64 = fa._b64url_encode(json.dumps(payload, sort_keys=True).encode())
    return f"{new_b64}.{mac}"


# -- TTL constants are distinct -----------------------------------------------


def test_ttls_are_distinct_named_constants():
    assert fa.FORWARD_AUTH_COOKIE_TTL == 3600
    assert fa.FORWARD_AUTH_TOKEN_TTL < fa.FORWARD_AUTH_COOKIE_TTL
    # The short token is seconds-scale, not the 1h cookie.
    assert fa.FORWARD_AUTH_TOKEN_TTL <= 300


# -- authorization token: happy path ------------------------------------------


def test_token_roundtrip():
    token = _mint()
    payload = fa.verify_authorization_token(token, expected_domain="acme-corp.com")

    assert payload is not None
    assert payload["sub"] == "user-1"
    assert payload["tid"] == "tenant-1"
    assert payload["dom"] == "acme-corp.com"
    assert payload["app"] == "app-1"
    assert payload["rd"] == "https://grafana.acme-corp.com/dash"
    assert payload["nonce"] == "n0nce"


# -- authorization token: signature tampering ---------------------------------


def test_token_rejects_payload_tampering():
    """Changing any bound field without resigning must fail."""
    token = _mint()
    tampered = _tamper_payload(token, lambda p: p.__setitem__("sub", "attacker"))
    assert fa.verify_authorization_token(tampered, expected_domain="acme-corp.com") is None


def test_token_rejects_app_substitution():
    token = _mint()
    tampered = _tamper_payload(token, lambda p: p.__setitem__("app", "other-app"))
    assert fa.verify_authorization_token(tampered, expected_domain="acme-corp.com") is None


def test_token_rejects_bad_mac():
    token = _mint()
    payload_b64, _mac = token.split(".", 1)
    forged = f"{payload_b64}.{fa._b64url_encode(b'not-the-real-mac')}"
    assert fa.verify_authorization_token(forged, expected_domain="acme-corp.com") is None


def test_token_rejects_structural_garbage():
    for bad in ["", "no-dot", "a.b.c", ".", "x.", ".y", "💥.💥"]:
        assert fa.verify_authorization_token(bad, expected_domain="acme-corp.com") is None


def test_token_rejects_non_string():
    assert fa.verify_authorization_token(None, expected_domain="acme-corp.com") is None  # type: ignore[arg-type]


def test_token_rejects_forged_with_wrong_key():
    """A token signed with the cookie key must not verify as a token."""
    payload_b64 = fa._b64url_encode(
        json.dumps(
            {
                "sub": "u",
                "tid": "t",
                "dom": "acme-corp.com",
                "app": "a",
                "rd": "/",
                "nonce": "n",
                "exp": int(time.time()) + 60,
            },
            sort_keys=True,
        ).encode()
    )
    forged = f"{payload_b64}.{fa._sign(fa._cookie_key, payload_b64)}"
    assert fa.verify_authorization_token(forged, expected_domain="acme-corp.com") is None


# -- authorization token: expiry ----------------------------------------------


def test_token_rejects_expired():
    past = time.time() - 1000
    token = _mint(now=past)
    assert fa.verify_authorization_token(token, expected_domain="acme-corp.com") is None


def test_token_expiry_boundary():
    now = 1_000_000.0
    token = fa.mint_authorization_token(
        user_id="u",
        tenant_id="t",
        domain="acme-corp.com",
        app_id="a",
        rd="/",
        nonce="n",
        ttl_seconds=60,
        now=now,
    )
    # exp = now + 60. At exactly exp it is still valid; one second past is not.
    assert (
        fa.verify_authorization_token(token, expected_domain="acme-corp.com", now=now + 60)
        is not None
    )
    assert (
        fa.verify_authorization_token(token, expected_domain="acme-corp.com", now=now + 60.001)
        is None
    )


def test_token_rejects_expired_reuse():
    """An expired token replayed later stays rejected."""
    now = 1_000_000.0
    token = fa.mint_authorization_token(
        user_id="u",
        tenant_id="t",
        domain="acme-corp.com",
        app_id="a",
        rd="/",
        nonce="n",
        now=now,
    )
    for later in (now + 61, now + 10_000):
        assert (
            fa.verify_authorization_token(token, expected_domain="acme-corp.com", now=later) is None
        )


# -- authorization token: cross-domain substitution ---------------------------


def test_token_rejects_cross_domain_substitution():
    """A token minted for domain A cannot be redeemed for domain B."""
    token = _mint(domain="acme-corp.com")
    assert fa.verify_authorization_token(token, expected_domain="victim.net") is None


def test_token_rejects_domain_tampering():
    """Rewriting the bound domain to match the target fails the MAC."""
    token = _mint(domain="acme-corp.com")
    tampered = _tamper_payload(token, lambda p: p.__setitem__("dom", "victim.net"))
    assert fa.verify_authorization_token(tampered, expected_domain="victim.net") is None


def test_token_domain_match_is_exact():
    token = _mint(domain="acme-corp.com")
    for near in ["acme-corp.co", "acme-corp.com.", "ACME-CORP.COM", "x.acme-corp.com"]:
        assert fa.verify_authorization_token(token, expected_domain=near) is None


# -- per-domain cookie: happy path --------------------------------------------


def _build_cookie(**overrides):
    kwargs = {
        "user_id": "user-9",
        "email": "user9@acme-corp.com",
        "display_name": "User Nine",
        "groups": ["admins", "staff"],
    }
    kwargs.update(overrides)
    return fa.build_forward_auth_cookie_value(**kwargs)


def test_cookie_roundtrip():
    value = _build_cookie()
    payload = fa.read_forward_auth_cookie(value)

    assert payload is not None
    assert payload["sub"] == "user-9"
    assert payload["email"] == "user9@acme-corp.com"
    assert payload["name"] == "User Nine"
    assert payload["groups"] == ["admins", "staff"]


def test_cookie_uses_one_hour_ttl_by_default():
    now = 2_000_000.0
    value = fa.build_forward_auth_cookie_value(
        user_id="u", email="e@x.com", display_name="N", groups=[], now=now
    )
    payload = fa.read_forward_auth_cookie(value, now=now)
    assert payload is not None
    assert payload["exp"] == int(now) + 3600


# -- per-domain cookie: tampering ---------------------------------------------


def test_cookie_rejects_tampering():
    value = _build_cookie()
    # Flip the groups to escalate privileges.
    tampered_b64, mac = value.split(".", 1)
    payload = json.loads(fa._b64url_decode(tampered_b64).decode())
    payload["groups"] = ["superadmins"]
    new_b64 = fa._b64url_encode(json.dumps(payload, sort_keys=True).encode())
    forged = f"{new_b64}.{mac}"
    assert fa.read_forward_auth_cookie(forged) is None


def test_cookie_rejects_bad_mac():
    value = _build_cookie()
    payload_b64, _ = value.split(".", 1)
    forged = f"{payload_b64}.{fa._b64url_encode(b'nope')}"
    assert fa.read_forward_auth_cookie(forged) is None


def test_cookie_rejects_token_signed_value():
    """A token (token key) must not be accepted as a cookie (cookie key)."""
    token = _mint()
    assert fa.read_forward_auth_cookie(token) is None


def test_cookie_rejects_absent_and_garbage():
    for bad in [None, "", "no-dot", "a.b.c"]:
        assert fa.read_forward_auth_cookie(bad) is None


def test_cookie_rejects_non_base64_payload():
    # Valid structure, valid MAC over the (invalid) payload, but payload isn't
    # decodable JSON.
    payload_b64 = "!!!notbase64!!!"
    forged = f"{payload_b64}.{fa._sign(fa._cookie_key, payload_b64)}"
    assert fa.read_forward_auth_cookie(forged) is None


def test_cookie_rejects_non_dict_payload():
    payload_b64 = fa._b64url_encode(json.dumps([1, 2, 3]).encode())
    forged = f"{payload_b64}.{fa._sign(fa._cookie_key, payload_b64)}"
    assert fa.read_forward_auth_cookie(forged) is None


def test_cookie_rejects_missing_identity_fields():
    payload_b64 = fa._b64url_encode(
        json.dumps({"exp": int(time.time()) + 3600, "sub": "u"}).encode()
    )
    forged = f"{payload_b64}.{fa._sign(fa._cookie_key, payload_b64)}"
    assert fa.read_forward_auth_cookie(forged) is None


def test_cookie_rejects_non_list_groups():
    payload_b64 = fa._b64url_encode(
        json.dumps(
            {
                "sub": "u",
                "email": "e",
                "name": "n",
                "groups": "not-a-list",
                "exp": int(time.time()) + 3600,
            }
        ).encode()
    )
    forged = f"{payload_b64}.{fa._sign(fa._cookie_key, payload_b64)}"
    assert fa.read_forward_auth_cookie(forged) is None


def test_cookie_rejects_non_finite_exp():
    """A validly-signed cookie with NaN/Infinity exp must NOT be 'never-expiring'.

    NaN defeats the `now > exp` check (every comparison with NaN is False), so a
    finiteness guard is required even though forging this needs the signing key.
    """
    for bad_exp in (float("nan"), float("inf")):
        payload_b64 = fa._b64url_encode(
            json.dumps(
                {"sub": "u", "email": "e", "name": "n", "groups": [], "exp": bad_exp}
            ).encode()
        )
        forged = f"{payload_b64}.{fa._sign(fa._cookie_key, payload_b64)}"
        assert fa.read_forward_auth_cookie(forged) is None


def test_token_rejects_non_finite_exp():
    """A validly-signed token with NaN/Infinity exp must be rejected as expired."""
    for bad_exp in (float("nan"), float("inf")):
        payload_b64 = fa._b64url_encode(
            json.dumps(
                {
                    "sub": "u",
                    "tid": "t",
                    "dom": "acme.com",
                    "app": "a",
                    "rd": "https://acme.com/",
                    "nonce": "n",
                    "exp": bad_exp,
                }
            ).encode()
        )
        forged = f"{payload_b64}.{fa._sign(fa._token_key, payload_b64)}"
        assert fa.verify_authorization_token(forged, expected_domain="acme.com") is None


# -- per-domain cookie: expiry ------------------------------------------------


def test_cookie_rejects_expired():
    past = time.time() - 7200
    value = _build_cookie(now=past)
    assert fa.read_forward_auth_cookie(value) is None


def test_cookie_expiry_boundary():
    now = 3_000_000.0
    value = fa.build_forward_auth_cookie_value(
        user_id="u", email="e@x.com", display_name="N", groups=[], now=now
    )
    # exp = now + 3600. Valid at exp, invalid just after.
    assert fa.read_forward_auth_cookie(value, now=now + 3600) is not None
    assert fa.read_forward_auth_cookie(value, now=now + 3600.001) is None


# -- cookie attributes (set/clear params) -------------------------------------


def test_cookie_params_security_attributes(monkeypatch):
    monkeypatch.setattr(fa.settings, "IS_DEV", False)
    params = fa.forward_auth_cookie_params("acme-corp.com")

    assert params["key"] == fa.FORWARD_AUTH_COOKIE_NAME
    assert params["domain"] == "acme-corp.com"
    assert params["httponly"] is True
    assert params["secure"] is True
    assert params["samesite"] == "lax"
    assert params["max_age"] == fa.FORWARD_AUTH_COOKIE_TTL
    assert params["path"] == "/"


def test_cookie_params_secure_relaxed_in_dev(monkeypatch):
    monkeypatch.setattr(fa.settings, "IS_DEV", True)
    params = fa.forward_auth_cookie_params("acme-corp.com")
    assert params["secure"] is False


def test_cookie_params_secure_override(monkeypatch):
    monkeypatch.setattr(fa.settings, "IS_DEV", True)
    params = fa.forward_auth_cookie_params("acme-corp.com", secure=True)
    assert params["secure"] is True


def test_clear_cookie_params_match_domain_and_path():
    params = fa.clear_forward_auth_cookie_params("acme-corp.com")
    assert params["key"] == fa.FORWARD_AUTH_COOKIE_NAME
    assert params["domain"] == "acme-corp.com"
    assert params["path"] == "/"


# -- key separation -----------------------------------------------------------


def test_forward_auth_keys_independent_from_all_other_purposes():
    """Token key != cookie key != any other crypto purpose in the app.

    A token signed for any unrelated purpose (session, generic tokens, hibp)
    must not collide with the forward-auth keys. We assert raw-key inequality,
    which is the property that makes cross-purpose forgery impossible.
    """
    from utils.crypto import derive_hmac_key

    token_k = fa._token_key
    cookie_k = fa._cookie_key

    assert token_k != cookie_k

    # Independent from every other HMAC purpose used in the codebase.
    for purpose in ("token", "hibp", "session-signing"):
        assert token_k != derive_hmac_key(purpose)
        assert cookie_k != derive_hmac_key(purpose)

    # Re-deriving with the same purpose is stable (sanity: not random per call).
    assert fa._token_key == derive_hmac_key("forward-auth-token")
    assert fa._cookie_key == derive_hmac_key("forward-auth-cookie")


def test_token_signed_with_generic_token_key_does_not_verify():
    """A blob signed with utils.tokens' key must not verify as a forward token."""
    from utils.crypto import derive_hmac_key

    generic_key = derive_hmac_key("token")  # the utils.tokens purpose
    payload_b64 = fa._b64url_encode(
        json.dumps(
            {
                "v": 1,
                "sub": "u",
                "tid": "t",
                "dom": "acme-corp.com",
                "app": "a",
                "rd": "/",
                "nonce": "n",
                "exp": int(time.time()) + 60,
            },
            sort_keys=True,
        ).encode()
    )
    forged = f"{payload_b64}.{fa._sign(generic_key, payload_b64)}"
    assert fa.verify_authorization_token(forged, expected_domain="acme-corp.com") is None


def test_cookie_signed_with_token_key_does_not_read():
    """A cookie-shaped blob signed with the TOKEN key must not read as a cookie."""
    payload_b64 = fa._b64url_encode(
        json.dumps(
            {
                "v": 1,
                "sub": "u",
                "email": "e@x.com",
                "name": "n",
                "groups": [],
                "exp": int(time.time()) + 3600,
            },
            sort_keys=True,
        ).encode()
    )
    forged = f"{payload_b64}.{fa._sign(fa._token_key, payload_b64)}"
    assert fa.read_forward_auth_cookie(forged) is None


# -- nonce generation ---------------------------------------------------------


def test_generate_nonce_is_random_and_hex():
    a = fa.generate_nonce()
    b = fa.generate_nonce()
    assert a != b
    assert len(a) == 64  # token_hex(32)
    int(a, 16)  # parses as hex


# -- base64 helpers -----------------------------------------------------------


def test_b64url_roundtrip_handles_padding():
    for raw in [b"", b"a", b"ab", b"abc", b"abcd", b"\x00\xff\x10"]:
        assert fa._b64url_decode(fa._b64url_encode(raw)) == raw


def test_b64url_encode_is_unpadded():
    assert "=" not in fa._b64url_encode(b"abc")
    # And is genuine urlsafe base64.
    expected = base64.urlsafe_b64encode(b"\xfb\xff").decode().rstrip("=")
    assert fa._b64url_encode(b"\xfb\xff") == expected
