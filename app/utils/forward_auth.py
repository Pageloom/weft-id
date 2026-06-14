"""Forward-auth security primitives: signed tokens and per-domain cookies.

This is the isolated crypto core for the multi-domain forward-auth handshake
(iteration 4). It contains NO HTTP wiring -- no FastAPI routes, no request
handling. The iteration-5 runtime calls these functions to mint/verify the
short-lived authorization token and to set/read/clear the per-domain cookie.

Two distinct, deliberately separate lifetimes (do not conflate them):

  * The **authorization token** is short-lived (seconds) and **single-use**. It
    is minted at `/forward-auth/authorize` on the canonical tenant host and
    redeemed once at `/forward-auth/callback` on the portal host. Single-use is
    enforced by a DB-backed nonce consumed atomically on redemption.

  * The **per-domain cookie** is the forward-auth session. It lives for
    ``FORWARD_AUTH_COOKIE_TTL`` (1 hour, fixed) and is validated by signature +
    expiry ONLY -- pure TTL, no central-session revalidation (see the resolved
    design decision, 2026-06-14). The post-logout staleness consequence is
    documented on the cookie helpers.

Signing uses HKDF-derived keys from the master secret (``utils.crypto``); no new
crypto primitive is introduced. Each surface gets an independent key via a
distinct HKDF purpose string.
"""

import base64
import hashlib
import hmac
import json
import math
import secrets
import time
from typing import Any

import settings
from utils.crypto import derive_hmac_key

# ---------------------------------------------------------------------------
# Lifetimes (two distinct, named constants -- never conflate them)
# ---------------------------------------------------------------------------

# Per-domain forward-auth COOKIE lifetime: 1 hour, fixed for this round (not
# per-app configurable yet). A later iteration can shorten this or make it
# per-app by changing this single constant -- call sites read it from here.
#
# Validation of this cookie is PURE TTL: signature + expiry only, with NO
# central-session revalidation. Consequence: after a user logs out of their
# central WeftID session, any already-issued per-domain cookie stays valid until
# it expires -- bounded post-logout staleness of at most FORWARD_AUTH_COOKIE_TTL
# (<= 1 hour). Full cross-domain single-logout is a separate, later backlog item.
FORWARD_AUTH_COOKIE_TTL = 3600  # seconds (1 hour)

# Authorization TOKEN lifetime: short and single-use. This covers only the
# browser hop from /forward-auth/authorize (canonical host) to
# /forward-auth/callback (portal host), so it is measured in seconds.
FORWARD_AUTH_TOKEN_TTL = 60  # seconds

# Base name for the per-domain cookie. The actual cookie is per-domain (scoped
# via the Domain attribute), so one name is reused across domains; the browser
# keeps them separate by domain.
FORWARD_AUTH_COOKIE_NAME = "weftid_forward_auth"

# Independent HKDF-derived signing keys (distinct purposes => independent keys).
_token_key = derive_hmac_key("forward-auth-token")
_cookie_key = derive_hmac_key("forward-auth-cookie")


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def _b64url_encode(raw: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64url_decode(value: str) -> bytes:
    """Decode URL-safe base64, tolerating missing padding."""
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def _sign(key: bytes, payload_b64: str) -> str:
    """Return the URL-safe base64 HMAC-SHA256 of a payload segment."""
    mac = hmac.new(key, payload_b64.encode(), hashlib.sha256).digest()
    return _b64url_encode(mac)


def _pack(key: bytes, payload: dict[str, Any]) -> str:
    """Serialize + sign a payload into a ``<payload>.<mac>`` string.

    JSON is dumped with sorted keys for deterministic bytes, base64url-encoded,
    then HMAC-signed. The signature covers the encoded payload exactly, so any
    tampering with the payload (or the encoded form) invalidates the MAC.
    """
    payload_b64 = _b64url_encode(json.dumps(payload, sort_keys=True).encode())
    return f"{payload_b64}.{_sign(key, payload_b64)}"


def _unpack(key: bytes, token: str) -> dict[str, Any] | None:
    """Verify a ``<payload>.<mac>`` string and return the payload, or None.

    Returns None for any structural malformation or signature mismatch. The MAC
    is compared in constant time. Expiry/field checks are the caller's job.
    """
    if not isinstance(token, str) or token.count(".") != 1:
        return None
    payload_b64, mac = token.split(".", 1)
    if not payload_b64 or not mac:
        return None

    expected = _sign(key, payload_b64)
    try:
        if not hmac.compare_digest(mac, expected):
            return None
    except TypeError:
        # compare_digest rejects non-ASCII; such a MAC can never be valid.
        return None

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode())
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


# ---------------------------------------------------------------------------
# Authorization token (short-lived, single-use)
# ---------------------------------------------------------------------------


def generate_nonce() -> str:
    """Generate a cryptographically random 256-bit nonce (hex)."""
    return secrets.token_hex(32)


def mint_authorization_token(
    *,
    user_id: str,
    tenant_id: str,
    domain: str,
    app_id: str,
    rd: str,
    nonce: str,
    ttl_seconds: int = FORWARD_AUTH_TOKEN_TTL,
    now: float | None = None,
) -> str:
    """Mint a signed, short-lived authorization token for the handshake.

    The token binds {user, tenant, domain, app, rd, exp, nonce}. It is signed
    (HMAC-SHA256) but NOT encrypted; it carries no secret, only identifiers the
    portal host re-validates. Single-use is enforced separately by recording
    ``nonce`` in the DB nonce store at mint time and consuming it on redemption
    (see ``database.forward_auth_nonces``).

    Args:
        user_id: The authenticated user the token authorizes.
        tenant_id: The minting (home) tenant.
        domain: The protected domain the per-domain cookie will be scoped to.
        app_id: The proxy app being authorized.
        rd: The post-handshake redirect target (validated by the runtime, not
            here).
        nonce: The single-use nonce (also recorded in the nonce store).
        ttl_seconds: Token lifetime in seconds (short).
        now: Override the clock (testing).

    Returns:
        A ``<payload>.<mac>`` token string safe to place in a URL query.
    """
    issued = now if now is not None else time.time()
    payload = {
        "v": 1,
        "sub": str(user_id),
        "tid": str(tenant_id),
        "dom": domain,
        "app": str(app_id),
        "rd": rd,
        "nonce": nonce,
        "exp": int(issued) + ttl_seconds,
    }
    return _pack(_token_key, payload)


def verify_authorization_token(
    token: str,
    *,
    expected_domain: str,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Verify an authorization token's signature, expiry, and domain binding.

    This is the stateless half of redemption. It rejects:
      * a bad/forged signature or any structural malformation,
      * an expired token,
      * a token whose bound ``domain`` does not match ``expected_domain`` (the
        domain the callback is redeeming for) -- this defeats cross-domain token
        substitution, where a token minted for domain A is replayed at the
        callback for domain B.

    It does NOT enforce single-use. The caller must additionally consume the
    returned ``nonce`` atomically (``redeem_authorization_token`` wires both
    together). Verifying alone is replay-able; redemption is not.

    Args:
        token: The token string from the callback.
        expected_domain: The protected domain the redemption is for. Must equal
            the token's bound domain.
        now: Override the clock (testing).

    Returns:
        The validated payload dict (with ``sub``, ``tid``, ``dom``, ``app``,
        ``rd``, ``nonce``, ``exp``) if every stateless check passes, else None.
    """
    payload = _unpack(_token_key, token)
    if payload is None:
        return None

    # Required fields present and well-typed.
    required = ("sub", "tid", "dom", "app", "rd", "nonce", "exp")
    if any(field not in payload for field in required):
        return None
    if not isinstance(payload["exp"], int | float) or not math.isfinite(payload["exp"]):
        # Reject NaN/Infinity: NaN makes every comparison False (never expires).
        return None

    # Expiry.
    current = now if now is not None else time.time()
    if current > payload["exp"]:
        return None

    # Domain binding: reject cross-domain substitution. Constant-time compare to
    # avoid leaking the bound domain via timing.
    bound_domain = payload["dom"]
    if not isinstance(bound_domain, str):
        return None
    if not hmac.compare_digest(bound_domain, expected_domain):
        return None

    return payload


# ---------------------------------------------------------------------------
# Per-domain forward-auth cookie (1h fixed TTL, pure-TTL validation)
# ---------------------------------------------------------------------------


def build_forward_auth_cookie_value(
    *,
    user_id: str,
    email: str,
    display_name: str,
    groups: list[str],
    ttl_seconds: int = FORWARD_AUTH_COOKIE_TTL,
    now: float | None = None,
) -> str:
    """Build the signed value for a per-domain forward-auth cookie.

    The payload is the MINIMAL identity the proxied app needs reflected in
    ``X-Forwarded-*`` headers: user id, email, display name, and group names,
    plus an expiry. It is signed (HMAC-SHA256), not encrypted -- it exposes only
    the same identity the app already receives in headers.

    Lifetime is ``FORWARD_AUTH_COOKIE_TTL`` (1 hour, fixed). See the module
    docstring and ``read_forward_auth_cookie`` for the pure-TTL validation model
    and its post-logout staleness consequence.

    Args:
        user_id: The forward-auth subject.
        email: The subject's primary email.
        display_name: A human-readable display name.
        groups: The subject's group names (for X-Forwarded-Groups).
        ttl_seconds: Cookie lifetime; defaults to the fixed 1h constant.
        now: Override the clock (testing).

    Returns:
        A signed ``<payload>.<mac>`` cookie value.
    """
    issued = now if now is not None else time.time()
    payload = {
        "v": 1,
        "sub": str(user_id),
        "email": email,
        "name": display_name,
        "groups": list(groups),
        "exp": int(issued) + ttl_seconds,
    }
    return _pack(_cookie_key, payload)


def read_forward_auth_cookie(
    cookie_value: str | None,
    *,
    now: float | None = None,
) -> dict[str, Any] | None:
    """Validate and decode a per-domain forward-auth cookie.

    Validation is **pure TTL**: signature + expiry ONLY. There is intentionally
    NO central-session revalidation here (resolved design decision, 2026-06-14).

    Consequence -- post-logout staleness: because this never consults the
    central WeftID session, a cookie issued before a central logout remains
    valid until it expires. The window is bounded by ``FORWARD_AUTH_COOKIE_TTL``
    (<= 1 hour). Instant cross-domain revocation (single-logout) is a separate,
    later backlog item and is deliberately out of scope here.

    Args:
        cookie_value: The raw cookie value (or None if the cookie is absent).
        now: Override the clock (testing).

    Returns:
        The identity payload dict (``sub``, ``email``, ``name``, ``groups``,
        ``exp``) if the signature is valid and the cookie is unexpired, else
        None (absent, tampered, malformed, or expired).
    """
    if not cookie_value:
        return None

    payload = _unpack(_cookie_key, cookie_value)
    if payload is None:
        return None

    if (
        "exp" not in payload
        or not isinstance(payload["exp"], int | float)
        or not math.isfinite(payload["exp"])
    ):
        # Reject NaN/Infinity: NaN makes every comparison False (never expires).
        return None

    current = now if now is not None else time.time()
    if current > payload["exp"]:
        return None

    # Ensure the minimal identity shape is present.
    for field in ("sub", "email", "name", "groups"):
        if field not in payload:
            return None
    if not isinstance(payload["groups"], list):
        return None

    return payload


def forward_auth_cookie_params(
    domain: str,
    *,
    secure: bool | None = None,
    ttl_seconds: int = FORWARD_AUTH_COOKIE_TTL,
) -> dict[str, Any]:
    """Return the cookie attributes for SETTING the per-domain cookie.

    The runtime passes these to Starlette ``response.set_cookie(value=...,
    **forward_auth_cookie_params(domain))``. The cookie is:
      * httponly -- not readable by JS in the proxied app,
      * secure -- HTTPS only (auto-relaxed in dev when ``IS_DEV``),
      * SameSite=Lax -- sent on top-level navigations (the redirect back from
        the callback) but not on cross-site subrequests,
      * Domain=<protected domain> -- so the browser sends it on the proxy's
        same-domain ``/forward-auth/check`` subrequest for any host under the
        domain.

    Args:
        domain: The protected domain to scope the cookie to (the ``Domain``
            attribute). Must be the bare registrable domain, e.g.
            ``acme-corp.com``.
        secure: Force the Secure flag; defaults to True except in dev.
        ttl_seconds: Cookie max-age; defaults to the fixed 1h constant.

    Returns:
        Kwargs for ``response.set_cookie`` EXCEPT ``key``/``value``: includes
        ``max_age``, ``httponly``, ``secure``, ``samesite``, ``domain``,
        ``path``. The caller supplies ``key=FORWARD_AUTH_COOKIE_NAME`` and the
        value from ``build_forward_auth_cookie_value``.
    """
    is_secure = (not settings.IS_DEV) if secure is None else secure
    return {
        "key": FORWARD_AUTH_COOKIE_NAME,
        "max_age": ttl_seconds,
        "httponly": True,
        "secure": is_secure,
        "samesite": "lax",
        "domain": domain,
        "path": "/",
    }


def clear_forward_auth_cookie_params(domain: str) -> dict[str, Any]:
    """Return the attributes for CLEARING the per-domain cookie.

    Mirrors ``forward_auth_cookie_params`` so the browser matches and deletes
    the right cookie. The runtime passes these to
    ``response.delete_cookie(**clear_forward_auth_cookie_params(domain))``.

    Args:
        domain: The protected domain the cookie was scoped to.

    Returns:
        Kwargs for ``response.delete_cookie`` (``key``, ``domain``, ``path``).
    """
    return {
        "key": FORWARD_AUTH_COOKIE_NAME,
        "domain": domain,
        "path": "/",
    }
