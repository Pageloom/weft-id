"""``private_key_jwt`` client authentication (RFC 7523, OpenID Connect Core
1.0 section 9).

A client set to ``private_key_jwt`` proves who it is with a short-lived JWT
(the client assertion) signed by one of its private keys, instead of a shared
secret. WeftID holds only the public keys: inline (``jwks``) or published by
the client (``jwks_uri``).

Two kinds of callers:

- **Protocol**: :func:`authenticate_client_assertion` checks an assertion
  presented at the token, device authorization, introspection, or revocation
  endpoint. There is no user; a failure is ``UnauthorizedError`` and the
  router answers ``invalid_client``. Authentication is not audited, like
  secret authentication.
- **Admins**: :func:`set_client_authentication` switches a client between a
  secret and ``private_key_jwt`` and sets its keys.

An assertion is accepted when:

- ``iss`` and ``sub`` are both the client_id of an active ``private_key_jwt``
  client (and the ``client_id`` form field, when sent, is the same),
- it is signed with RS256, PS256 or ES256 (the client's registered
  ``token_endpoint_auth_signing_alg`` when it has one) by a key in the
  client's JWKS, chosen by ``kid`` when the header names one,
- ``aud`` names the issuer, the token endpoint, or the endpoint called,
- ``exp`` is present and at most an hour away, and
- its ``jti`` has not been used by this client before (kept until ``exp``
  plus the clock-skew leeway).

Keys published at ``jwks_uri`` are fetched through the SSRF guard and cached
for an hour. An assertion whose key is not in the cached set (the client
rotated keys) triggers one refetch, at most once a minute per client, so a
stream of bad assertions cannot turn WeftID into a fetch amplifier.
"""

import json
import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import database
import jwt
from services.auth import require_admin, require_super_admin
from services.event_log import log_event
from services.exceptions import NotFoundError, UnauthorizedError, ValidationError
from services.types import RequestingUser
from utils.fetch_guard import FetchGuard
from utils.safe_http import build_safe_client
from utils.url_safety import has_plain_authority

logger = logging.getLogger(__name__)

# RFC 7523 section 2.2.
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

CLIENT_SECRET = "client_secret"
PRIVATE_KEY_JWT = "private_key_jwt"
CLIENT_AUTH_METHODS = (CLIENT_SECRET, PRIVATE_KEY_JWT)

# Asymmetric algorithms only: never "none", never HMAC (the client's key is
# public, so an HMAC "signature" with it would prove nothing).
SIGNING_ALG_VALUES_SUPPORTED = ("RS256", "PS256", "ES256")
_ALG_KEY_TYPES = {"RS256": "RSA", "PS256": "RSA", "ES256": "EC"}

# Clock-skew tolerance for exp, nbf and iat.
_LEEWAY_SECONDS = 60
# The furthest in the future an assertion's exp may be. Assertions are meant to
# be minted per request; the bound also bounds how long a jti is kept.
MAX_ASSERTION_LIFETIME = timedelta(hours=1)
MAX_JTI_LENGTH = 255

# JWKS bounds (the same for inline keys, registration, and fetched sets).
MAX_JWKS_KEYS = 20
MAX_JWKS_BYTES = 32768
MAX_JWKS_URI_LENGTH = 2048

# Private (and symmetric) JWK members. A JWKS holding any of them is refused:
# WeftID must never be handed a client's private key.
_PRIVATE_KEY_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

# jwks_uri cache: fresh for an hour; a forced refetch at most once a minute.
_JWKS_TTL_SECONDS = 3600
_JWKS_REFRESH_INTERVAL_SECONDS = 60
_JWKS_FETCH_TIMEOUT_SECONDS = 5.0

# The OIDC conformance suite publishes client keys from a docker service on
# the dev network with a self-signed certificate. Dev only: both escape
# hatches are inert when IS_DEV is false.
_DEV_HOSTNAME_ALLOWLIST = frozenset({"localhost.emobix.co.uk"})

_cache_lock = threading.Lock()
# (tenant_id, client uuid) -> (jwks_uri, fetched_at monotonic, jwks dict)
_jwks_cache: dict[tuple[str, str], tuple[str, float, dict]] = {}
# (tenant_id, client uuid) -> monotonic time of the last forced refetch
_last_refresh: dict[tuple[str, str], float] = {}
# Per client: a failing jwks_uri is not refetched for 30s, and one fetch runs
# at a time.
_jwks_fetch_guard = FetchGuard()


class _AssertionRejectedError(Exception):
    """Internal: why an assertion was refused (logged, never returned)."""


# =============================================================================
# Key validation (shared with dynamic client registration)
# =============================================================================


def validate_jwks(jwks: object) -> dict:
    """Validate a JSON Web Key Set of client public keys.

    Returns the set unchanged. Raises ``ValueError`` with a message fit to
    show the caller: not an object with a ``keys`` array, too many keys or
    too large, a key that is not an RSA or EC public key, or a key carrying
    private members.
    """
    if not isinstance(jwks, dict):
        raise ValueError(f"jwks must be a JSON Web Key Set with between 1 and {MAX_JWKS_KEYS} keys")
    keys = jwks.get("keys")
    if (
        not isinstance(keys, list)
        or not keys
        or len(keys) > MAX_JWKS_KEYS
        or not all(isinstance(k, dict) for k in keys)
        or len(json.dumps(jwks)) > MAX_JWKS_BYTES
    ):
        raise ValueError(f"jwks must be a JSON Web Key Set with between 1 and {MAX_JWKS_KEYS} keys")
    for key in keys:
        if _PRIVATE_KEY_MEMBERS & key.keys():
            raise ValueError("jwks must contain public keys only")
        if key.get("kty") not in ("RSA", "EC"):
            raise ValueError("jwks keys must be RSA or EC public keys")
        try:
            jwt.PyJWK(key)
        except jwt.PyJWTError as exc:
            raise ValueError("jwks contains a key that cannot be used") from exc
    return jwks


def validate_jwks_uri(value: object) -> str:
    """Validate a client JWKS URL: absolute https, no fragment, bounded.

    Raises ``ValueError`` with a message fit to show the caller.
    """
    if not isinstance(value, str) or not value or len(value) > MAX_JWKS_URI_LENGTH:
        raise ValueError(f"jwks_uri must be a URL of at most {MAX_JWKS_URI_LENGTH} characters")
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        parts, host = None, None
    if (
        parts is None
        or parts.scheme != "https"
        or not host
        or not has_plain_authority(parts)
        or parts.fragment
    ):
        raise ValueError("jwks_uri must be an absolute https URI without a fragment")
    return value


# =============================================================================
# JWKS for a client
# =============================================================================


def _cache_key(tenant_id: str, client: dict) -> tuple[str, str]:
    return (str(tenant_id), str(client["id"]))


def clear_jwks_cache(tenant_id: str, client_uuid: str) -> None:
    """Drop the cached JWKS of a client (its keys or jwks_uri changed)."""
    key = (str(tenant_id), str(client_uuid))
    with _cache_lock:
        _jwks_cache.pop(key, None)
        _last_refresh.pop(key, None)
    _jwks_fetch_guard.forget_owner(key)


def _fetch_jwks(jwks_uri: str) -> dict:
    """Fetch a client's JWKS through the SSRF guard, bounded in size."""
    client = build_safe_client(
        timeout=_JWKS_FETCH_TIMEOUT_SECONDS,
        total_timeout=_JWKS_FETCH_TIMEOUT_SECONDS * 2,
        dev_hostname_allowlist=_DEV_HOSTNAME_ALLOWLIST,
        dev_skip_tls_verify=True,
        dev_base_domain_rewrite=True,
    )
    try:
        with client, client.stream("GET", jwks_uri) as response:
            if response.status_code != 200:
                raise _AssertionRejectedError(f"jwks_uri returned HTTP {response.status_code}")
            body = b""
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_JWKS_BYTES:
                    raise _AssertionRejectedError("jwks_uri document is too large")
    except _AssertionRejectedError:
        raise
    except Exception as exc:  # noqa: BLE001 - any transport failure is a rejection
        raise _AssertionRejectedError(f"jwks_uri fetch failed: {type(exc).__name__}") from exc
    try:
        return validate_jwks(json.loads(body))
    except ValueError as exc:
        raise _AssertionRejectedError(f"jwks_uri document is not usable: {exc}") from exc


def _client_jwks(tenant_id: str, client: dict, *, refresh: bool) -> dict | None:
    """The client's key set: inline, or fetched from jwks_uri (cached).

    With ``refresh`` a cached set is refetched, unless the last forced
    refetch was under a minute ago; returns None then (nothing new to try).
    """
    if client.get("jwks") is not None:
        return None if refresh else client["jwks"]
    jwks_uri = client.get("jwks_uri")
    if not jwks_uri:
        raise _AssertionRejectedError("client has no keys")

    key = _cache_key(tenant_id, client)
    now = time.monotonic()
    with _cache_lock:
        cached = _jwks_cache.get(key)
        if refresh:
            if now - _last_refresh.get(key, float("-inf")) < _JWKS_REFRESH_INTERVAL_SECONDS:
                return None
            _last_refresh[key] = now
        elif cached and cached[0] == jwks_uri and now - cached[1] < _JWKS_TTL_SECONDS:
            return cached[2]

    jwks = _jwks_fetch_guard.run(
        key,
        jwks_uri,
        lambda: _fetch_jwks(jwks_uri),
        busy=lambda: _AssertionRejectedError("a jwks_uri fetch for this client is in progress"),
    )
    with _cache_lock:
        _jwks_cache[key] = (jwks_uri, time.monotonic(), jwks)
    return jwks


def _candidate_keys(jwks: dict, header: dict, alg: str) -> list[jwt.PyJWK]:
    """The keys that could have signed the assertion, bound to ``alg``.

    With a ``kid`` only that key; without one, every signing key of the
    algorithm's key type (RFC 7517 section 4.5 leaves kid optional).
    """
    kid = header.get("kid")
    candidates: list[jwt.PyJWK] = []
    for key in jwks.get("keys", []):
        if not isinstance(key, dict):
            continue
        if kid is not None and key.get("kid") != kid:
            continue
        if key.get("kty") != _ALG_KEY_TYPES[alg]:
            continue
        if key.get("use") not in (None, "sig") or key.get("alg") not in (None, alg):
            continue
        try:
            candidates.append(jwt.PyJWK(key, algorithm=alg))
        except jwt.PyJWTError:
            continue
    return candidates


# =============================================================================
# Protocol: assertion check
# =============================================================================


def _decode(assertion: str, key: jwt.PyJWK, *, client_id: str, audiences: list[str]) -> dict:
    return jwt.decode(
        assertion,
        key=key,
        algorithms=[key.algorithm_name],
        audience=audiences,
        issuer=client_id,
        leeway=_LEEWAY_SECONDS,
        options={
            "require": ["iss", "sub", "aud", "exp", "jti"],
            "enforce_minimum_key_length": True,
        },
    )


def _verify_with_keys(
    tenant_id: str, client: dict, header: dict, alg: str, decode: Callable[[jwt.PyJWK], dict]
) -> dict:
    """Verify a client-signed JWT against the client's keys; refetch once on a miss.

    ``decode`` verifies the token with one candidate key and returns its claims.
    """
    jwks = _client_jwks(tenant_id, client, refresh=False)
    for attempt in range(2):
        if jwks is not None:
            for key in _candidate_keys(jwks, header, alg):
                try:
                    return decode(key)
                except jwt.InvalidSignatureError:
                    continue
                except jwt.PyJWTError as exc:
                    raise _AssertionRejectedError(f"{type(exc).__name__}: {exc}") from exc
        if attempt == 0:
            # No key verified it: the client may have rotated its keys.
            jwks = _client_jwks(tenant_id, client, refresh=True)
            if jwks is None:
                break
    raise _AssertionRejectedError("no client key verifies the signature")


def _check_assertion(
    tenant_id: str, assertion: str, client_id: str | None, audiences: list[str]
) -> dict:
    try:
        header = jwt.get_unverified_header(assertion)
        unverified = jwt.decode(assertion, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        raise _AssertionRejectedError("assertion is not a JWT") from exc

    iss = unverified.get("iss")
    if not isinstance(iss, str) or not iss or unverified.get("sub") != iss:
        raise _AssertionRejectedError("iss and sub must both be the client_id")
    if client_id is not None and client_id != iss:
        raise _AssertionRejectedError("client_id does not match the assertion")

    client = database.oauth2.get_client_by_client_id(tenant_id, iss)
    if client is None or client.get("client_auth_method") != PRIVATE_KEY_JWT:
        raise _AssertionRejectedError("not a private_key_jwt client")
    if not client.get("is_active", True):
        raise _AssertionRejectedError("client is deactivated")

    alg = header.get("alg")
    allowed = (
        (client["token_endpoint_auth_signing_alg"],)
        if client.get("token_endpoint_auth_signing_alg")
        else SIGNING_ALG_VALUES_SUPPORTED
    )
    if not isinstance(alg, str) or alg not in allowed:
        raise _AssertionRejectedError(f"alg {str(alg)[:20]!r} is not allowed")

    claims = _verify_with_keys(
        tenant_id,
        client,
        header,
        alg,
        lambda key: _decode(assertion, key, client_id=client["client_id"], audiences=audiences),
    )

    jti = claims["jti"]
    if not isinstance(jti, str) or not jti or len(jti) > MAX_JTI_LENGTH:
        raise _AssertionRejectedError("jti must be a string of at most 255 characters")
    expires_at = datetime.fromtimestamp(claims["exp"], UTC)
    if expires_at > datetime.now(UTC) + MAX_ASSERTION_LIFETIME + timedelta(seconds=_LEEWAY_SECONDS):
        raise _AssertionRejectedError("exp is more than an hour away")
    # Keep the jti for as long as the assertion decodes: until exp plus the
    # clock-skew leeway, or it could be replayed inside that window.
    if not database.oauth2.record_client_assertion_jti(
        tenant_id,
        tenant_id,
        str(client["id"]),
        jti,
        expires_at + timedelta(seconds=_LEEWAY_SECONDS),
    ):
        raise _AssertionRejectedError("jti was already used")
    return client


def authenticate_client_assertion(
    tenant_id: str,
    *,
    assertion: str,
    client_id: str | None,
    audiences: list[str],
) -> dict:
    """Authenticate a client by its ``private_key_jwt`` assertion.

    Authorization: none -- this IS the client's authentication. No audit
    (secret authentication is not audited either); a refusal is logged at
    INFO with the reason, never the assertion.

    Args:
        tenant_id: Tenant ID
        assertion: The ``client_assertion`` form field
        client_id: The ``client_id`` form field, if sent (must match)
        audiences: The ``aud`` values accepted for this endpoint

    Returns:
        The active client record

    Raises:
        UnauthorizedError: the assertion does not authenticate a client
    """
    try:
        return _check_assertion(tenant_id, assertion, client_id, audiences)
    except _AssertionRejectedError as exc:
        logger.info("OAuth2 client assertion refused: %s", exc)
        raise UnauthorizedError(
            message="Client authentication failed", code="invalid_client"
        ) from None


def verify_client_signed_jwt(
    tenant_id: str, client: dict, token: str, *, allowed_algs: tuple[str, ...]
) -> dict:
    """Verify a JWT signed with one of the client's keys and return its claims.

    Used for request objects (OpenID Connect Core 1.0 section 6), which any
    client with registered keys may sign, whatever its authentication method.
    Checks the signature (``alg`` in ``allowed_algs``, a key chosen as for
    assertions, one refetch of a ``jwks_uri`` on a miss) and ``exp`` / ``nbf``
    when present. Every other claim is the caller's to check.

    Raises:
        ValueError: the token is not a JWT signed by the client (the message
            is a reason for logs, not for the caller's user)
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise ValueError("not a JWT") from exc
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in allowed_algs:
        raise ValueError(f"alg {str(alg)[:20]!r} is not allowed")

    def decode(key: jwt.PyJWK) -> dict:
        return jwt.decode(
            token,
            key=key,
            algorithms=[key.algorithm_name],
            leeway=_LEEWAY_SECONDS,
            options={"verify_aud": False, "enforce_minimum_key_length": True},
        )

    try:
        return _verify_with_keys(tenant_id, client, header, alg, decode)
    except _AssertionRejectedError as exc:
        raise ValueError(str(exc)) from None


# =============================================================================
# Admin: authentication settings
# =============================================================================


def _key_source(jwks: dict | None, jwks_uri: str | None) -> str:
    if jwks is not None:
        return "jwks"
    return "jwks_uri" if jwks_uri else "none"


def set_client_authentication(
    requesting_user: RequestingUser,
    client_id: str,
    *,
    method: str,
    jwks: dict | None = None,
    jwks_uri: str | None = None,
) -> dict:
    """Set how a confidential client authenticates, and its public keys.

    ``private_key_jwt`` needs exactly one of ``jwks`` and ``jwks_uri``. A
    ``client_secret`` client may keep keys too (they are unused by client
    authentication). Switching to ``private_key_jwt`` replaces the secret with
    one nobody knows, so the old secret stops working at once; switching back
    generates a new secret, returned once as ``client_secret``. A registered
    signing algorithm is kept while the client stays on ``private_key_jwt``.

    Authorization: Requires admin role; super_admin for a B2B client.
    Logs: oauth2_client_authentication_changed.

    Returns:
        The updated client dict (with ``client_secret`` after switching to
        ``client_secret``)

    Raises:
        NotFoundError: No such client
        ForbiddenError: Insufficient role
        ValidationError: Unknown method, a public client, or invalid keys
    """
    require_admin(requesting_user)
    tenant_id = requesting_user["tenant_id"]

    old = database.oauth2.get_client_by_client_id(tenant_id, client_id)
    if old is None:
        raise NotFoundError(message="Client not found", code="oauth2_client_not_found")
    if old["client_type"] == "b2b":
        require_super_admin(requesting_user)
    if old.get("is_public"):
        raise ValidationError(
            message="A public client has no client authentication to change",
            code="public_client_auth_fixed",
        )
    if method not in CLIENT_AUTH_METHODS:
        raise ValidationError(
            message=f"Unsupported method. Supported: {', '.join(CLIENT_AUTH_METHODS)}",
            code="invalid_client_auth_method",
        )
    if jwks is not None and jwks_uri:
        raise ValidationError(
            message="Provide a JWKS or a JWKS URL, not both", code="invalid_client_keys"
        )
    try:
        if jwks is not None:
            validate_jwks(jwks)
        if jwks_uri:
            validate_jwks_uri(jwks_uri)
    except ValueError as exc:
        raise ValidationError(message=str(exc), code="invalid_client_keys") from exc
    if method == PRIVATE_KEY_JWT and jwks is None and not jwks_uri:
        raise ValidationError(
            message="private_key_jwt needs the client's public keys (a JWKS or a JWKS URL)",
            code="client_keys_required",
        )

    method_changed = method != old.get("client_auth_method", CLIENT_SECRET)
    updated = database.oauth2.set_client_authentication(
        tenant_id,
        client_id,
        client_auth_method=method,
        jwks=jwks,
        jwks_uri=jwks_uri or None,
        token_endpoint_auth_signing_alg=(
            old.get("token_endpoint_auth_signing_alg") if method == PRIVATE_KEY_JWT else None
        ),
        rotate_secret=method_changed,
    )
    if updated is None:
        raise NotFoundError(message="Client not found", code="oauth2_client_not_found")
    clear_jwks_cache(tenant_id, str(updated["id"]))

    log_event(
        tenant_id=tenant_id,
        actor_user_id=requesting_user["id"],
        artifact_type="oauth2_client",
        artifact_id=str(updated["id"]),
        event_type="oauth2_client_authentication_changed",
        metadata={
            "name": updated["name"],
            "client_id": client_id,
            "client_auth_method": method,
            "previous_client_auth_method": old.get("client_auth_method", CLIENT_SECRET),
            "key_source": _key_source(jwks, jwks_uri or None),
            "jwks_uri": jwks_uri or None,
            "secret_rotated": method_changed,
        },
    )
    return updated
