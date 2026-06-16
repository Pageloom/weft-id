"""Forward-auth token redemption: stateless verify + atomic single-use consume.

This service composes the pure crypto primitives in ``utils.forward_auth`` with
the DB-backed nonce store (``database.forward_auth_nonces``) to mint and redeem
the short-lived, single-use authorization token of the handshake. It contains no
HTTP wiring; the iteration-5 runtime calls these functions.

  * ``issue_authorization_token`` -- mint the token AND record its nonce, so the
    token can later be redeemed exactly once. Runs on the canonical tenant host
    with a known tenant scope.

  * ``redeem_authorization_token`` -- verify the token (signature, expiry,
    domain binding) AND atomically consume its nonce. Returns the bound identity
    on success, or None on any failure (bad signature, expiry, cross-domain
    substitution, or replay/double-spend). Runs pre-auth on the portal host, so
    it consumes with ``UNSCOPED``.

The single-use guarantee comes from the atomic ``DELETE ... RETURNING`` in
``consume_nonce``: only the first redemption finds and deletes the nonce row;
every replay or concurrent race gets None. There is no check-then-write window,
so double-spend is impossible even under concurrent callbacks.
"""

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import database
import settings
from services.event_log import log_event
from utils.forward_auth import (
    FORWARD_AUTH_TOKEN_TTL,
    generate_nonce,
    mint_authorization_token,
    verify_authorization_token,
)


def issue_authorization_token(
    *,
    user_id: str,
    tenant_id: str,
    domain: str,
    app_id: str,
    rd: str,
    ttl_seconds: int = FORWARD_AUTH_TOKEN_TTL,
) -> str:
    """Mint a single-use authorization token and record its nonce.

    The nonce is recorded BEFORE the token is handed out so a redemption can
    always find (and consume) it. Runs on the canonical tenant host where the
    tenant scope is known, so the nonce row is written tenant-scoped.

    Args:
        user_id: The authenticated user the token authorizes.
        tenant_id: The minting (home) tenant.
        domain: The protected domain the token (and later cookie) is bound to.
        app_id: The proxy app being authorized.
        rd: The post-handshake redirect target (validated by the runtime).
        ttl_seconds: Token lifetime in seconds (short).

    Returns:
        The signed token string to place in the callback URL.
    """
    nonce = generate_nonce()
    expires_at = datetime.fromtimestamp(datetime.now(UTC).timestamp() + ttl_seconds, tz=UTC)

    database.forward_auth_nonces.create_nonce(
        tenant_id,
        tenant_id,
        nonce,
        domain,
        expires_at,
    )

    return mint_authorization_token(
        user_id=user_id,
        tenant_id=tenant_id,
        domain=domain,
        app_id=app_id,
        rd=rd,
        nonce=nonce,
        ttl_seconds=ttl_seconds,
    )


def redeem_authorization_token(
    token: str,
    *,
    expected_domain: str,
) -> dict[str, Any] | None:
    """Verify a token and atomically consume its nonce (single-use redemption).

    Order matters: verify the stateless parts first (cheap, no DB), then consume
    the nonce. The consume is the single-use gate -- a replayed token whose
    nonce was already spent returns None even though its signature/expiry/domain
    still check out. The nonce is also re-bound to ``expected_domain`` in the
    delete predicate as defense-in-depth against cross-domain substitution.

    Runs pre-auth on the portal host: the nonce is consumed with ``UNSCOPED``
    because no central session/tenant scope exists at the callback. The 0048 RLS
    policy permits this UNSCOPED consume the same way 0047 does for the
    portal-host lookup; the nonce is a 256-bit secret and the token's HMAC binds
    {tenant, domain, ...}, so an UNSCOPED consume grants nothing on its own.

    Args:
        token: The token from the callback URL.
        expected_domain: The protected domain the callback is redeeming for.

    Returns:
        The validated token payload (``sub``, ``tid``, ``dom``, ``app``, ``rd``,
        ``nonce``, ``exp``) on success, or None on any failure: bad signature,
        expired token, cross-domain substitution, or replay/double-spend.
    """
    payload = verify_authorization_token(token, expected_domain=expected_domain)
    if payload is None:
        return None

    consumed = database.forward_auth_nonces.consume_nonce(
        database.UNSCOPED,
        payload["nonce"],
        expected_domain,
    )
    if consumed is None:
        # Nonce already spent (replay) or never minted -> reject.
        return None

    # Defense-in-depth: the consumed row's tenant must match the token's bound
    # tenant. The token HMAC already guarantees this, but a mismatch indicates
    # tampering somewhere upstream; fail closed.
    if str(consumed["tenant_id"]) != str(payload["tid"]):
        return None

    return payload


# ---------------------------------------------------------------------------
# Runtime resolution + access decision (iteration 5)
# ---------------------------------------------------------------------------
#
# These helpers run on the portal host / canonical host without a normal
# RequestingUser. They are deliberately fail-closed: an unknown or disabled
# domain/app, or any malformed input, denies access rather than erroring.
# Audit is reduced-verbosity per the design decision (see ITERATION doc):
#   * proxy_access_granted -- only on the FIRST allow of a per-domain session
#     (logged at /callback when the cookie is minted), not on every /check.
#   * proxy_access_denied  -- every denial.
#   * proxy_session_expired -- a /check that fails because the cookie is
#     absent/expired/tampered (the session has lapsed and a re-handshake starts).


def _path_matches_public(path: str, public_paths: list[str]) -> bool:
    """Return True if *path* matches any configured public-path pattern.

    A pattern ending in ``*`` is a prefix match (``/static/*`` matches
    ``/static/app.css``); otherwise it is an exact path match. Patterns are
    rooted relative paths validated at app-config time. The compared path is the
    request path only (query string stripped by the caller).

    SECURITY: a path containing a ``..`` segment is never treated as public. A
    backend that normalizes ``..`` could otherwise turn a public-prefix-matching
    request like ``/static/../admin`` into a protected one (``/admin``), letting
    an unauthenticated caller bypass the gate.
    """
    if ".." in path.split("/"):
        return False
    for pattern in public_paths:
        if pattern.endswith("*"):
            if path.startswith(pattern[:-1]):
                return True
        elif path == pattern:
            return True
    return False


def get_canonical_tenant_host(tenant_id: str) -> str | None:
    """Return the canonical ``<subdomain>.<BASE_DOMAIN>`` host for a tenant.

    Used by /start to redirect the browser from the portal host to the tenant's
    own WeftID host where the central session lives. Returns None if the tenant
    cannot be resolved or BASE_DOMAIN is unset (fail closed).
    """
    if not settings.BASE_DOMAIN:
        return None
    row = database.tenants.get_tenant_by_id(tenant_id)
    if not row or not row.get("subdomain"):
        return None
    return f"{row['subdomain']}.{settings.BASE_DOMAIN}"


def _verified_domain_row(tenant_id: str, domain: str) -> dict | None:
    """Return the protected-domain row for *domain* iff verified + enabled."""
    if not domain:
        return None
    row = database.protected_domains.get_protected_domain_by_domain(tenant_id, domain)
    if not row:
        return None
    if row["verification_status"] != "verified" or not row["enabled"]:
        return None
    return row


def resolve_proxy_app_by_host(
    *,
    tenant_id: str,
    domain: str,
    external_host: str,
) -> dict | None:
    """Resolve the enabled proxy app for a verified domain + forwarded host.

    Single indexed lookup (the /check hot path): resolves the verified domain
    then the enabled app fronting *external_host* under it. Returns None (fail
    closed) for an unverified/disabled domain or no matching enabled app.
    """
    domain_row = _verified_domain_row(tenant_id, domain)
    if domain_row is None or not external_host:
        return None
    return database.proxy_apps.get_enabled_proxy_app_for_domain_and_host(
        tenant_id, str(domain_row["id"]), external_host
    )


def resolve_sole_enabled_app(*, tenant_id: str, domain: str) -> dict | None:
    """Return the domain's single enabled app, or None if 0 or >1 exist.

    Used by /check when the proxy did not convey a distinguishing original host.
    Ambiguity (multiple enabled apps) fails closed rather than guessing.
    """
    domain_row = _verified_domain_row(tenant_id, domain)
    if domain_row is None:
        return None
    apps = database.proxy_apps.list_proxy_apps_for_domain(tenant_id, str(domain_row["id"]))
    enabled = [a for a in apps if a.get("enabled")]
    if len(enabled) == 1:
        return enabled[0]
    return None


def get_tenant_verified_domain(*, tenant_id: str, domain: str, portal_host: str) -> dict | None:
    """Return the verified protected-domain row for /authorize, fail-closed.

    Asserts the domain belongs to THIS tenant, is verified+enabled, and that the
    supplied portal_host matches the registered portal host (so a forged
    portal_host query cannot redirect the minted token elsewhere).
    """
    domain_row = _verified_domain_row(tenant_id, domain)
    if domain_row is None:
        return None
    if _normalize_host_value(domain_row["portal_host"]) != _normalize_host_value(portal_host):
        return None
    return domain_row


def resolve_app_for_rd(*, tenant_id: str, protected_domain_id: str, rd: str) -> dict | None:
    """Resolve which enabled app under a domain owns the redirect destination *rd*.

    If *rd* is an absolute https URL, match its host against an enabled app under
    the domain. If *rd* is a rooted relative path (no host), fall back to the
    domain's sole enabled app. Returns None on ambiguity / no match (fail closed).
    """
    host = ""
    if rd:
        parts = urlsplit(rd)
        if parts.scheme == "https" and parts.hostname:
            host = _normalize_host_value(parts.hostname)

    if host:
        return database.proxy_apps.get_enabled_proxy_app_for_domain_and_host(
            tenant_id, protected_domain_id, host
        )
    apps = database.proxy_apps.list_proxy_apps_for_domain(tenant_id, protected_domain_id)
    enabled = [a for a in apps if a.get("enabled")]
    if len(enabled) == 1:
        return enabled[0]
    return None


def get_app_for_callback(*, tenant_id: str, proxy_app_id: str) -> dict | None:
    """Fetch the enabled proxy app bound to a redeemed token, fail-closed."""
    row = database.proxy_apps.get_proxy_app(tenant_id, proxy_app_id)
    if not row or not row.get("enabled"):
        return None
    return row


def _normalize_host_value(value: str | None) -> str:
    """Normalize a host: strip port + trailing dots, lowercase."""
    return (value or "").split(":")[0].rstrip(".").lower()


# Mapping from the app's header_config keys to the response header names. Only
# keys explicitly enabled in the app's config are emitted; values come solely
# from the authenticated identity (never reflected from request headers).
_HEADER_NAMES = {
    "user": "X-Forwarded-User",
    "email": "X-Forwarded-Email",
    "groups": "X-Forwarded-Groups",
    "display_name": "X-Forwarded-Display-Name",
}


def build_forwarded_headers(app_row: dict, identity: dict[str, Any]) -> dict[str, str]:
    """Build the X-Forwarded-* identity headers honoring the app's header_config.

    SECURITY: every value comes from *identity* (the validated per-domain cookie /
    central session), never from a request header. Header values are sanitized of
    CR/LF to prevent response splitting. A header is emitted only when its key is
    enabled in the app's header_config.
    """
    config = app_row.get("header_config") or {}
    headers: dict[str, str] = {}

    def _clean(value: str) -> str:
        return value.replace("\r", "").replace("\n", "")

    if config.get("user"):
        headers[_HEADER_NAMES["user"]] = _clean(str(identity.get("user_id", "")))
    if config.get("email"):
        headers[_HEADER_NAMES["email"]] = _clean(str(identity.get("email", "")))
    if config.get("display_name"):
        headers[_HEADER_NAMES["display_name"]] = _clean(str(identity.get("display_name", "")))
    if config.get("groups"):
        groups = identity.get("groups") or []
        joined = ",".join(_clean(str(g)) for g in groups)
        headers[_HEADER_NAMES["groups"]] = joined
    return headers


def is_public_path(app_row: dict, path: str) -> bool:
    """Return True if *path* is a configured public path for *app_row*."""
    public_paths = app_row.get("public_paths") or []
    if not isinstance(public_paths, list):
        return False
    return _path_matches_public(path, list(public_paths))


def build_forward_auth_identity(tenant_id: str, user_id: str) -> dict[str, Any] | None:
    """Assemble the minimal identity for the per-domain cookie / forwarded headers.

    Returns a dict with ``user_id``, ``email``, ``display_name`` and ``groups``
    (effective group names), or None if the user cannot be resolved or is
    inactivated/anonymized (fail closed).
    """
    user = database.users.get_user_by_id(tenant_id, user_id)
    if not user or user.get("is_inactivated") or user.get("is_anonymized"):
        return None

    email = database.user_emails.get_primary_email(tenant_id, user_id)
    email_str = email["email"] if email else ""

    first = (user.get("first_name") or "").strip()
    last = (user.get("last_name") or "").strip()
    display_name = f"{first} {last}".strip() or email_str

    groups = database.groups.get_effective_group_names(tenant_id, user_id)

    return {
        "user_id": str(user_id),
        "email": email_str,
        "display_name": display_name,
        "groups": groups,
    }


def authorize_app_access(
    *,
    tenant_id: str,
    user_id: str,
    proxy_app_id: str,
    domain: str,
    app_name: str | None = None,
) -> bool:
    """Decide whether *user_id* may access *proxy_app_id*; audit the denial.

    Runs on the canonical tenant host during /authorize, where the central
    session is known. Uses the shared DAG-aware grant resolver. On denial a
    ``proxy_access_denied`` event is logged (every deny is audited). On allow no
    event is logged here -- the first-allow ``proxy_access_granted`` is logged at
    /callback when the per-domain cookie is actually minted.

    Returns:
        True if access is allowed, False otherwise.
    """
    allowed = database.sp_group_assignments.user_can_access_app(
        tenant_id, user_id, proxy_app_id, proxy_app_id=True
    )
    if not allowed:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=user_id,
            event_type="proxy_access_denied",
            artifact_type="proxy_app",
            artifact_id=proxy_app_id,
            metadata={"domain": domain, "proxy_app_name": app_name},
            dispatch_scim=False,
        )
    return allowed


def log_access_granted(
    *, tenant_id: str, user_id: str, proxy_app_id: str, domain: str, app_name: str | None = None
) -> None:
    """Log the first-allow event for a per-domain session (called at /callback)."""
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        event_type="proxy_access_granted",
        artifact_type="proxy_app",
        artifact_id=proxy_app_id,
        metadata={"domain": domain, "proxy_app_name": app_name},
        dispatch_scim=False,
    )


def log_session_expired(
    *, tenant_id: str, proxy_app_id: str, domain: str, app_name: str | None = None
) -> None:
    """Log a lapsed per-domain session at /check (cookie absent/expired/invalid).

    Uses the system actor: /check has no authenticated user (the cookie is gone),
    so there is no actor to attribute. The event records that a session lapsed
    and a re-handshake will begin.
    """
    from services.event_log import SYSTEM_ACTOR_ID

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        event_type="proxy_session_expired",
        artifact_type="proxy_app",
        artifact_id=proxy_app_id,
        metadata={"domain": domain, "proxy_app_name": app_name},
        dispatch_scim=False,
    )
