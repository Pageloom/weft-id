"""Forward-auth runtime endpoints (the handshake loop).

This wires the Iteration 4 crypto + nonce primitives into the four HTTP
endpoints that gate HTTP apps on arbitrary domains. The flow (see the iteration
doc for the full narrative):

    proxy /check (portal host)
      -> no/expired cookie: 302 /forward-auth/start?rd=<original>
      -> valid cookie:      200 + X-Forwarded-* identity headers
      -> public path:       200 (no session needed)

    /start (portal host)
      -> 302 to the canonical tenant host /forward-auth/authorize

    /authorize (canonical tenant host, central session)
      -> not signed in: stash this URL in the session, 302 to /login (login
         completion returns here via get_post_auth_redirect)
      -> signed in + allowed:  mint token, 302 to portal /forward-auth/callback
      -> signed in + denied:   403 (proxy_access_denied audited)

    /callback (portal host)
      -> validate single-use token, set per-domain cookie, 302 to rd
      -> bad/replayed/cross-domain token: 403

Trust boundary
--------------
Tenant + protected domain are resolved ONLY from the portal host via the
Iteration 2 middleware (``request.state.forward_auth_*``), never from a raw
attacker header. The original protected request (host + path) is conveyed by the
operator's reverse proxy in the standard forward-auth headers (``X-Forwarded-Uri``
/ ``X-Forwarded-Host``); these only ever select an app *within* the already-
trusted, verified domain, and ``rd`` is re-validated against the app's registered
external URL. The ``X-Forwarded-*`` identity RESPONSE headers are built from the
authenticated identity (the per-domain cookie / central session), never reflected
from request headers.
"""

import logging
from typing import Annotated
from urllib.parse import quote, urlsplit

import settings
from dependencies import get_current_user, get_tenant_id_from_request
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from services import forward_auth as forward_auth_service
from services.exceptions import RateLimitError
from utils.forward_auth import (
    FORWARD_AUTH_COOKIE_NAME,
    build_forward_auth_cookie_value,
    forward_auth_cookie_params,
    read_forward_auth_cookie,
)
from utils.ratelimit import MINUTE, ratelimit
from utils.request_metadata import extract_remote_address

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/forward-auth", tags=["forward-auth"], include_in_schema=False)

# Bound on the original-URI / rd query and header values we accept. Generous
# enough for real URLs, small enough to bound work on this pre-auth hot path.
_MAX_URL_LEN = 2048
_MAX_HOST_LEN = 253


def _normalize_host(value: str | None) -> str:
    """Normalize a host value: strip port and trailing dots, lowercase."""
    return (value or "").split(":")[0].rstrip(".").lower()


def _forward_auth_context(request: Request) -> dict | None:
    """Return the middleware-stashed {tenant_id, domain, portal_host} or None.

    These come from TenantGuardMiddleware resolving the VERIFIED portal host.
    If absent, the request did not arrive on a recognized portal host -> fail
    closed.
    """
    tenant_id = getattr(request.state, "forward_auth_tenant_id", None)
    domain = getattr(request.state, "forward_auth_domain", None)
    portal_host = getattr(request.state, "forward_auth_portal_host", None)
    if not tenant_id or not domain or not portal_host:
        return None
    return {"tenant_id": tenant_id, "domain": domain, "portal_host": portal_host}


def _original_request_uri(request: Request) -> str:
    """Extract the original protected request path+query from forward-auth headers.

    Reverse proxies pass the original target URI in ``X-Forwarded-Uri`` (Traefik,
    nginx ``auth_request`` via ``$request_uri``) and fall back to the ``rd`` query
    if present (our own /start sets it). Always a rooted relative path; anything
    else collapses to ``/``.
    """
    uri = request.headers.get("x-forwarded-uri") or ""
    uri = uri[:_MAX_URL_LEN]
    if not uri.startswith("/") or uri.startswith("//"):
        return "/"
    return uri


def _original_host(request: Request, portal_host: str) -> str:
    """Extract the original protected app host from forward-auth headers.

    The operator's proxy sets ``X-Forwarded-Host`` to the protected app's host
    (e.g. grafana.acme-corp.com). When it equals the portal host (single-app
    deployments, or a proxy that rewrites it), the caller falls back to the
    domain's sole enabled app. Bounded and normalized; never used for tenant/
    domain resolution (that comes from the portal host only).
    """
    raw = request.headers.get("x-forwarded-host") or ""
    host = _normalize_host(raw[:_MAX_HOST_LEN])
    if not host or host == portal_host:
        return ""
    return host


def _resolve_app(request: Request, ctx: dict) -> dict | None:
    """Resolve the enabled proxy app for this /check, fail-closed.

    Hot path: at most one indexed query. Uses the forwarded original host when
    present; otherwise, if the verified domain has exactly one enabled app, uses
    that. Returns None when no app can be unambiguously resolved.
    """
    tenant_id = ctx["tenant_id"]
    domain_id_host = _original_host(request, ctx["portal_host"])

    if domain_id_host:
        return forward_auth_service.resolve_proxy_app_by_host(
            tenant_id=tenant_id, domain=ctx["domain"], external_host=domain_id_host
        )
    # No distinguishing host: only safe if the domain has a single enabled app.
    return forward_auth_service.resolve_sole_enabled_app(tenant_id=tenant_id, domain=ctx["domain"])


def _safe_rd(rd: str, app_external_url: str) -> str | None:
    """Validate ``rd`` against the app's registered external URL (no open redirect).

    ``rd`` is the post-handshake destination. It must be an absolute https URL
    whose scheme+host(+port) match the app's external URL, OR a rooted relative
    path (which the browser resolves against the app host). Anything else is
    rejected (returns None).
    """
    if not rd:
        return None
    rd = rd[:_MAX_URL_LEN]

    # Rooted relative path: safe (resolved against the app host by the browser).
    if rd.startswith("/") and not rd.startswith("//"):
        return rd

    parts = urlsplit(rd)
    if parts.scheme != "https" or not parts.netloc:
        return None
    app_parts = urlsplit(app_external_url)
    if _normalize_host(parts.hostname) != _normalize_host(app_parts.hostname):
        return None
    # Ports must match too (default https port treated as absent).
    if (parts.port or 443) != (app_parts.port or 443):
        return None
    return rd


def _deny_response(message: str) -> HTMLResponse:
    """A minimal, no-leak 403 page for the signed-in-but-denied / bad-token case."""
    html = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<title>Access denied</title></head><body style="font-family:system-ui,'
        'sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#374151">'
        '<h1 style="font-size:1.25rem">Access denied</h1>'
        f'<p style="color:#6b7280">{message}</p></body></html>'
    )
    return HTMLResponse(content=html, status_code=403)


# ---------------------------------------------------------------------------
# /check -- the hot path (portal host)
# ---------------------------------------------------------------------------


@router.get("/check")
def forward_auth_check(request: Request) -> Response:
    """Proxy subrequest gate. 200 allow / 302 start / 403 deny / 200 public.

    Runs on the portal host. At most one indexed access query (app resolution)
    plus one cookie verify -- no central-session check, no N+1.
    """
    ctx = _forward_auth_context(request)
    if ctx is None:
        # Not a recognized portal host. Should be unreachable (middleware fails
        # closed first), but never error here.
        return _deny_response("This host is not configured for forward auth.")

    # Rate limit per portal host + client IP. Fail-open if cache is down (the
    # ratelimit util already does this).
    client_ip = extract_remote_address(request) or "unknown"
    try:
        ratelimit.prevent(
            "forward_auth_check:host:{host}:ip:{ip}",
            limit=120,
            timespan=MINUTE,
            host=ctx["portal_host"],
            ip=client_ip,
        )
    except RateLimitError:
        return Response(status_code=429, content="Too many requests")

    app_row = _resolve_app(request, ctx)
    if app_row is None:
        # Unknown/disabled app under this domain -> fail closed (deny, not 500).
        return _deny_response("No application is configured for this address.")

    original_path = _original_request_uri(request).split("?", 1)[0]

    # Public-path bypass: allow without any session.
    if forward_auth_service.is_public_path(app_row, original_path):
        return Response(status_code=200)

    # Pure-TTL cookie check (signature + expiry only).
    cookie_value = request.cookies.get(FORWARD_AUTH_COOKIE_NAME)
    identity = read_forward_auth_cookie(cookie_value)
    if identity is None:
        # No / expired / tampered cookie: the per-domain session has lapsed.
        # Audit the expiry (reduced-verbosity) and start a re-handshake.
        if cookie_value:
            forward_auth_service.log_session_expired(
                tenant_id=ctx["tenant_id"],
                proxy_app_id=str(app_row["id"]),
                domain=ctx["domain"],
                app_name=app_row.get("name"),
            )
        rd = _original_request_uri(request)
        start_url = f"/forward-auth/start?rd={quote(rd, safe='')}"
        return RedirectResponse(url=start_url, status_code=302)

    # Valid cookie -> allow. Build X-Forwarded-* from the authenticated identity
    # ONLY (never reflected from request headers), honoring the app's header_config.
    # The cookie payload uses compact keys (sub/name); map to the identity shape.
    cookie_identity = {
        "user_id": identity.get("sub", ""),
        "email": identity.get("email", ""),
        "display_name": identity.get("name", ""),
        "groups": identity.get("groups", []),
    }
    headers = forward_auth_service.build_forwarded_headers(app_row, cookie_identity)
    return Response(status_code=200, headers=headers)


# ---------------------------------------------------------------------------
# /start -- redirect to the canonical tenant host (portal host)
# ---------------------------------------------------------------------------


@router.get("/start")
def forward_auth_start(
    request: Request,
    rd: Annotated[str, Query(max_length=_MAX_URL_LEN)] = "/",
) -> Response:
    """Begin the handshake: redirect the browser to the tenant host /authorize."""
    ctx = _forward_auth_context(request)
    if ctx is None:
        return _deny_response("This host is not configured for forward auth.")

    canonical_host = forward_auth_service.get_canonical_tenant_host(ctx["tenant_id"])
    if not canonical_host:
        return _deny_response("Sign-in is temporarily unavailable for this domain.")

    # rd is carried opaquely to /authorize and validated against the app there.
    safe_rd = rd[:_MAX_URL_LEN] if rd else "/"
    authorize_url = (
        f"https://{canonical_host}/forward-auth/authorize"
        f"?domain={quote(ctx['domain'], safe='')}"
        f"&portal_host={quote(ctx['portal_host'], safe='')}"
        f"&rd={quote(safe_rd, safe='')}"
    )
    return RedirectResponse(url=authorize_url, status_code=302)


# ---------------------------------------------------------------------------
# /authorize -- mint the token (canonical tenant host, central session)
# ---------------------------------------------------------------------------


@router.get("/authorize")
def forward_auth_authorize(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict | None, Depends(get_current_user)],
    domain: Annotated[str, Query(max_length=_MAX_HOST_LEN)],
    portal_host: Annotated[str, Query(max_length=_MAX_HOST_LEN)],
    rd: Annotated[str, Query(max_length=_MAX_URL_LEN)] = "/",
) -> Response:
    """Authorize the user for the app on the canonical tenant host, mint a token.

    Runs on the tenant's own host where the central WeftID session lives. If the
    user is not signed in, bounce through /login and return here. The domain +
    portal_host must belong to THIS tenant (verified), preventing one tenant from
    minting tokens for another's domain.
    """
    domain_n = _normalize_host(domain)
    portal_host_n = _normalize_host(portal_host)

    # The domain/portal host must be a verified protected domain owned by this
    # tenant. Fail closed otherwise (no token minted).
    app_domain = forward_auth_service.get_tenant_verified_domain(
        tenant_id=tenant_id, domain=domain_n, portal_host=portal_host_n
    )
    if app_domain is None:
        return _deny_response("This domain is not configured for your account.")

    # Not signed in -> send to login. Stash the authorize URL in the session so
    # login completion returns here (honored by get_post_auth_redirect). This is
    # a server-built relative path, never an attacker-controlled redirect target.
    if not user:
        return_to = (
            f"/forward-auth/authorize?domain={quote(domain_n, safe='')}"
            f"&portal_host={quote(portal_host_n, safe='')}&rd={quote(rd, safe='')}"
        )
        request.session["pending_forward_auth_authorize"] = return_to
        return RedirectResponse(url="/login", status_code=302)

    # Resolve the app the rd belongs to, within the verified domain.
    app_row = forward_auth_service.resolve_app_for_rd(
        tenant_id=tenant_id, protected_domain_id=str(app_domain["id"]), rd=rd
    )
    if app_row is None:
        return _deny_response("No application is configured for this address.")

    safe_rd = _safe_rd(rd, app_row["external_url"])
    if safe_rd is None:
        # rd does not belong to this app -> reject (open-redirect guard).
        return _deny_response("Invalid return destination.")

    allowed = forward_auth_service.authorize_app_access(
        tenant_id=tenant_id,
        user_id=str(user["id"]),
        proxy_app_id=str(app_row["id"]),
        domain=domain_n,
        app_name=app_row.get("name"),
    )
    if not allowed:
        return _deny_response("You do not have access to this application.")

    token = forward_auth_service.issue_authorization_token(
        user_id=str(user["id"]),
        tenant_id=tenant_id,
        domain=domain_n,
        app_id=str(app_row["id"]),
        rd=safe_rd,
    )

    callback_url = f"https://{portal_host_n}/forward-auth/callback?token={quote(token, safe='')}"
    return RedirectResponse(url=callback_url, status_code=302)


# ---------------------------------------------------------------------------
# /callback -- redeem token + set per-domain cookie (portal host)
# ---------------------------------------------------------------------------


@router.get("/callback")
def forward_auth_callback(
    request: Request,
    token: Annotated[str, Query(max_length=_MAX_URL_LEN * 2)],
) -> Response:
    """Redeem the single-use token, set the per-domain cookie, redirect to rd."""
    ctx = _forward_auth_context(request)
    if ctx is None:
        return _deny_response("This host is not configured for forward auth.")

    # Single-use redemption bound to THIS portal host's domain. Cross-domain
    # token substitution and replay both return None here.
    payload = forward_auth_service.redeem_authorization_token(token, expected_domain=ctx["domain"])
    if payload is None:
        return _deny_response("Your sign-in link is invalid or has expired.")

    # Defense-in-depth: the token's bound tenant must be the tenant that owns this
    # portal host. redeem already binds {tenant, domain} via the HMAC + nonce, but
    # a mismatch here means something is wrong upstream; fail closed.
    if str(payload["tid"]) != str(ctx["tenant_id"]):
        return _deny_response("Your sign-in link is invalid or has expired.")

    # Re-resolve the app from the token's bound app id + this tenant (the token
    # tenant was already matched in redeem). Build the cookie identity fresh from
    # the current user record (never trust the token for identity attributes).
    app_row = forward_auth_service.get_app_for_callback(
        tenant_id=str(payload["tid"]), proxy_app_id=str(payload["app"])
    )
    if app_row is None:
        return _deny_response("No application is configured for this address.")

    identity = forward_auth_service.build_forward_auth_identity(
        str(payload["tid"]), str(payload["sub"])
    )
    if identity is None:
        return _deny_response("Your account is not active.")

    safe_rd = _safe_rd(str(payload["rd"]), app_row["external_url"])
    if safe_rd is None:
        return _deny_response("Invalid return destination.")

    # First-allow audit for this per-domain session.
    forward_auth_service.log_access_granted(
        tenant_id=str(payload["tid"]),
        user_id=str(payload["sub"]),
        proxy_app_id=str(payload["app"]),
        domain=ctx["domain"],
        app_name=app_row.get("name"),
    )

    cookie_value = build_forward_auth_cookie_value(
        user_id=identity["user_id"],
        email=identity["email"],
        display_name=identity["display_name"],
        groups=identity["groups"],
    )

    response = RedirectResponse(url=safe_rd, status_code=302)
    params = forward_auth_cookie_params(ctx["domain"], secure=not settings.IS_DEV)
    key = params.pop("key")
    response.set_cookie(key=key, value=cookie_value, **params)
    return response
