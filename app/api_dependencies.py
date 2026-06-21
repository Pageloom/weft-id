"""FastAPI dependencies for API endpoints with dual authentication support."""

import hashlib
import logging
import secrets
from typing import Annotated, TypedDict

import database
from dependencies import get_tenant_id_from_request
from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import APIKeyCookie, OAuth2PasswordBearer
from services.exceptions import RateLimitError
from utils import auth
from utils.ratelimit import MINUTE, ratelimit
from utils.request_context import set_api_client_context

logger = logging.getLogger(__name__)

# Security schemes for OpenAPI documentation
# These are used to show the "Authorize" button in Swagger UI
# auto_error=False because we handle authentication manually in get_current_user_api
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/oauth2/token", auto_error=False)
session_cookie_scheme = APIKeyCookie(name="session", auto_error=False)

_CSRF_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Upper bound on the inbound SCIM bearer token length, enforced before the
# pre-auth sha256 so an oversized Authorization header can't drive work
# proportional to attacker input. WeftID-minted tokens are 64 hex chars;
# 512 leaves generous headroom for any third-party provider token format.
_MAX_BEARER_TOKEN_LEN = 512


def _validate_session_csrf(request: Request) -> None:
    """Validate CSRF token for session-cookie-authenticated API requests.

    Safe methods (GET, HEAD, OPTIONS) are exempt. For state-changing methods,
    the X-CSRF-Token header must match the session token.
    """
    if request.method in _CSRF_SAFE_METHODS:
        return
    session_token = request.session.get("_csrf_token")
    request_token = request.headers.get("X-CSRF-Token")
    if not session_token or not request_token:
        raise HTTPException(status_code=403, detail="CSRF token required")
    if not secrets.compare_digest(session_token, request_token):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")


def get_current_user_api(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    authorization: Annotated[str | None, Header()] = None,
) -> dict:
    """
    Get the currently authenticated user from either Bearer token OR session cookie.

    This dependency supports dual authentication:
    1. Bearer token in Authorization header (OAuth2)
    2. Session cookie (existing web authentication)

    Args:
        request: FastAPI request object
        tenant_id: Tenant ID extracted from hostname
        authorization: Authorization header (optional)

    Returns:
        dict: The authenticated user data

    Raises:
        HTTPException: 401 if not authenticated

    Example:
        # Bearer token authentication
        Authorization: Bearer weft-id_access_abc123...

        # Session cookie authentication
        Cookie: session=...
    """
    # Try Bearer token first
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]

        # Validate token (scoped to the tenant from request)
        token_data = database.oauth2.validate_token(token, tenant_id)

        if token_data:
            # Token is valid and matches tenant
            # Get user from token's user_id
            user = database.users.get_user_by_id(tenant_id, token_data["user_id"])

            if user:
                # Set API client context for event logging
                # token_data["client_id"] is the internal UUID (FK to oauth2_clients.id)
                client = database.oauth2.get_client_by_id(tenant_id, str(token_data["client_id"]))
                if client:
                    set_api_client_context(
                        client_id=client["client_id"],
                        client_name=client["name"],
                        client_type=client["client_type"],
                    )

                # Add primary email to user dict (API responses include email)
                primary_email = database.user_emails.get_primary_email(tenant_id, user["id"])
                if primary_email:
                    user["email"] = primary_email["email"]
                return user

    # Fall back to session cookie
    user = auth.get_current_user(request, tenant_id)
    if user:
        _validate_session_csrf(request)
        # Force-profile-completion gate: cookie-authed callers cannot use the
        # API while flagged. Bearer-token clients (machine API) are exempt
        # since they cannot complete a profile.
        if user.get("force_profile_completion"):
            raise HTTPException(
                status_code=403,
                detail={
                    "detail": "Profile completion required",
                    "error_code": "profile_completion_required",
                },
            )
        # Add primary email to user dict (API responses include email)
        primary_email = database.user_emails.get_primary_email(tenant_id, user["id"])
        if primary_email:
            user["email"] = primary_email["email"]
        return user

    # Not authenticated via either method
    raise HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_admin_api(
    user: Annotated[dict, Depends(get_current_user_api)],
) -> dict:
    """
    Require admin or super_admin role for API endpoints.

    Args:
        user: Authenticated user from get_current_user_api

    Returns:
        dict: The authenticated user data with admin role

    Raises:
        HTTPException: 403 if user lacks admin permissions
    """
    user_role = user.get("role")
    if user_role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return user


# ============================================================================
# Inbound SCIM bearer-token authentication
# ============================================================================
#
# The inbound SCIM endpoint family at `/scim/v2/inbound/{idp_id}/` uses
# its own bearer-token scheme (not OAuth2). Tokens are stored hash-only
# in `scim_inbound_tokens`, bound to a single `saml_identity_providers`
# row, and revoked instantly (no grace window). Auth failures all return
# the same SCIM-shaped 401 envelope -- no tenancy / IdP leakage in
# error messages.
#
# This dep is intentionally NOT compatible with `get_current_user_api`:
# inbound SCIM has no concept of a WeftID user session; the token IS
# the credential, and its `idp_id` IS the request scope.


class InboundScimContext(TypedDict):
    """Authentication context for an authenticated inbound SCIM request.

    Set by `require_inbound_scim_auth` on success. The router uses
    `tenant_id` + `idp_id` to scope all downstream database queries;
    `token_id` is recorded so event-log entries (iteration 3+) can
    point at the exact credential that authorised the call.
    """

    tenant_id: str
    idp_id: str
    token_id: str


def _raise_scim_auth_error(reason: str) -> None:
    """Always raise the same SCIM-shaped 401, regardless of `reason`.

    `reason` is logged server-side so operators can debug auth failures
    (token format, unknown hash, revoked, wrong tenant for idp_id) but
    NEVER returned to the caller. The client always sees the same
    "Authentication required" detail so they cannot probe for which
    IdP ids exist or which tenants own them.
    """
    # Import locally to avoid a circular import (router -> deps -> router).
    from routers.scim.inbound.errors import ScimErrorException

    logger.info("inbound SCIM auth rejected: %s", reason)
    raise ScimErrorException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Bearer realm="WeftID inbound SCIM"'},
    )


def require_inbound_scim_auth(
    request: Request,
    idp_id: str,
    authorization: Annotated[str | None, Header()] = None,
) -> InboundScimContext:
    """Validate the inbound SCIM bearer token and resolve request scope.

    Validation rules:
    - `Authorization` header must be present and shaped `Bearer <token>`.
    - The token's SHA-256 hash must match an existing row in
      `scim_inbound_tokens`.
    - The row must not be revoked.
    - The row's `idp_id` must equal the `{idp_id}` URL segment (no
      cross-IdP / cross-tenant token reuse).

    Side effects on success:
    - Updates `last_used_at` (best-effort; failures are logged but
      do not block the request).

    Rate limit: 60 / minute keyed by client IP to deter blind
    brute-force token guessing.
    Authenticated traffic from an IdP will never hit this -- only
    unauthenticated probing.
    """
    client_host = request.client.host if request.client else "unknown"
    try:
        ratelimit.prevent(
            "scim_inbound_auth:ip:{ip}",
            limit=60,
            timespan=MINUTE,
            ip=client_host,
        )
    except RateLimitError as exc:
        # Import locally to keep the module-level dependency surface
        # focused on what the happy path uses.
        from routers.scim.inbound.errors import ScimErrorException

        raise ScimErrorException(
            status_code=429,
            detail="Too many requests",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None

    if not authorization or not authorization.startswith("Bearer "):
        _raise_scim_auth_error("missing or malformed Authorization header")

    # mypy: _raise_scim_auth_error always raises; subscript is safe
    assert authorization is not None
    token_plaintext = authorization.split(" ", 1)[1].strip()
    if not token_plaintext:
        _raise_scim_auth_error("empty bearer token")

    # Bound the token length before hashing. WeftID-minted inbound SCIM
    # tokens are 64 hex chars; any legitimate provider token is well under
    # this ceiling. Rejecting oversized headers here keeps the pre-auth
    # hash path from doing work proportional to attacker-controlled input
    # rather than relying on the reverse proxy's header-size limits.
    if len(token_plaintext) > _MAX_BEARER_TOKEN_LEN:
        _raise_scim_auth_error("bearer token too long")

    digest = hashlib.sha256(token_plaintext.encode("utf-8")).hexdigest()

    # UNSCOPED lookup -- the request tenant isn't known until the token
    # resolves. The unique hash index (added in iteration 1's migration)
    # blocks the cross-tenant collision that would otherwise be the risk
    # of UNSCOPED lookups: two tenants cannot accidentally share a hash.
    row = database.scim_inbound_tokens.get_by_hash(database.UNSCOPED, digest)
    if row is None:
        _raise_scim_auth_error("unknown token hash")
    assert row is not None  # for mypy
    if row.get("revoked_at") is not None:
        _raise_scim_auth_error(f"revoked token {row['id']}")
    if str(row["idp_id"]) != str(idp_id):
        _raise_scim_auth_error(
            f"token {row['id']} bound to idp {row['idp_id']} but URL specifies idp {idp_id}"
        )

    tenant_id = str(row["tenant_id"])
    token_id = str(row["id"])

    # Best-effort touch. A failure here (DB blip, RLS misconfiguration)
    # should not stop the inbound SCIM request from completing; the
    # touch is observability, not authorisation.
    try:
        database.scim_inbound_tokens.touch_last_used(tenant_id, token_id)
    except Exception:  # noqa: BLE001 -- observability path, never fatal
        logger.warning("inbound SCIM last_used touch failed for token %s", token_id)

    return InboundScimContext(
        tenant_id=tenant_id,
        idp_id=str(idp_id),
        token_id=token_id,
    )


def require_super_admin_api(
    user: Annotated[dict, Depends(get_current_user_api)],
) -> dict:
    """
    Require super_admin role for API endpoints.

    Args:
        user: Authenticated user from get_current_user_api

    Returns:
        dict: The authenticated user data with super_admin role

    Raises:
        HTTPException: 403 if user lacks super_admin permissions
    """
    user_role = user.get("role")
    if user_role != "super_admin":
        raise HTTPException(
            status_code=403,
            detail="Super admin access required",
        )

    return user
