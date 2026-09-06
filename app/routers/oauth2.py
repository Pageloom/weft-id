"""OAuth2 authorization and token endpoints."""

import base64
import binascii
import secrets
import time
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import unquote, urlparse

import oauth2
import services.oauth2 as oauth2_service
import services.oidc as oidc_service
from dependencies import get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from middleware.csrf import make_csrf_token_func
from schemas.oauth2 import TokenErrorResponse, TokenResponse
from services.oidc.claims import SCOPE_OPENID, parse_scope
from utils.csp_nonce import get_csp_nonce
from utils.templates import templates
from utils.urls import tenant_base_url

# Maximum age for authorization requests (10 minutes)
AUTH_REQUEST_MAX_AGE_SECONDS = 600

router = APIRouter(prefix="/oauth2", tags=["oauth2"], include_in_schema=False)


# ============================================================================
# Authorization Endpoints (GET/POST /oauth2/authorize)
# ============================================================================


@router.get("/authorize", response_class=HTMLResponse)
def authorize_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_current_user)],
    client_id: str,
    redirect_uri: str,
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    scope: Annotated[str | None, Query(max_length=500)] = None,
    nonce: Annotated[str | None, Query(max_length=512)] = None,
):
    """
    OAuth2 authorization endpoint - show authorization page.

    User must be logged in (session cookie) to authorize a client.

    Query Parameters:
        client_id: OAuth2 client ID
        redirect_uri: Redirect URI for authorization code
        state: Optional state parameter
        code_challenge: Optional PKCE code challenge
        code_challenge_method: Optional PKCE challenge method (S256 or plain)
        scope: Optional space-delimited OAuth2/OIDC scopes (e.g. "openid profile")
        nonce: Optional OIDC nonce, bound to the resulting ID token
    """
    # Get client
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client:
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Invalid client_id",
                "error_description": "The client_id provided is not registered.",
                "nav": {},
                "csp_nonce": get_csp_nonce(request),
            },
        )

    # Verify client type is 'normal' (authorization code flow only) and that the
    # client is active. A deactivated client must not render a WeftID-branded
    # consent page or receive an authorization code, even though the token
    # endpoint would later reject the exchange. The error text is identical to
    # the client_type rejection so the page does not disclose whether a client_id
    # exists-but-is-deactivated versus is-the-wrong-type.
    if client["client_type"] != "normal" or not client.get("is_active", True):
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Unauthorized client",
                "error_description": "This client is not authorized for this flow.",
                "nav": {},
                "csp_nonce": get_csp_nonce(request),
            },
        )

    # Verify redirect_uri matches exactly
    if redirect_uri not in (client["redirect_uris"] or []):
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Invalid redirect_uri",
                "error_description": "The redirect_uri does not match registered URIs.",
                "nav": {},
                "csp_nonce": get_csp_nonce(request),
            },
        )

    # Verify PKCE parameters if provided
    if code_challenge and code_challenge_method not in ("S256", "plain"):
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Invalid request",
                "error_description": "Invalid code_challenge_method. Must be S256 or plain.",
                "nav": {},
                "csp_nonce": get_csp_nonce(request),
            },
        )

    # Group-based access control for OIDC-enabled clients ONLY. Plain OAuth2
    # clients are never gated (unchanged behavior). Enforced here, before any
    # authorization code can be issued, so a denied user never sees the consent
    # page and never receives a code/token. The denial is user-visible (error
    # page) and audited (oidc_access_denied).
    if client.get("oidc_enabled") and not oidc_service.user_can_access_client(
        tenant_id=tenant_id,
        user_id=user["id"],
        client_uuid=str(client["id"]),
        client_id=client["client_id"],
        client_name=client.get("name"),
    ):
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Access denied",
                "error_description": (
                    "You do not have access to this application. "
                    "Contact your administrator to request access."
                ),
                "nav": {},
                "csp_nonce": get_csp_nonce(request),
            },
            status_code=403,
        )

    # Requested scopes to display on the consent page for OIDC requests, paired
    # with a human-readable description. Unknown scopes fall back to their raw
    # name so nothing requested is hidden from the user.
    requested_scopes = [
        {"name": s, "description": oidc_service.SCOPE_DESCRIPTIONS.get(s, s)}
        for s in sorted(parse_scope(scope))
    ]

    # Generate unique auth request ID and store parameters in session
    auth_request_id = secrets.token_urlsafe(32)

    # Store authorization request parameters (for validation on POST).
    # Reassign the top-level key so SessionMiddleware marks the session
    # modified (nested mutations do not trigger save in starlette 1.0+).
    auth_requests = dict(request.session.get("oauth2_auth_requests") or {})
    auth_requests[auth_request_id] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "nonce": nonce,
        "created_at": time.time(),
    }
    request.session["oauth2_auth_requests"] = auth_requests

    # Allow the consent form's redirect chain to leave this origin. Chromium
    # applies the consent page's CSP ``form-action`` to every hop that follows
    # the form POST, so the 303 to the client's redirect_uri (and the client's
    # own follow-up redirect on that origin) would be refused under the default
    # ``form-action 'self'``. The redirect_uri was matched exactly against the
    # client's registered URIs above; allow its origin, mirroring the SAML IdP
    # SSO post binding (``routers.saml_idp.sso``).
    request.state.csp_form_action_url = _form_action_origin(redirect_uri)

    # Show authorization page
    return templates.TemplateResponse(
        request,
        "oauth2_authorize.html",
        {
            "client": client,
            "user": user,
            "auth_request_id": auth_request_id,
            "redirect_uri": redirect_uri,
            "requested_scopes": requested_scopes,
            "nav": {},
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


def _form_action_origin(redirect_uri: str) -> str:
    """Return ``scheme://host[:port]`` of a registered redirect_uri for CSP."""
    parts = urlparse(redirect_uri)
    return f"{parts.scheme}://{parts.netloc}"


@router.post("/authorize")
def authorize_grant(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_current_user)],
    auth_request_id: Annotated[str, Form(max_length=50)],
    action: Annotated[str, Form(max_length=20)],
):
    """
    OAuth2 authorization endpoint - handle allow/deny.

    User submits form to allow or deny authorization. The auth_request_id
    references a stored authorization request from the session, preventing
    parameter tampering and providing one-time-use semantics.

    Form Data:
        auth_request_id: Server-generated ID referencing stored auth request
        action: "allow" or "deny"
    """
    # Retrieve stored authorization request from session. Copy and reassign
    # so SessionMiddleware sees the change (nested mutations do not mark the
    # session modified in starlette 1.0+).
    auth_requests = dict(request.session.get("oauth2_auth_requests") or {})
    stored_request = auth_requests.get(auth_request_id)

    if not stored_request:
        # Invalid or missing auth request - show error page
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Invalid request",
                "error_description": "Authorization request not found or already used.",
                "nav": {},
                "csp_nonce": get_csp_nonce(request),
            },
        )

    # Extract stored parameters
    client_id = stored_request["client_id"]
    redirect_uri = stored_request["redirect_uri"]
    state = stored_request["state"]
    code_challenge = stored_request["code_challenge"]
    code_challenge_method = stored_request["code_challenge_method"]
    scope = stored_request.get("scope")
    nonce = stored_request.get("nonce")
    created_at = stored_request["created_at"]

    # Delete from session immediately (one-time use). Reassign so the
    # session is marked modified and the cookie is rewritten.
    del auth_requests[auth_request_id]
    request.session["oauth2_auth_requests"] = auth_requests

    # Validate request hasn't expired
    if time.time() - created_at > AUTH_REQUEST_MAX_AGE_SECONDS:
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Request expired",
                "error_description": "Authorization request has expired. Please start over.",
                "nav": {},
                "csp_nonce": get_csp_nonce(request),
            },
        )

    # Get client
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client or client["client_type"] != "normal" or not client.get("is_active", True):
        # Invalid, wrong-type, or deactivated client: redirect with error and
        # issue no authorization code (defense in depth alongside the GET check).
        # redirect-ok: registered OAuth2 redirect_uri
        return RedirectResponse(
            url=f"{redirect_uri}?error=unauthorized_client" + (f"&state={state}" if state else ""),
            status_code=303,
        )

    # Verify redirect_uri matches (defense in depth - should always match since we stored it)
    if redirect_uri not in (client["redirect_uris"] or []):
        return templates.TemplateResponse(
            request,
            "oauth2_error.html",
            {
                "error": "Invalid redirect_uri",
                "error_description": "The redirect_uri does not match registered URIs.",
                "nav": {},
                "csp_nonce": get_csp_nonce(request),
            },
        )

    # Handle denial
    if action == "deny":
        # redirect-ok: registered OAuth2 redirect_uri
        return RedirectResponse(
            url=f"{redirect_uri}?error=access_denied" + (f"&state={state}" if state else ""),
            status_code=303,
        )

    # Handle approval - create authorization code
    if action == "allow":
        # Defense in depth: re-check group-based access for OIDC-enabled clients
        # at grant time (the GET check gated the consent page, but membership
        # could have changed since). Plain OAuth2 clients are never gated. A
        # denial here redirects with the standard OAuth2 access_denied error so
        # no code is issued.
        if client.get("oidc_enabled") and not oidc_service.user_can_access_client(
            tenant_id=tenant_id,
            user_id=user["id"],
            client_uuid=str(client["id"]),
            client_id=client["client_id"],
            client_name=client.get("name"),
        ):
            # redirect-ok: registered OAuth2 redirect_uri
            return RedirectResponse(
                url=f"{redirect_uri}?error=access_denied" + (f"&state={state}" if state else ""),
                status_code=303,
            )

        # Record the user's authentication time for the OIDC `auth_time` claim.
        # Prefer the session login timestamp (when they actually authenticated);
        # fall back to the code-issuance time when it is unavailable.
        session_start = request.session.get("session_start")
        auth_time = (
            datetime.fromtimestamp(session_start, UTC) if session_start else datetime.now(UTC)
        )

        code = oauth2_service.create_authorization_code(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=user["id"],
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            nonce=nonce,
            auth_time=auth_time,
        )

        # Redirect with authorization code
        # redirect-ok: registered OAuth2 redirect_uri
        return RedirectResponse(
            url=f"{redirect_uri}?code={code}" + (f"&state={state}" if state else ""),
            status_code=303,
        )

    # Invalid action
    # redirect-ok: registered OAuth2 redirect_uri
    return RedirectResponse(
        url=f"{redirect_uri}?error=invalid_request" + (f"&state={state}" if state else ""),
        status_code=303,
    )


# ============================================================================
# Token Endpoint (POST /oauth2/token)
# ============================================================================


# Upper bound for a Basic-auth client_id / client_secret, matching the form
# fields' max_length so both methods enforce the same limit.
_CLIENT_CREDENTIAL_MAX_LENGTH = 255


def _resolve_client_credentials(
    request: Request,
    form_client_id: str | None,
    form_client_secret: str | None,
) -> tuple[str, str] | None:
    """Resolve the token-endpoint client credentials from the request.

    Supports both client authentication methods for confidential clients:

    - ``client_secret_basic``: ``Authorization: Basic base64(id:secret)``,
      with ``id`` and ``secret`` form-urlencoded per RFC 6749 section 2.3.1.
      This is the method the spec says servers MUST support and the OIDC
      discovery default when ``token_endpoint_auth_methods_supported`` is
      omitted.
    - ``client_secret_post``: ``client_id`` + ``client_secret`` form fields.

    Returns ``(client_id, client_secret)``, or ``None`` when no usable
    credentials were supplied. A request carrying BOTH a Basic header and
    form credentials is rejected (RFC 6749 section 2.3: a client must not
    use more than one authentication method per request), as is a malformed
    or over-long Basic header.
    """
    authorization = request.headers.get("authorization", "")
    scheme, _, encoded = authorization.partition(" ")
    has_basic = scheme.lower() == "basic" and bool(encoded.strip())
    has_form = bool(form_client_id) or bool(form_client_secret)

    if has_basic and has_form:
        return None

    if has_basic:
        try:
            decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
        except binascii.Error, UnicodeDecodeError, ValueError:
            return None
        raw_id, sep, raw_secret = decoded.partition(":")
        if not sep:
            return None
        basic_id = unquote(raw_id)
        basic_secret = unquote(raw_secret)
        if not basic_id or not basic_secret:
            return None
        if (
            len(basic_id) > _CLIENT_CREDENTIAL_MAX_LENGTH
            or len(basic_secret) > _CLIENT_CREDENTIAL_MAX_LENGTH
        ):
            return None
        return basic_id, basic_secret

    if form_client_id and form_client_secret:
        return form_client_id, form_client_secret

    return None


@router.post("/token", response_model=TokenResponse, responses={400: {"model": TokenErrorResponse}})
def token_endpoint(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    grant_type: Annotated[str, Form(max_length=50)],
    client_id: Annotated[str | None, Form(max_length=255)] = None,
    client_secret: Annotated[str | None, Form(max_length=255)] = None,
    code: Annotated[str | None, Form(max_length=255)] = None,
    redirect_uri: Annotated[str | None, Form(max_length=2048)] = None,
    code_verifier: Annotated[str | None, Form(max_length=255)] = None,
    refresh_token: Annotated[str | None, Form(max_length=255)] = None,
):
    """
    OAuth2 token endpoint - exchange authorization code or refresh token for access token.

    Supports three grant types:
    1. authorization_code - Exchange auth code for access + refresh tokens
    2. refresh_token - Refresh access token using refresh token
    3. client_credentials - Get access token using client credentials (B2B)

    Client authentication (RFC 6749 section 2.3.1): either HTTP Basic
    (``client_secret_basic``, the Authorization header) or the ``client_id`` +
    ``client_secret`` form fields (``client_secret_post``). Exactly one method
    must be used per request.

    Form Data:
        grant_type: "authorization_code", "refresh_token", or "client_credentials"
        client_id: OAuth2 client ID (client_secret_post; omit when using Basic)
        client_secret: OAuth2 client secret (client_secret_post; omit when using Basic)
        code: Authorization code (for authorization_code grant)
        redirect_uri: Redirect URI (for authorization_code grant, must match)
        code_verifier: PKCE code verifier (if PKCE was used)
        refresh_token: Refresh token (for refresh_token grant)
    """
    credentials = _resolve_client_credentials(request, client_id, client_secret)
    if credentials is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_client",
                "error_description": "Client authentication failed",
            },
        )
    client_id, client_secret = credentials

    # Get and validate client
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_client",
                "error_description": "Client authentication failed",
            },
        )

    # Verify client secret
    if not oauth2.verify_token_hash(client_secret, client["client_secret_hash"]):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_client",
                "error_description": "Client authentication failed",
            },
        )

    # Check if client is active
    if not client.get("is_active", True):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_client",
                "error_description": "Client is deactivated",
            },
        )

    # ========================================================================
    # Grant Type: authorization_code
    # ========================================================================
    if grant_type == "authorization_code":
        # Validate client type
        if client["client_type"] != "normal":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unauthorized_client",
                    "error_description": "Client is not authorized for this grant type",
                },
            )

        # Validate required parameters
        if not code or not redirect_uri:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "error_description": "Missing required parameter: code or redirect_uri",
                },
            )

        # Validate and consume authorization code
        code_data = oauth2_service.validate_and_consume_code(
            tenant_id=tenant_id,
            code=code,
            client_id=client["id"],
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

        if not code_data:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired authorization code",
                },
            )

        granted_scope = code_data.get("scope")

        # Create refresh token (carrying the granted scope so the refresh_token
        # grant can mint access tokens with the same scope)
        refresh_token_str, refresh_token_id = oauth2_service.create_refresh_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=code_data["user_id"],
            scope=granted_scope,
        )

        # Create access token (carrying the granted scope for downstream userinfo)
        access_token_str = oauth2_service.create_access_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=code_data["user_id"],
            parent_token_id=refresh_token_id,
            scope=granted_scope,
        )

        # Issue an OIDC ID token only when the client has opted into OIDC AND the
        # request carried the `openid` scope. Plain OAuth2 clients are unaffected.
        id_token_str: str | None = None
        scopes = parse_scope(granted_scope)
        if client.get("oidc_enabled") and SCOPE_OPENID in scopes:
            id_token_str = oidc_service.issue_id_token(
                tenant_id=tenant_id,
                issuer=tenant_base_url(request),
                client_uuid=str(client["id"]),
                client_id=client["client_id"],
                user_id=code_data["user_id"],
                scopes=scopes,
                nonce=code_data.get("nonce"),
                auth_time=code_data.get("auth_time"),
            )

        return TokenResponse(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=int(oauth2.ACCESS_TOKEN_EXPIRY.total_seconds()),
            refresh_token=refresh_token_str,
            id_token=id_token_str,
        )

    # ========================================================================
    # Grant Type: refresh_token
    # ========================================================================
    elif grant_type == "refresh_token":
        # Validate required parameters
        if not refresh_token:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_request",
                    "error_description": "Missing required parameter: refresh_token",
                },
            )

        # Validate refresh token
        token_data = oauth2_service.validate_refresh_token(
            tenant_id=tenant_id,
            token=refresh_token,
            client_id=client["id"],
        )

        if not token_data:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired refresh token",
                },
            )

        # Re-check group-based access before minting a fresh access token. Access
        # is enforced only at authorize time, so without this a user whose grant
        # was revoked (removed from the assigned group, or the client switched off
        # available_to_all) could keep exchanging their refresh token for new
        # access tokens for the full 30-day refresh window. Plain OAuth2 clients
        # are never gated. Bounds exposure to the 1-hour access-token lifetime;
        # revocation on grant withdrawal (services.oidc.clients) closes the gap.
        if client.get("oidc_enabled") and not oidc_service.user_can_access_client(
            tenant_id=tenant_id,
            user_id=str(token_data["user_id"]),
            client_uuid=str(client["id"]),
            client_id=client["client_id"],
            client_name=client.get("name"),
        ):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_grant",
                    "error_description": "Access has been revoked",
                },
            )

        # Create new access token (linked to refresh token). Carry forward the
        # scope granted at authorization so downstream userinfo keeps returning
        # the same claims across refreshes. This grant does not rotate the
        # refresh token, so there is no rotated token to re-persist scope onto.
        access_token_str = oauth2_service.create_access_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=token_data["user_id"],
            parent_token_id=token_data["id"],
            scope=token_data.get("scope"),
        )

        return TokenResponse(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=int(oauth2.ACCESS_TOKEN_EXPIRY.total_seconds()),
            refresh_token=None,  # Don't return refresh token on refresh
        )

    # ========================================================================
    # Grant Type: client_credentials
    # ========================================================================
    elif grant_type == "client_credentials":
        # Validate client type
        if client["client_type"] != "b2b":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unauthorized_client",
                    "error_description": "Client is not authorized for this grant type",
                },
            )

        # Get service user ID
        service_user_id = client["service_user_id"]
        if not service_user_id:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "server_error",
                    "error_description": "Client configuration error: missing service user",
                },
            )

        # Create access token (24h expiry, no refresh token)
        access_token_str = oauth2_service.create_access_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=service_user_id,
            is_client_credentials=True,
        )

        return TokenResponse(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=int(oauth2.CLIENT_CREDENTIALS_TOKEN_EXPIRY.total_seconds()),
            refresh_token=None,  # No refresh token for client credentials
        )

    # ========================================================================
    # Unsupported grant type
    # ========================================================================
    else:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_grant_type",
                "error_description": f"Grant type '{grant_type}' is not supported",
            },
        )
