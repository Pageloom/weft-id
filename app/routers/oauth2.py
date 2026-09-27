"""OAuth2 authorization and token endpoints.

Architectural Note: this module contains a direct ``log_event()`` call for the
``user_signed_out`` event raised when a relying party forces re-authentication
(``prompt=login``, an exceeded ``max_age``, or an ``id_token_hint`` for another
user). Like ``routers/auth/logout.py``, this is session termination at the HTTP
boundary, an accepted exception to the "event logging in services" pattern.
"""

import base64
import binascii
import json
import secrets
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import unquote, urlencode, urlparse

import oauth2
import services.oauth2 as oauth2_service
import services.oidc as oidc_service
from dependencies import get_current_user, get_tenant_id_from_request, require_current_user
from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from middleware.csrf import make_csrf_token_func
from routers.auth.logout import end_oidc_session_quietly, frontchannel_logout_response
from routers.saml_idp._helpers import PENDING_OAUTH2_AUTHORIZE_KEY
from schemas.oauth2 import TokenErrorResponse, TokenResponse
from services.event_log import log_event
from services.oidc.claims import SCOPE_OPENID, parse_scope
from utils.csp_nonce import get_csp_nonce
from utils.redirects import safe_redirect
from utils.request_metadata import extract_request_metadata
from utils.session import ensure_session_id
from utils.templates import templates
from utils.urls import tenant_base_url

# Maximum age for authorization requests (10 minutes)
AUTH_REQUEST_MAX_AGE_SECONDS = 600

# ``prompt`` values (OpenID Connect Core 1.0, section 3.1.2.1). Values that
# demand a fresh authentication even when a session exists.
REAUTH_PROMPT_VALUES = frozenset({"login", "select_account"})

# The only response type the authorization endpoint issues.
SUPPORTED_RESPONSE_TYPES = frozenset({"code"})

# Upper bound for ``state``, matching the parameter's max_length.
_MAX_STATE_LENGTH = 2048

# How the authorization response is delivered (OAuth 2.0 Multiple Response
# Type Encoding Practices; OAuth 2.0 Form Post Response Mode). ``query`` is the
# default for ``response_type=code``.
DEFAULT_RESPONSE_MODE = "query"
SUPPORTED_RESPONSE_MODES = frozenset({"query", "form_post"})

router = APIRouter(prefix="/oauth2", tags=["oauth2"], include_in_schema=False)


# ============================================================================
# Authorization Endpoint (GET/POST /oauth2/authorize)
# ============================================================================


@dataclass(frozen=True)
class AuthorizeParams:
    """The authorization request parameters, identical for GET and POST.

    Every OpenID Connect Core 1.0 section 3.1.2.1 parameter is declared so the
    request can be stashed and resumed after login without loss. Parameters
    that are accepted but have no effect today (``display``, ``ui_locales``,
    ``claims_locales``, ``acr_values``) are kept so a resumed request is the
    request the RP sent.
    """

    client_id: str | None = None
    redirect_uri: str | None = None
    response_type: str | None = None
    state: str | None = None
    scope: str | None = None
    nonce: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    prompt: str | None = None
    max_age: str | None = None
    login_hint: str | None = None
    id_token_hint: str | None = None
    request_object: str | None = None  # the ``request`` parameter
    request_uri: str | None = None
    response_mode: str | None = None
    display: str | None = None
    ui_locales: str | None = None
    claims_locales: str | None = None
    acr_values: str | None = None

    def as_query(self, *, strip_reauth: bool = False) -> list[tuple[str, str]]:
        """Return the present parameters as query pairs, in declaration order.

        With ``strip_reauth`` the parameters that demanded a fresh login
        (``prompt=login``/``select_account`` and ``max_age``) are removed, so
        the request resumed after that login does not demand another one.
        """
        pairs: list[tuple[str, str]] = []
        for name, value in asdict(self).items():
            if value is None:
                continue
            key = "request" if name == "request_object" else name
            if strip_reauth:
                if key == "max_age":
                    continue
                if key == "prompt":
                    value = " ".join(v for v in value.split() if v not in REAUTH_PROMPT_VALUES)
                    if not value:
                        continue
            pairs.append((key, value))
        return pairs


@router.get("/authorize", response_class=HTMLResponse)
def authorize_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict | None, Depends(get_current_user)],
    client_id: Annotated[str | None, Query(max_length=255)] = None,
    redirect_uri: Annotated[str | None, Query(max_length=2048)] = None,
    response_type: Annotated[str | None, Query(max_length=50)] = None,
    state: Annotated[str | None, Query(max_length=2048)] = None,
    scope: Annotated[str | None, Query(max_length=500)] = None,
    nonce: Annotated[str | None, Query(max_length=512)] = None,
    code_challenge: Annotated[str | None, Query(max_length=255)] = None,
    code_challenge_method: Annotated[str | None, Query(max_length=50)] = None,
    prompt: Annotated[str | None, Query(max_length=50)] = None,
    max_age: Annotated[str | None, Query(max_length=20)] = None,
    login_hint: Annotated[str | None, Query(max_length=320)] = None,
    id_token_hint: Annotated[str | None, Query(max_length=8192)] = None,
    request_object: Annotated[str | None, Query(alias="request", max_length=8192)] = None,
    request_uri: Annotated[str | None, Query(max_length=2048)] = None,
    response_mode: Annotated[str | None, Query(max_length=50)] = None,
    display: Annotated[str | None, Query(max_length=50)] = None,
    ui_locales: Annotated[str | None, Query(max_length=255)] = None,
    claims_locales: Annotated[str | None, Query(max_length=255)] = None,
    acr_values: Annotated[str | None, Query(max_length=255)] = None,
):
    """
    OAuth2/OIDC authorization endpoint (GET).

    Validates the request, authenticates the user (sending them through the
    login flow with this request stashed in the session when needed), then
    shows the consent page. See ``_handle_authorize_request`` for the order
    of operations and the ``prompt``/``max_age``/hint semantics.

    Query Parameters (OpenID Connect Core 1.0, section 3.1.2.1):
        client_id: OAuth2 client ID (required; invalid values render an error page)
        redirect_uri: Registered redirect URI (required; exact match; invalid
            values render an error page and never redirect)
        response_type: Must be "code"
        state: Opaque value echoed back to the RP
        scope: Space-delimited scopes (e.g. "openid profile email")
        nonce: OIDC nonce, bound to the resulting ID token
        code_challenge: PKCE code challenge
        code_challenge_method: PKCE method (S256 or plain)
        prompt: none | login | consent | select_account (space-separated)
        max_age: Maximum authentication age in seconds
        login_hint: Pre-fills the email step of the login page
        id_token_hint: A WeftID-issued ID token identifying the expected user
        request, request_uri: Not supported; rejected with
            request_not_supported / request_uri_not_supported
        response_mode: query (default) or form_post; decides how the code or
            error is delivered to the redirect_uri. Other values are
            invalid_request.
        display, ui_locales, claims_locales, acr_values: Accepted and ignored
    """
    return _handle_authorize_request(
        request,
        tenant_id,
        user,
        AuthorizeParams(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            state=state,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            prompt=prompt,
            max_age=max_age,
            login_hint=login_hint,
            id_token_hint=id_token_hint,
            request_object=request_object,
            request_uri=request_uri,
            response_mode=response_mode,
            display=display,
            ui_locales=ui_locales,
            claims_locales=claims_locales,
            acr_values=acr_values,
        ),
    )


@router.post("/authorize", response_class=HTMLResponse)
def authorize_post(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict | None, Depends(get_current_user)],
    client_id: Annotated[str | None, Form(max_length=255)] = None,
    redirect_uri: Annotated[str | None, Form(max_length=2048)] = None,
    response_type: Annotated[str | None, Form(max_length=50)] = None,
    state: Annotated[str | None, Form(max_length=2048)] = None,
    scope: Annotated[str | None, Form(max_length=500)] = None,
    nonce: Annotated[str | None, Form(max_length=512)] = None,
    code_challenge: Annotated[str | None, Form(max_length=255)] = None,
    code_challenge_method: Annotated[str | None, Form(max_length=50)] = None,
    prompt: Annotated[str | None, Form(max_length=50)] = None,
    max_age: Annotated[str | None, Form(max_length=20)] = None,
    login_hint: Annotated[str | None, Form(max_length=320)] = None,
    id_token_hint: Annotated[str | None, Form(max_length=8192)] = None,
    request_object: Annotated[str | None, Form(alias="request", max_length=8192)] = None,
    request_uri: Annotated[str | None, Form(max_length=2048)] = None,
    response_mode: Annotated[str | None, Form(max_length=50)] = None,
    display: Annotated[str | None, Form(max_length=50)] = None,
    ui_locales: Annotated[str | None, Form(max_length=255)] = None,
    claims_locales: Annotated[str | None, Form(max_length=255)] = None,
    acr_values: Annotated[str | None, Form(max_length=255)] = None,
):
    """
    OAuth2/OIDC authorization endpoint (POST).

    Accepts the same parameters as the GET form, as form-encoded body fields
    (OpenID Connect Core 1.0, section 3.1.2.1 permits either method), and
    behaves identically. This path is exempt from CSRF validation because the
    request originates at the relying party; it is validated against the
    client's registration, never trusted from the session. The consent form
    submits to ``/oauth2/authorize/decision``, not here.

    Form Data: see ``authorize_page`` for the parameter list.
    """
    return _handle_authorize_request(
        request,
        tenant_id,
        user,
        AuthorizeParams(
            client_id=client_id,
            redirect_uri=redirect_uri,
            response_type=response_type,
            state=state,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            prompt=prompt,
            max_age=max_age,
            login_hint=login_hint,
            id_token_hint=id_token_hint,
            request_object=request_object,
            request_uri=request_uri,
            response_mode=response_mode,
            display=display,
            ui_locales=ui_locales,
            claims_locales=claims_locales,
            acr_values=acr_values,
        ),
    )


def _handle_authorize_request(
    request: Request,
    tenant_id: str,
    user: dict | None,
    params: AuthorizeParams,
) -> Response:
    """Process an authorization request (shared by GET and POST).

    Order of operations, per OpenID Connect Core 1.0 section 3.1.2.2 to
    3.1.2.4 and RFC 6749 section 4.1.2.1:

    1. ``client_id`` and ``redirect_uri`` are validated first. A failure here
       renders the error page and never redirects, because there is no
       trustworthy place to redirect to. This happens before any session
       check so an unauthenticated request with a bad client is not bounced
       through login.
    2. Every other parameter error is reported to the RP at the (now
       verified) ``redirect_uri`` with ``error`` and ``state``, delivered per
       ``response_mode`` (a redirect with a query, or an auto-submitting form
       POST for ``form_post``).
    3. Authentication: no session and ``prompt=none`` is ``login_required``;
       no session otherwise stashes the request and enters the login flow.
       ``prompt=login``/``select_account``, an exceeded ``max_age``, or an
       ``id_token_hint`` for a different user force a fresh local login
       (``_reauthenticate``) unless ``prompt=none`` (``login_required``).
    4. Access control for OIDC-enabled clients (error page, or
       ``access_denied`` under ``prompt=none``).
    5. Consent: a remembered grant covering every requested scope issues the
       code directly (``prompt=none`` answers ``consent_required`` otherwise;
       ``prompt=consent`` always shows the page). Everything else renders the
       consent page, which marks the scopes already allowed.
    """
    # -- 1. Client and redirect_uri: error page, never a redirect -------------
    if not params.client_id:
        return _error_page(request, "Invalid client_id", "The client_id parameter is required.")

    client = oauth2_service.get_client_by_client_id(tenant_id, params.client_id)
    if not client:
        return _error_page(
            request, "Invalid client_id", "The client_id provided is not registered."
        )

    # Verify client type is 'normal' (authorization code flow only) and that the
    # client is active. A deactivated client must not render a WeftID-branded
    # consent page or receive an authorization code, even though the token
    # endpoint would later reject the exchange. The error text is identical to
    # the client_type rejection so the page does not disclose whether a client_id
    # exists-but-is-deactivated versus is-the-wrong-type.
    if client["client_type"] != "normal" or not client.get("is_active", True):
        return _error_page(
            request, "Unauthorized client", "This client is not authorized for this flow."
        )

    if not params.redirect_uri:
        return _error_page(
            request, "Invalid redirect_uri", "The redirect_uri parameter is required."
        )
    if params.redirect_uri not in (client["redirect_uris"] or []):
        return _error_page(
            request, "Invalid redirect_uri", "The redirect_uri does not match registered URIs."
        )
    redirect_uri = params.redirect_uri
    state = params.state

    # -- 2. Remaining parameters: error response to the verified redirect_uri -
    # The response mode is settled first because it decides how every later
    # response (errors included) reaches the RP. An unsupported mode is itself
    # reported in the default mode.
    response_mode = params.response_mode or DEFAULT_RESPONSE_MODE
    if response_mode not in SUPPORTED_RESPONSE_MODES:
        return _RpResponse(request, redirect_uri, state, DEFAULT_RESPONSE_MODE).error(
            "invalid_request", "Unsupported response_mode. Use query or form_post."
        )
    rp = _RpResponse(request, redirect_uri, state, response_mode)

    if params.request_object is not None:
        # The rejection is delivered the way the RP asked inside the object
        # when it put response_mode/state only there (see _request_object_hints).
        # Query parameters the RP sent explicitly take precedence.
        hints = _request_object_hints(params.request_object)
        if not params.response_mode:
            response_mode = hints.get("response_mode", response_mode)
        rp = _RpResponse(request, redirect_uri, state or hints.get("state"), response_mode)
        return rp.error(
            "request_not_supported", "Request objects passed by value are not supported."
        )
    if params.request_uri is not None:
        return rp.error(
            "request_uri_not_supported", "Request objects passed by reference are not supported."
        )
    if not params.response_type:
        return rp.error("invalid_request", "The response_type parameter is required.")
    if params.response_type not in SUPPORTED_RESPONSE_TYPES:
        return rp.error("unsupported_response_type", "Only response_type=code is supported.")
    if params.code_challenge and params.code_challenge_method not in ("S256", "plain"):
        return rp.error("invalid_request", "Invalid code_challenge_method. Must be S256 or plain.")

    prompts = set(params.prompt.split()) if params.prompt else set()
    if "none" in prompts and len(prompts) > 1:
        return rp.error(
            "invalid_request", "prompt=none cannot be combined with other prompt values."
        )
    prompt_none = "none" in prompts

    max_age = _parse_max_age(params.max_age)
    if params.max_age is not None and max_age is None:
        return rp.error("invalid_request", "max_age must be a non-negative integer.")

    hint_claims: dict | None = None
    if params.id_token_hint is not None:
        hint_claims = oidc_service.verify_id_token_hint(
            tenant_id=tenant_id,
            issuer=tenant_base_url(request),
            client_id=client["client_id"],
            id_token=params.id_token_hint,
        )
        if hint_claims is None:
            return rp.error(
                "invalid_request", "The id_token_hint could not be verified for this client."
            )

    # -- 3. Authentication ----------------------------------------------------
    if not user:
        if prompt_none:
            return rp.error("login_required", "The user is not authenticated.")
        # Stash the full authorize request (a server-built relative path, never
        # a client-supplied redirect target) so the login flow can resume it.
        # ``get_post_auth_redirect`` only honours a rooted ``/oauth2/authorize?``
        # path, and login completion carries the key across session
        # regeneration. Without this, an RP-initiated login ends on the
        # dashboard and the authorization request is lost.
        request.session[PENDING_OAUTH2_AUTHORIZE_KEY] = _pending_authorize_path(params)
        return _login_redirect(params.login_hint)

    if user.get("force_profile_completion"):
        # Same gate as ``require_current_user``: the profile must be completed
        # before any authenticated page, the consent page included.
        if prompt_none:
            return rp.error(
                "interaction_required", "The user must complete their profile before authorizing."
            )
        return RedirectResponse(url="/account/profile", status_code=303)

    reauth_reason: str | None = None
    if prompts & REAUTH_PROMPT_VALUES:
        reauth_reason = "prompt"
    elif max_age is not None and _max_age_exceeded(request.session, max_age):
        reauth_reason = "max_age"
    elif hint_claims is not None and hint_claims["sub"] != str(user["id"]):
        reauth_reason = "id_token_hint"
    if reauth_reason is not None:
        if prompt_none:
            return rp.error("login_required", "The user must authenticate again.")
        return _reauthenticate(request, tenant_id, user, client, params, reauth_reason)

    # -- 4. Access control ----------------------------------------------------
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
        if prompt_none:
            return rp.error("access_denied", "The user does not have access.")
        return _error_page(
            request,
            "Access denied",
            "You do not have access to this application. "
            "Contact your administrator to request access.",
            status_code=403,
        )

    # -- 5. Consent -----------------------------------------------------------
    scopes = parse_scope(params.scope)
    granted_scopes = oidc_service.get_granted_scopes(tenant_id, str(client["id"]), user["id"])
    covered = granted_scopes is not None and scopes <= granted_scopes
    if prompt_none and not covered:
        return rp.error("consent_required", "The user has not consented to this client and scope.")
    if covered and "consent" not in prompts:
        # A remembered grant covers the request: no UI (OpenID Connect Core
        # 3.1.2.1; ``prompt=consent`` is the RP's way to ask for the page).
        return _issue_code(
            rp,
            tenant_id,
            client=client,
            user=user,
            code_challenge=params.code_challenge,
            code_challenge_method=params.code_challenge_method,
            scope=params.scope,
            nonce=params.nonce,
        )

    # Requested scopes to display on the consent page for OIDC requests, paired
    # with a human-readable description and whether the user already allowed
    # them. Unknown scopes fall back to their raw name so nothing requested is
    # hidden from the user.
    requested_scopes = [
        {
            "name": s,
            "description": oidc_service.SCOPE_DESCRIPTIONS.get(s, s),
            "granted": s in (granted_scopes or set()),
        }
        for s in sorted(scopes)
    ]

    # Generate unique auth request ID and store parameters in session
    auth_request_id = secrets.token_urlsafe(32)

    # Store authorization request parameters (for validation on POST).
    # Reassign the top-level key so SessionMiddleware marks the session
    # modified (nested mutations do not trigger save in starlette 1.0+).
    auth_requests = dict(request.session.get("oauth2_auth_requests") or {})
    auth_requests[auth_request_id] = {
        "client_id": client["client_id"],
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": params.code_challenge,
        "code_challenge_method": params.code_challenge_method,
        "scope": params.scope,
        "nonce": params.nonce,
        "response_mode": response_mode,
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


def _error_page(
    request: Request, error: str, error_description: str, *, status_code: int = 200
) -> Response:
    """Render the WeftID-branded authorization error page (no redirect)."""
    return templates.TemplateResponse(
        request,
        "oauth2_error.html",
        {
            "error": error,
            "error_description": error_description,
            "nav": {},
            "csp_nonce": get_csp_nonce(request),
        },
        status_code=status_code,
    )


def _append_query(redirect_uri: str, pairs: list[tuple[str, str]]) -> str:
    """Append percent-encoded query pairs to a registered redirect_uri,
    joining with ``&`` when the registered URI already carries a query."""
    separator = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{separator}{urlencode(pairs)}"


@dataclass(frozen=True)
class _RpResponse:
    """Where and how the authorization response reaches the RP.

    Only built once ``redirect_uri`` has been matched against the client's
    registration, so both delivery paths send the user agent to a verified
    URI. ``query`` redirects with the parameters in the query string;
    ``form_post`` renders a page that POSTs them there as form fields
    (OAuth 2.0 Form Post Response Mode), so the code never appears in a URL.
    """

    request: Request
    redirect_uri: str
    state: str | None
    response_mode: str

    def error(self, error: str, error_description: str) -> Response:
        """Deliver an OAuth2 error response (RFC 6749 section 4.1.2.1)."""
        return self.deliver([("error", error), ("error_description", error_description)])

    def deliver(self, pairs: list[tuple[str, str]]) -> Response:
        """Deliver the response parameters, echoing ``state`` when present."""
        if self.state:
            pairs = [*pairs, ("state", self.state)]
        if self.response_mode == "form_post":
            return _form_post_response(self.request, self.redirect_uri, pairs)
        # redirect-ok: registered OAuth2 redirect_uri
        return RedirectResponse(url=_append_query(self.redirect_uri, pairs), status_code=303)


def _form_post_response(
    request: Request, redirect_uri: str, pairs: list[tuple[str, str]]
) -> Response:
    """Render the auto-submitting form that POSTs the response to the RP.

    The page submits itself with a nonce'd script and shows a Continue button
    when scripts do not run. The CSP ``form-action`` is widened to the
    redirect_uri's origin (the same rule the consent form uses), and the page
    is never cached because it carries a live authorization code.
    """
    request.state.csp_form_action_url = _form_action_origin(redirect_uri)
    response = templates.TemplateResponse(
        request,
        "oauth2_form_post.html",
        {
            "redirect_uri": redirect_uri,
            "fields": pairs,
            "csp_nonce": get_csp_nonce(request),
        },
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _request_object_hints(request_object: str) -> dict[str, str]:
    """Read ``response_mode`` and ``state`` from an unsupported request object.

    Request objects are rejected (``request_not_supported``), but an RP that
    sends one may carry ``response_mode`` and ``state`` only inside it (OpenID
    Connect Core 1.0, section 6.1), and it then waits for the answer in that
    mode. The payload is decoded without verification, and only these two
    values are used, only to shape the rejection sent to the already verified
    redirect_uri: the mode must be a supported one, and ``state`` is echoed
    exactly as an RP could have sent it in the query. Anything unreadable
    (a JWE, bad base64, non-JSON) yields no hints.
    """
    segments = request_object.split(".")
    if len(segments) != 3:
        return {}
    try:
        padded = segments[1] + "=" * (-len(segments[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except ValueError, binascii.Error:
        return {}
    if not isinstance(claims, dict):
        return {}
    hints: dict[str, str] = {}
    mode = claims.get("response_mode")
    if isinstance(mode, str) and mode in SUPPORTED_RESPONSE_MODES:
        hints["response_mode"] = mode
    state = claims.get("state")
    if isinstance(state, str) and 0 < len(state) <= _MAX_STATE_LENGTH:
        hints["state"] = state
    return hints


def _parse_max_age(raw: str | None) -> int | None:
    """Parse ``max_age`` as a non-negative integer; ``None`` when absent or invalid."""
    if raw is None:
        return None
    text = raw.strip()
    if not text.isdigit():
        return None
    return int(text)


def _max_age_exceeded(session: dict, max_age: int) -> bool:
    """True when the session's authentication is older than ``max_age`` seconds.

    ``max_age=0`` always demands a fresh login. A session without a recorded
    authentication time cannot prove its age and is treated as exceeded.
    """
    if max_age == 0:
        return True
    session_start = session.get("session_start")
    if not isinstance(session_start, int | float):
        return True
    return (time.time() - session_start) > max_age


def _login_path(login_hint: str | None) -> str:
    """The same-origin login path ``_login_redirect`` sends the user to."""
    if login_hint and login_hint.strip():
        return "/login?" + urlencode({"prefill_email": login_hint.strip()})
    return "/login"


def _login_redirect(login_hint: str | None) -> RedirectResponse:
    """Send the user to the login page, pre-filling the email step from
    ``login_hint`` when the RP supplied one. The hint is only ever a form
    prefill; routing decisions are made from what the user submits."""
    path = _login_path(login_hint)
    if path != "/login":
        return safe_redirect(path)
    return RedirectResponse(url="/login", status_code=303)


def _reauthenticate(
    request: Request,
    tenant_id: str,
    user: dict,
    client: dict,
    params: AuthorizeParams,
    reason: str,
) -> Response:
    """Force a fresh local login for an authenticated user.

    The current session is terminated (audited as ``user_signed_out`` with
    reason ``reauthentication``) and the request is stashed with its re-auth
    demands stripped, so the request resumed after login does not demand yet
    another login. The full local flow (password, then MFA per tenant policy)
    applies; forced re-authentication is not propagated to upstream IdPs.

    Other relying parties that received ID tokens in the ended session are
    told by front channel (an intermediate page loads their logout iframes on
    the way to the login page). The requesting client is not: it is mid-login
    and its logout page would clear the state it keeps for this request.
    """
    frontchannel_logout_urls = end_oidc_session_quietly(
        request, tenant_id, exclude_client_uuid=str(client["id"])
    )
    log_event(
        tenant_id=tenant_id,
        actor_user_id=str(user["id"]),
        artifact_type="user",
        artifact_id=str(user["id"]),
        event_type="user_signed_out",
        metadata={
            "reason": "reauthentication",
            "trigger": reason,
            "client_id": client["client_id"],
            "frontchannel_logout_count": len(frontchannel_logout_urls),
        },
        request_metadata=extract_request_metadata(request),
    )
    request.session.clear()
    request.session[PENDING_OAUTH2_AUTHORIZE_KEY] = _pending_authorize_path(
        params, strip_reauth=True
    )
    if frontchannel_logout_urls:
        return frontchannel_logout_response(
            request, frontchannel_logout_urls, _login_path(user.get("email"))
        )
    return _login_redirect(user.get("email"))


def _issue_code(
    rp: _RpResponse,
    tenant_id: str,
    *,
    client: dict,
    user: dict,
    code_challenge: str | None,
    code_challenge_method: str | None,
    scope: str | None,
    nonce: str | None,
) -> Response:
    """Create an authorization code and deliver it to the RP."""
    # Record the user's authentication time for the OIDC `auth_time` claim.
    # Prefer the session login timestamp (when they actually authenticated);
    # fall back to the code-issuance time when it is unavailable.
    session_start = rp.request.session.get("session_start")
    auth_time = datetime.fromtimestamp(session_start, UTC) if session_start else datetime.now(UTC)

    code = oauth2_service.create_authorization_code(
        tenant_id=tenant_id,
        client_id=client["id"],
        user_id=user["id"],
        redirect_uri=rp.redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
        nonce=nonce,
        auth_time=auth_time,
        sid=ensure_session_id(rp.request.session),
    )
    return rp.deliver([("code", code)])


def _pending_authorize_path(params: AuthorizeParams, *, strip_reauth: bool = False) -> str:
    """Rebuild this authorize request as a same-origin path for the login stash.

    The parameters are re-encoded rather than copied from the URL: the request
    may have arrived by POST, and RPs commonly send ``redirect_uri=https://...``
    unescaped in a GET, where a literal ``://`` anywhere in the target is
    (rightly) rejected by the redirect validator as a scheme. Percent-encoding
    the values keeps the parameters byte-for-byte identical once the resumed
    request decodes them again.
    """
    query = urlencode(params.as_query(strip_reauth=strip_reauth))
    return f"/oauth2/authorize?{query}" if query else "/oauth2/authorize"


def _form_action_origin(redirect_uri: str) -> str:
    """Return ``scheme://host[:port]`` of a registered redirect_uri for CSP."""
    parts = urlparse(redirect_uri)
    return f"{parts.scheme}://{parts.netloc}"


# ============================================================================
# Consent Decision (POST /oauth2/authorize/decision)
# ============================================================================


@router.post("/authorize/decision")
def authorize_grant(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    user: Annotated[dict, Depends(require_current_user)],
    auth_request_id: Annotated[str, Form(max_length=50)],
    action: Annotated[str, Form(max_length=20)],
):
    """
    Consent decision endpoint - handle allow/deny from the consent page.

    User submits form to allow or deny authorization. The auth_request_id
    references a stored authorization request from the session, preventing
    parameter tampering and providing one-time-use semantics. This is a
    same-origin form POST protected by CSRF, distinct from the authorization
    endpoint's own POST binding (``/oauth2/authorize``).

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
        return _error_page(
            request, "Invalid request", "Authorization request not found or already used."
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
    rp = _RpResponse(
        request, redirect_uri, state, stored_request.get("response_mode") or DEFAULT_RESPONSE_MODE
    )

    # Delete from session immediately (one-time use). Reassign so the
    # session is marked modified and the cookie is rewritten.
    del auth_requests[auth_request_id]
    request.session["oauth2_auth_requests"] = auth_requests

    # Validate request hasn't expired
    if time.time() - created_at > AUTH_REQUEST_MAX_AGE_SECONDS:
        return _error_page(
            request, "Request expired", "Authorization request has expired. Please start over."
        )

    # Get client
    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)

    if not client or client["client_type"] != "normal" or not client.get("is_active", True):
        # Invalid, wrong-type, or deactivated client: redirect with error and
        # issue no authorization code (defense in depth alongside the GET check).
        return rp.error("unauthorized_client", "This client is not authorized.")

    # Verify redirect_uri matches (defense in depth - should always match since we stored it)
    if redirect_uri not in (client["redirect_uris"] or []):
        return _error_page(
            request, "Invalid redirect_uri", "The redirect_uri does not match registered URIs."
        )

    # Handle denial
    if action == "deny":
        return rp.error("access_denied", "The user denied the request.")

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
            return rp.error("access_denied", "The user does not have access.")

        # Remember the consent (create or widen the persisted grant) so the
        # next request from this client is answered without the page.
        oidc_service.record_consent(tenant_id, client, user["id"], parse_scope(scope))

        return _issue_code(
            rp,
            tenant_id,
            client=client,
            user=user,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            nonce=nonce,
        )

    # Invalid action
    return rp.error("invalid_request", "The action must be allow or deny.")


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


# Token responses and errors must never be cached (RFC 6749 section 5.1).
_TOKEN_RESPONSE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _token_error(error: str, error_description: str, *, status_code: int = 400) -> JSONResponse:
    """Build an RFC 6749 section 5.2 token error: top-level ``error`` and
    ``error_description``, never FastAPI's ``{"detail": ...}`` envelope.

    ``invalid_client`` is always a 401 with a ``WWW-Authenticate: Basic``
    challenge (required when the client authenticated with the Authorization
    header, permitted otherwise).
    """
    headers = dict(_TOKEN_RESPONSE_HEADERS)
    if error == "invalid_client":
        status_code = 401
        headers["WWW-Authenticate"] = 'Basic realm="oauth2"'
    return JSONResponse(
        {"error": error, "error_description": error_description},
        status_code=status_code,
        headers=headers,
    )


def _token_success(body: TokenResponse) -> JSONResponse:
    """Serialise a token response with absent fields omitted (never ``null``)
    and the no-store cache headers."""
    return JSONResponse(body.model_dump(exclude_none=True), headers=_TOKEN_RESPONSE_HEADERS)


async def token_request_validation_handler(
    request: Request, exc: RequestValidationError
) -> Response:
    """Report form validation failures at the token endpoint as RFC 6749
    ``invalid_request`` (a missing ``grant_type``, an over-long parameter)
    instead of FastAPI's 422. Every other path keeps the default handler."""
    if request.url.path == "/oauth2/token":
        return _token_error("invalid_request", "The token request is malformed.")
    return await request_validation_exception_handler(request, exc)


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
) -> Response:
    """
    OAuth2 token endpoint - exchange authorization code or refresh token for access token.

    Supports three grant types:
    1. authorization_code - Exchange auth code for access + refresh tokens
       (+ ID token for OIDC). Redeeming a code twice fails with invalid_grant
       and revokes every token already issued from it.
    2. refresh_token - Exchange a refresh token for a new access token and a
       new refresh token (rotation: the presented refresh token stops working;
       the grant's original expiry is kept)
    3. client_credentials - Get access token using client credentials (B2B)

    Client authentication (RFC 6749 section 2.3.1): either HTTP Basic
    (``client_secret_basic``, the Authorization header) or the ``client_id`` +
    ``client_secret`` form fields (``client_secret_post``). Exactly one method
    must be used per request.

    Responses carry ``Cache-Control: no-store`` and ``Pragma: no-cache``.
    Errors are RFC 6749 section 5.2 JSON objects with top-level ``error`` and
    ``error_description``: HTTP 400, or 401 with ``WWW-Authenticate: Basic``
    for ``invalid_client``. Absent fields (``refresh_token``, ``id_token``)
    are omitted, never null.

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
        return _token_error("invalid_client", "Client authentication failed")
    client_id, client_secret = credentials

    client = oauth2_service.get_client_by_client_id(tenant_id, client_id)
    if not client or not oauth2.verify_token_hash(client_secret, client["client_secret_hash"]):
        return _token_error("invalid_client", "Client authentication failed")
    if not client.get("is_active", True):
        return _token_error("invalid_client", "Client is deactivated")

    # ========================================================================
    # Grant Type: authorization_code
    # ========================================================================
    if grant_type == "authorization_code":
        if client["client_type"] != "normal":
            return _token_error(
                "unauthorized_client", "Client is not authorized for this grant type"
            )

        if not code or not redirect_uri:
            return _token_error(
                "invalid_request", "Missing required parameter: code or redirect_uri"
            )

        # Validate and consume the code. A second redemption returns None here
        # after revoking everything issued from the first one.
        code_data = oauth2_service.validate_and_consume_code(
            tenant_id=tenant_id,
            code=code,
            client_id=client["id"],
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        if not code_data:
            return _token_error("invalid_grant", "Invalid or expired authorization code")

        granted_scope = code_data.get("scope")
        grant_id = code_data["id"]

        # Create refresh token (carrying the granted scope so the refresh_token
        # grant can mint access tokens with the same scope)
        refresh_token_str, refresh_token_id = oauth2_service.create_refresh_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=code_data["user_id"],
            scope=granted_scope,
            grant_id=grant_id,
        )

        # Create access token (carrying the granted scope for downstream userinfo)
        access_token_str = oauth2_service.create_access_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=code_data["user_id"],
            parent_token_id=refresh_token_id,
            scope=granted_scope,
            grant_id=grant_id,
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
                sid=code_data.get("sid"),
            )

        return _token_success(
            TokenResponse(
                access_token=access_token_str,
                token_type="Bearer",
                expires_in=int(oauth2.ACCESS_TOKEN_EXPIRY.total_seconds()),
                refresh_token=refresh_token_str,
                id_token=id_token_str,
            )
        )

    # ========================================================================
    # Grant Type: refresh_token
    # ========================================================================
    elif grant_type == "refresh_token":
        if not refresh_token:
            return _token_error("invalid_request", "Missing required parameter: refresh_token")

        # The lookup is bound to the authenticating client, so a refresh token
        # issued to another client is simply not found (invalid_grant).
        token_data = oauth2_service.validate_refresh_token(
            tenant_id=tenant_id,
            token=refresh_token,
            client_id=client["id"],
        )
        if not token_data:
            return _token_error("invalid_grant", "Invalid or expired refresh token")

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
            return _token_error("invalid_grant", "Access has been revoked")

        # Rotate: the presented refresh token is replaced (same scope, grant,
        # and absolute expiry). A concurrent refresh with the same token loses.
        rotated = oauth2_service.rotate_refresh_token(tenant_id, client["id"], token_data)
        if rotated is None:
            return _token_error("invalid_grant", "Invalid or expired refresh token")
        new_refresh_token, new_refresh_token_id = rotated

        # New access token, linked to the new refresh token and carrying the
        # scope granted at authorization so userinfo keeps returning the same
        # claims across refreshes.
        access_token_str = oauth2_service.create_access_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=token_data["user_id"],
            parent_token_id=new_refresh_token_id,
            scope=token_data.get("scope"),
            grant_id=str(token_data["grant_id"]) if token_data.get("grant_id") else None,
        )

        return _token_success(
            TokenResponse(
                access_token=access_token_str,
                token_type="Bearer",
                expires_in=int(oauth2.ACCESS_TOKEN_EXPIRY.total_seconds()),
                refresh_token=new_refresh_token,
            )
        )

    # ========================================================================
    # Grant Type: client_credentials
    # ========================================================================
    elif grant_type == "client_credentials":
        if client["client_type"] != "b2b":
            return _token_error(
                "unauthorized_client", "Client is not authorized for this grant type"
            )

        service_user_id = client["service_user_id"]
        if not service_user_id:
            return _token_error(
                "server_error",
                "Client configuration error: missing service user",
                status_code=500,
            )

        # Create access token (24h expiry, no refresh token)
        access_token_str = oauth2_service.create_access_token(
            tenant_id=tenant_id,
            client_id=client["id"],
            user_id=service_user_id,
            is_client_credentials=True,
        )

        return _token_success(
            TokenResponse(
                access_token=access_token_str,
                token_type="Bearer",
                expires_in=int(oauth2.CLIENT_CREDENTIALS_TOKEN_EXPIRY.total_seconds()),
            )
        )

    # ========================================================================
    # Unsupported grant type
    # ========================================================================
    return _token_error("unsupported_grant_type", f"Grant type '{grant_type}' is not supported")
