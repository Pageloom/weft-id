"""OAuth2 authorization and token endpoints.

Architectural Note: this module contains a direct ``log_event()`` call for the
``user_signed_out`` event raised when a relying party forces re-authentication
(``prompt=login``, an exceeded ``max_age``, or an ``id_token_hint`` for another
user). Like ``routers/auth/logout.py``, this is session termination at the HTTP
boundary, an accepted exception to the "event logging in services" pattern.
"""

import base64
import binascii
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
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from middleware.csrf import make_csrf_token_func
from routers.saml_idp._helpers import PENDING_OAUTH2_AUTHORIZE_KEY
from schemas.oauth2 import TokenErrorResponse, TokenResponse
from services.event_log import log_event
from services.oidc.claims import SCOPE_OPENID, parse_scope
from utils.csp_nonce import get_csp_nonce
from utils.redirects import safe_redirect
from utils.request_metadata import extract_request_metadata
from utils.templates import templates
from utils.urls import tenant_base_url

# Maximum age for authorization requests (10 minutes)
AUTH_REQUEST_MAX_AGE_SECONDS = 600

# ``prompt`` values (OpenID Connect Core 1.0, section 3.1.2.1). Values that
# demand a fresh authentication even when a session exists.
REAUTH_PROMPT_VALUES = frozenset({"login", "select_account"})

# The only response type the authorization endpoint issues.
SUPPORTED_RESPONSE_TYPES = frozenset({"code"})

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
    ``claims_locales``, ``acr_values``, ``response_mode``) are kept so a
    resumed request is the request the RP sent.
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
        response_mode, display, ui_locales, claims_locales, acr_values:
            Accepted and ignored
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
    2. Every other parameter error is reported to the RP by redirecting to
       the (now verified) ``redirect_uri`` with ``error`` and ``state``.
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

    # -- 2. Remaining parameters: error redirect to the verified redirect_uri --
    if params.request_object is not None:
        return _error_redirect(
            redirect_uri,
            "request_not_supported",
            "Request objects passed by value are not supported.",
            state,
        )
    if params.request_uri is not None:
        return _error_redirect(
            redirect_uri,
            "request_uri_not_supported",
            "Request objects passed by reference are not supported.",
            state,
        )
    if not params.response_type:
        return _error_redirect(
            redirect_uri, "invalid_request", "The response_type parameter is required.", state
        )
    if params.response_type not in SUPPORTED_RESPONSE_TYPES:
        return _error_redirect(
            redirect_uri,
            "unsupported_response_type",
            "Only response_type=code is supported.",
            state,
        )
    if params.code_challenge and params.code_challenge_method not in ("S256", "plain"):
        return _error_redirect(
            redirect_uri,
            "invalid_request",
            "Invalid code_challenge_method. Must be S256 or plain.",
            state,
        )

    prompts = set(params.prompt.split()) if params.prompt else set()
    if "none" in prompts and len(prompts) > 1:
        return _error_redirect(
            redirect_uri,
            "invalid_request",
            "prompt=none cannot be combined with other prompt values.",
            state,
        )
    prompt_none = "none" in prompts

    max_age = _parse_max_age(params.max_age)
    if params.max_age is not None and max_age is None:
        return _error_redirect(
            redirect_uri, "invalid_request", "max_age must be a non-negative integer.", state
        )

    hint_claims: dict | None = None
    if params.id_token_hint is not None:
        hint_claims = oidc_service.verify_id_token_hint(
            tenant_id=tenant_id,
            issuer=tenant_base_url(request),
            client_id=client["client_id"],
            id_token=params.id_token_hint,
        )
        if hint_claims is None:
            return _error_redirect(
                redirect_uri,
                "invalid_request",
                "The id_token_hint could not be verified for this client.",
                state,
            )

    # -- 3. Authentication ----------------------------------------------------
    if not user:
        if prompt_none:
            return _error_redirect(
                redirect_uri, "login_required", "The user is not authenticated.", state
            )
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
            return _error_redirect(
                redirect_uri,
                "interaction_required",
                "The user must complete their profile before authorizing.",
                state,
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
            return _error_redirect(
                redirect_uri,
                "login_required",
                "The user must authenticate again.",
                state,
            )
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
            return _error_redirect(
                redirect_uri, "access_denied", "The user does not have access.", state
            )
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
        return _error_redirect(
            redirect_uri,
            "consent_required",
            "The user has not consented to this client and scope.",
            state,
        )
    if covered and "consent" not in prompts:
        # A remembered grant covers the request: no UI (OpenID Connect Core
        # 3.1.2.1; ``prompt=consent`` is the RP's way to ask for the page).
        return _issue_code_redirect(
            request,
            tenant_id,
            client=client,
            user=user,
            redirect_uri=redirect_uri,
            state=state,
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


def _error_redirect(
    redirect_uri: str, error: str, error_description: str, state: str | None
) -> RedirectResponse:
    """Redirect to the verified redirect_uri with an OAuth2 error response
    (RFC 6749 section 4.1.2.1); ``state`` is echoed when the RP sent one."""
    pairs = [("error", error), ("error_description", error_description)]
    if state:
        pairs.append(("state", state))
    # redirect-ok: registered OAuth2 redirect_uri
    return RedirectResponse(url=_append_query(redirect_uri, pairs), status_code=303)


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


def _login_redirect(login_hint: str | None) -> RedirectResponse:
    """Send the user to the login page, pre-filling the email step from
    ``login_hint`` when the RP supplied one. The hint is only ever a form
    prefill; routing decisions are made from what the user submits."""
    if login_hint and login_hint.strip():
        return safe_redirect("/login?" + urlencode({"prefill_email": login_hint.strip()}))
    return RedirectResponse(url="/login", status_code=303)


def _reauthenticate(
    request: Request,
    tenant_id: str,
    user: dict,
    client: dict,
    params: AuthorizeParams,
    reason: str,
) -> RedirectResponse:
    """Force a fresh local login for an authenticated user.

    The current session is terminated (audited as ``user_signed_out`` with
    reason ``reauthentication``) and the request is stashed with its re-auth
    demands stripped, so the request resumed after login does not demand yet
    another login. The full local flow (password, then MFA per tenant policy)
    applies; forced re-authentication is not propagated to upstream IdPs.
    """
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
        },
        request_metadata=extract_request_metadata(request),
    )
    request.session.clear()
    request.session[PENDING_OAUTH2_AUTHORIZE_KEY] = _pending_authorize_path(
        params, strip_reauth=True
    )
    return _login_redirect(user.get("email"))


def _issue_code_redirect(
    request: Request,
    tenant_id: str,
    *,
    client: dict,
    user: dict,
    redirect_uri: str,
    state: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
    scope: str | None,
    nonce: str | None,
) -> RedirectResponse:
    """Create an authorization code and redirect the user agent to the RP."""
    # Record the user's authentication time for the OIDC `auth_time` claim.
    # Prefer the session login timestamp (when they actually authenticated);
    # fall back to the code-issuance time when it is unavailable.
    session_start = request.session.get("session_start")
    auth_time = datetime.fromtimestamp(session_start, UTC) if session_start else datetime.now(UTC)

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

    pairs = [("code", code)]
    if state:
        pairs.append(("state", state))
    # redirect-ok: registered OAuth2 redirect_uri
    return RedirectResponse(url=_append_query(redirect_uri, pairs), status_code=303)


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
        return _error_redirect(
            redirect_uri, "unauthorized_client", "This client is not authorized.", state
        )

    # Verify redirect_uri matches (defense in depth - should always match since we stored it)
    if redirect_uri not in (client["redirect_uris"] or []):
        return _error_page(
            request, "Invalid redirect_uri", "The redirect_uri does not match registered URIs."
        )

    # Handle denial
    if action == "deny":
        return _error_redirect(redirect_uri, "access_denied", "The user denied the request.", state)

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
            return _error_redirect(
                redirect_uri, "access_denied", "The user does not have access.", state
            )

        # Remember the consent (create or widen the persisted grant) so the
        # next request from this client is answered without the page.
        oidc_service.record_consent(tenant_id, client, user["id"], parse_scope(scope))

        return _issue_code_redirect(
            request,
            tenant_id,
            client=client,
            user=user,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            nonce=nonce,
        )

    # Invalid action
    return _error_redirect(
        redirect_uri, "invalid_request", "The action must be allow or deny.", state
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
