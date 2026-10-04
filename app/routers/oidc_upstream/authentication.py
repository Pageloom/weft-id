"""OIDC upstream login and callback endpoints.

The relying-party authorization-code flow with PKCE:

- ``GET /auth/oidc/{connection_id}/login`` generates ``state``, ``nonce``, and
  a PKCE ``code_verifier`` (S256 challenge), stores them in the server-side
  login state store (``services.oidc_upstream.login_state``) keyed by
  ``state``, keeps ``state`` in the session (namespaced per connection) to
  bind the sign-in to this browser, and redirects off-origin to the IdP.
- ``POST /auth/oidc/{connection_id}/callback`` receives a ``form_post``
  callback (Apple). It arrives cross-site without the SameSite=Lax session
  cookie, so it only attaches the posted fields to the stored sign-in and
  redirects to the GET callback, where the cookie is sent.
- ``GET /auth/oidc/{connection_id}/callback`` checks ``state`` against the
  session, takes the stored sign-in, has the provider adapter exchange the
  code and return the user's identity, correlates the user, and completes
  login. The session's state and the stored sign-in are removed on first use
  so a replayed callback fails.

Security (cross-cutting requirements):

- **Providers**: everything provider-specific (authorize URL, code exchange,
  identity) lives in a provider adapter (``services.oidc_upstream.adapters``).
  These routes never branch on the provider type.
- **SSRF**: the token exchange, userinfo, and JWKS fetches all go through
  ``build_safe_client()`` (in the service helpers), never bare ``httpx``.
- **Platform MFA**: when the connection has ``require_platform_mfa``, the
  callback stashes ``pending_mfa_user_id`` / ``pending_mfa_method`` and
  redirects to ``/mfa/verify`` instead of calling
  ``complete_authenticated_login`` -- exactly as the SAML ACS does.
- **Rate limiting**: both routes are rate-limited via ``ratelimit.prevent``.
  The login route is public and is what the sign-in page's "Continue with
  ..." buttons link to (``?via=login_button``), so that limit covers them.
- **Email confirmation**: a provider that does not prove the user's email
  address (Facebook, Microsoft personal) sends the user to
  ``/auth/oidc/confirm-email`` until they enter a code mailed to it; the
  sign-in then resumes (MFA or completion) from where the callback left it.
- **Audit**: started, completed, failed and refused events carry ``entry``
  (``login_button`` or ``routed``), kept in the login state store across
  the hop.
"""

from typing import Annotated
from urllib.parse import urlencode

import services.emails as emails_service
import services.oidc_upstream as oidc_service
import settings
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Cookie, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from middleware.csrf import make_csrf_token_func
from routers.auth._login_completion import (
    complete_authenticated_login,
    stash_upstream_oidc_session,
)
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.exceptions import ForbiddenError, NotFoundError, RateLimitError
from utils.csp_nonce import get_csp_nonce
from utils.email import send_email_possession_code, send_mfa_code_email
from utils.email_verification import (
    create_verification_cookie,
    generate_verification_code,
    validate_verification_cookie,
)
from utils.mfa import create_email_otp
from utils.ratelimit import MINUTE, ratelimit
from utils.redirects import safe_redirect
from utils.request_metadata import extract_remote_address
from utils.templates import templates

router = APIRouter()

# Session key namespaces. Per-connection so a user can start two logins.
_SESSION_PREFIX = "oidc_auth"


# The largest upstream ID token carried through the platform MFA step in the
# session cookie (browsers cap a cookie at about 4 KB, and the session holds
# more than the stash).
_MAX_COOKIE_STASHED_ID_TOKEN_LENGTH = 2048

# Account-linking policy refusals (service error code -> login page error).
_POLICY_REFUSALS = {
    "saml_assigned_user": "sso_required",
    "oidc_connection_already_linked": "account_already_linked",
}


def _session_key(connection_id: str, name: str) -> str:
    return f"{_SESSION_PREFIX}:{connection_id}:{name}"


def _error_response(error_type: str) -> RedirectResponse:
    """Redirect to the login page with an error (no sensitive disclosure)."""
    return safe_redirect(f"/login?error={error_type}")


@router.get("/auth/oidc/{connection_id}/login")
def oidc_login(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    connection_id: str,
):
    """Initiate the OIDC authorization-code flow with PKCE.

    Redirects the user to the IdP's authorization endpoint.
    """
    client_ip = extract_remote_address(request) or "unknown"
    try:
        ratelimit.prevent(
            "oidc_login:tenant:{tenant_id}:ip:{ip}",
            limit=20,
            timespan=MINUTE * 5,
            tenant_id=tenant_id,
            ip=client_ip,
        )
    except RateLimitError:
        return _error_response("too_many_requests")

    connection = _get_connection(tenant_id, connection_id)
    if connection is None:
        return _error_response("idp_not_found")

    if not connection.get("is_enabled"):
        return _error_response("idp_disabled")

    # Only a connection that is on the sign-in page can be entered by button;
    # the query parameter alone must not relabel other sign-ins in the log.
    entry = (
        oidc_service.ENTRY_LOGIN_BUTTON
        if request.query_params.get("via") == "login_button" and connection.get("show_on_login")
        else oidc_service.ENTRY_ROUTED
    )

    adapter = oidc_service.get_adapter(connection.get("provider_type"))

    # Pick up provider configuration changes (for spec OIDC, endpoints the
    # IdP published since the last discovery, TTL-gated). A document WeftID
    # now refuses stops the sign-in here, before the user is sent anywhere.
    try:
        connection = adapter.prepare(tenant_id, connection)
    except oidc_service.DiscoveryError as exc:
        _log_failure(tenant_id, connection_id, connection, "discovery", str(exc), entry)
        return _error_response("configuration_error")

    state = oidc_service.generate_state()
    nonce = oidc_service.generate_nonce()
    code_verifier, code_challenge = oidc_service.generate_pkce_pair()

    try:
        authorize_url = adapter.authorize_url(
            connection,
            redirect_uri=_callback_url(request, connection_id),
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
        )
    except oidc_service.ProviderLoginError as exc:
        return _error_response(exc.public_error)

    login_state = oidc_service.LoginState(
        tenant_id=str(tenant_id),
        connection_id=connection_id,
        nonce=nonce,
        code_verifier=code_verifier,
        entry=entry,
    )
    if not oidc_service.save_login_state(state, login_state):
        _log_failure(tenant_id, connection_id, connection, "state_store", None, entry)
        return _error_response("auth_failed")
    request.session[_session_key(connection_id, "state")] = state

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="oidc_idp_connection",
        artifact_id=connection_id,
        event_type="oidc_login_started",
        metadata={"idp_name": connection.get("name"), "entry": entry},
    )

    # redirect-ok: deliberate off-origin hop to the IdP's authorization endpoint
    return RedirectResponse(url=authorize_url, status_code=303)


@router.get("/auth/oidc/{connection_id}/callback")
def oidc_callback(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    connection_id: str,
):
    """Handle the OIDC authorization-code callback.

    Validates ``state``, has the provider adapter exchange the code for the
    user's identity, correlates the user, and completes login (or routes to
    ``/mfa/verify``).
    """
    client_ip = extract_remote_address(request) or "unknown"
    try:
        ratelimit.prevent(
            "oidc_callback:tenant:{tenant_id}:ip:{ip}",
            limit=20,
            timespan=MINUTE * 5,
            tenant_id=tenant_id,
            ip=client_ip,
        )
    except RateLimitError:
        return _error_response("too_many_requests")

    connection = _get_connection(tenant_id, connection_id)
    if connection is None:
        return _error_response("idp_not_found")

    if not connection.get("is_enabled"):
        return _error_response("idp_disabled")

    # Single-use: the session's state and the stored sign-in are removed on
    # first use. The stored sign-in is only taken by the browser that
    # started it (the session's state matches).
    expected_state = request.session.pop(_session_key(connection_id, "state"), None)
    state = request.query_params.get("state")
    login_state = (
        oidc_service.take_login_state(state)
        if expected_state is not None and state == expected_state
        else None
    )
    if login_state is not None and (
        login_state.tenant_id != str(tenant_id) or login_state.connection_id != connection_id
    ):
        login_state = None
    entry = (
        oidc_service.ENTRY_LOGIN_BUTTON
        if login_state is not None and login_state.entry == oidc_service.ENTRY_LOGIN_BUTTON
        else oidc_service.ENTRY_ROUTED
    )

    # A posted callback's fields were stored by the POST route; otherwise
    # they are in the query string.
    callback_fields = login_state.callback_fields if login_state is not None else None
    fields = callback_fields if callback_fields is not None else request.query_params

    error = fields.get("error")
    if error:
        _log_failure(tenant_id, connection_id, connection, "idp_error", error, entry)
        return _error_response("auth_failed")

    if login_state is None:
        _log_failure(tenant_id, connection_id, connection, "state_mismatch", None, entry)
        return _error_response("auth_failed")

    code = fields.get("code")
    if not code:
        _log_failure(tenant_id, connection_id, connection, "missing_code", None, entry)
        return _error_response("auth_failed")

    code_verifier = login_state.code_verifier
    if not code_verifier:
        _log_failure(tenant_id, connection_id, connection, "missing_verifier", None, entry)
        return _error_response("auth_failed")

    adapter = oidc_service.get_adapter(connection.get("provider_type"))
    try:
        identity = adapter.complete(
            tenant_id,
            connection,
            code=code,
            redirect_uri=_callback_url(request, connection_id),
            code_verifier=code_verifier,
            nonce=login_state.nonce,
            callback_fields=callback_fields,
        )
    except oidc_service.ProviderLoginError as exc:
        _log_failure(tenant_id, connection_id, connection, exc.reason, exc.detail, entry)
        return _error_response(exc.public_error)

    try:
        user = oidc_service.authenticate_via_oidc(
            tenant_id=tenant_id,
            connection=connection,
            sub=identity.subject,
            claims=identity.claims,
            entry=entry,
        )
    except NotFoundError as exc:
        _log_failure(tenant_id, connection_id, connection, "user_not_found", str(exc), entry)
        return _error_response("user_not_found")
    except ForbiddenError as exc:
        # Account-linking policy refusals are audited by the service
        # (oidc_login_refused); everything else is a generic failure.
        refusal = _POLICY_REFUSALS.get(exc.code)
        if refusal:
            return _error_response(refusal)
        _log_failure(tenant_id, connection_id, connection, "auth_failed", str(exc), entry)
        return _error_response("auth_failed")
    except Exception as exc:  # noqa: BLE001 - ForbiddenError and others
        _log_failure(tenant_id, connection_id, connection, "auth_failed", str(exc), entry)
        return _error_response("auth_failed")

    user_id = str(user["id"])
    mfa_method = user.get("mfa_method") or "email"
    requires_mfa = oidc_service.oidc_connection_requires_platform_mfa(tenant_id, connection_id)
    # A provider that does not prove the user's address (Facebook, Microsoft
    # personal) cannot complete a sign-in until the user confirms it.
    pending_email = oidc_service.pending_email_confirmation(tenant_id, connection, user_id)
    detour = requires_mfa or pending_email is not None

    id_token = identity.id_token
    if identity.upstream_sub:
        # Across a detour (email confirmation, MFA) the stash rides in the
        # session cookie, so a large ID token is left out there (logout then
        # goes without id_token_hint). Without one, login completes in this
        # request.
        stash_upstream_oidc_session(
            request.session,
            connection_id=connection_id,
            user_id=user_id,
            upstream_sub=identity.upstream_sub,
            upstream_sid=identity.upstream_sid,
            id_token=id_token
            if id_token and (not detour or len(id_token) <= _MAX_COOKIE_STASHED_ID_TOKEN_LENGTH)
            else None,
        )

    if pending_email is not None:
        return _start_email_confirmation(
            request,
            tenant_id,
            connection_id=connection_id,
            user_id=user_id,
            mfa_method=mfa_method,
            pending_email=pending_email,
        )

    return _finish_sign_in(request, tenant_id, user_id, mfa_method, requires_mfa=requires_mfa)


@router.post("/auth/oidc/{connection_id}/callback")
def oidc_callback_post(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    connection_id: str,
    state: Annotated[str, Form(max_length=512)] = "",
    code: Annotated[str, Form(max_length=4096)] = "",
    error: Annotated[str, Form(max_length=255)] = "",
    user: Annotated[str, Form(max_length=4096)] = "",
):
    """Receive a ``form_post`` callback and continue on the GET callback.

    The provider posts from its own site, so the SameSite=Lax session cookie
    is not sent and the session must not be touched here. The posted fields
    are attached to the stored sign-in; the GET callback checks the browser
    binding and finishes the sign-in. CSRF-exempt: the stored ``state`` is
    what authenticates the post.
    """
    client_ip = extract_remote_address(request) or "unknown"
    try:
        ratelimit.prevent(
            "oidc_callback_post:tenant:{tenant_id}:ip:{ip}",
            limit=20,
            timespan=MINUTE * 5,
            tenant_id=tenant_id,
            ip=client_ip,
        )
    except RateLimitError:
        return _error_response("too_many_requests")

    connection = _get_connection(tenant_id, connection_id)
    if connection is None:
        return _error_response("idp_not_found")

    if not connection.get("is_enabled"):
        return _error_response("idp_disabled")

    login_state = oidc_service.load_login_state(state)
    if (
        login_state is None
        or login_state.tenant_id != str(tenant_id)
        or login_state.connection_id != connection_id
        or not oidc_service.attach_callback_fields(
            state, login_state, {"code": code, "error": error, "user": user}
        )
    ):
        entry = (
            login_state.entry
            if login_state is not None and login_state.entry == oidc_service.ENTRY_LOGIN_BUTTON
            else oidc_service.ENTRY_ROUTED
        )
        _log_failure(tenant_id, connection_id, connection, "state_mismatch", None, entry)
        return _error_response("auth_failed")

    return safe_redirect(f"/auth/oidc/{connection_id}/callback?{urlencode({'state': state})}")


def _finish_sign_in(
    request: Request,
    tenant_id: str,
    user_id: str,
    mfa_method: str,
    *,
    requires_mfa: bool,
) -> Response:
    """Complete the sign-in, through the platform MFA step when required."""
    # Platform MFA gate (mirrors the SAML ACS).
    if requires_mfa:
        request.session["pending_mfa_user_id"] = user_id
        request.session["pending_mfa_method"] = mfa_method

        if mfa_method == "email":
            code = create_email_otp(tenant_id, user_id)
            primary_email = emails_service.get_primary_email(tenant_id, user_id)
            if primary_email:
                send_mfa_code_email(primary_email, code, tenant_id=tenant_id)

        return RedirectResponse(url="/mfa/verify", status_code=303)

    return complete_authenticated_login(request, tenant_id, user_id, mfa_method=mfa_method)


# --- Email confirmation (untrusted-email providers) -------------------------
#
# The callback parks the authenticated user in the session and sends a code to
# their unconfirmed address; the code itself is held, hashed and encrypted, in
# a short-lived cookie (the same mechanism as the sign-in page's email check).
# Entering it confirms the address and resumes the sign-in where the callback
# left off.

_CONFIRM_SESSION_KEY = "pending_oidc_email_confirmation"
_CONFIRM_COOKIE = "oidc_email_confirm"
_CONFIRM_PATH = "/auth/oidc/confirm-email"


def _set_confirm_cookie(response: Response, email: str, tenant_id: str) -> None:
    code = generate_verification_code()
    send_email_possession_code(email, code, tenant_id=tenant_id)
    response.set_cookie(
        key=_CONFIRM_COOKIE,
        value=create_verification_cookie(email, code, tenant_id),
        max_age=settings.VERIFICATION_CODE_EXPIRY_SECONDS,
        httponly=True,
        samesite="lax",
        secure=not settings.IS_DEV,
    )


def _start_email_confirmation(
    request: Request,
    tenant_id: str,
    *,
    connection_id: str,
    user_id: str,
    mfa_method: str,
    pending_email: dict,
) -> Response:
    """Send a code to the user's unconfirmed address and ask for it."""
    try:
        ratelimit.prevent(
            "oidc_email_confirm_send:email:{email}",
            limit=5,
            timespan=MINUTE * 10,
            email=pending_email["email"],
        )
    except RateLimitError:
        return _error_response("too_many_requests")

    request.session[_CONFIRM_SESSION_KEY] = {
        "user_id": user_id,
        "connection_id": connection_id,
        "email_id": pending_email["email_id"],
        "mfa_method": mfa_method,
    }
    response = RedirectResponse(url="/auth/oidc/confirm-email", status_code=303)
    _set_confirm_cookie(response, pending_email["email"], tenant_id)
    return response


def _pending_confirmation(request: Request, tenant_id: str) -> tuple[dict, dict] | None:
    """Return ``(parked sign-in, address)`` while a confirmation is pending.

    None when nothing is parked, the connection is gone or disabled, or the
    address is no longer the user's unconfirmed primary one.
    """
    parked = request.session.get(_CONFIRM_SESSION_KEY)
    if not isinstance(parked, dict):
        return None
    connection_id = parked.get("connection_id")
    user_id = parked.get("user_id")
    if not isinstance(connection_id, str) or not isinstance(user_id, str):
        return None
    connection = _get_connection(tenant_id, connection_id)
    if connection is None or not connection.get("is_enabled"):
        return None
    pending_email = oidc_service.pending_email_confirmation(tenant_id, connection, user_id)
    if pending_email is None or pending_email["email_id"] != parked.get("email_id"):
        return None
    return parked, pending_email


def _abandon_confirmation(request: Request, error: str) -> Response:
    request.session.pop(_CONFIRM_SESSION_KEY, None)
    response = _error_response(error)
    response.delete_cookie(_CONFIRM_COOKIE)
    return response


@router.get(_CONFIRM_PATH, response_class=HTMLResponse)
def confirm_email_page(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    oidc_email_confirm: Annotated[str | None, Cookie()] = None,
):
    """Ask for the code sent to the address an untrusted provider reported."""
    pending = _pending_confirmation(request, tenant_id)
    if pending is None or not oidc_email_confirm:
        return _abandon_confirmation(request, "session_expired")
    _, pending_email = pending

    return templates.TemplateResponse(
        request,
        "email_verification.html",
        {
            "request": request,
            "email": pending_email["email"],
            "intro": "Confirm your email address to finish signing in.",
            "verify_action": _CONFIRM_PATH,
            "resend_action": f"{_CONFIRM_PATH}/resend",
            "back_label": "Back to sign in",
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
            "csrf_token": make_csrf_token_func(request),
            "csp_nonce": get_csp_nonce(request),
        },
    )


@router.post(_CONFIRM_PATH)
def confirm_email(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
    code: Annotated[str, Form(max_length=100)],
    oidc_email_confirm: Annotated[str | None, Cookie()] = None,
):
    """Check the code, confirm the address, and resume the sign-in."""
    pending = _pending_confirmation(request, tenant_id)
    if pending is None or not oidc_email_confirm:
        return _abandon_confirmation(request, "session_expired")
    parked, pending_email = pending

    client_ip = extract_remote_address(request) or "unknown"
    try:
        ratelimit.prevent(
            "oidc_email_confirm:ip:{ip}:user:{user_id}",
            limit=5,
            timespan=MINUTE * 5,
            ip=client_ip,
            user_id=parked["user_id"],
        )
    except RateLimitError:
        return RedirectResponse(
            url="/auth/oidc/confirm-email?error=too_many_attempts", status_code=303
        )

    is_valid, _, cookie_tenant_id = validate_verification_cookie(
        oidc_email_confirm, code.strip(), expected_email=pending_email["email"]
    )
    if not is_valid or cookie_tenant_id != str(tenant_id):
        return RedirectResponse(url="/auth/oidc/confirm-email?error=invalid_code", status_code=303)

    oidc_service.confirm_sign_in_email(
        tenant_id, parked["user_id"], pending_email["email_id"], parked["connection_id"]
    )
    request.session.pop(_CONFIRM_SESSION_KEY, None)
    response = _finish_sign_in(
        request,
        tenant_id,
        parked["user_id"],
        parked.get("mfa_method") or "email",
        requires_mfa=oidc_service.oidc_connection_requires_platform_mfa(
            tenant_id, parked["connection_id"]
        ),
    )
    response.delete_cookie(_CONFIRM_COOKIE)
    return response


@router.post(f"{_CONFIRM_PATH}/resend")
def resend_confirmation_code(
    request: Request,
    tenant_id: Annotated[str, Depends(get_tenant_id_from_request)],
):
    """Send a new code to the address being confirmed."""
    pending = _pending_confirmation(request, tenant_id)
    if pending is None:
        return _abandon_confirmation(request, "session_expired")
    _, pending_email = pending

    client_ip = extract_remote_address(request) or "unknown"
    try:
        ratelimit.prevent(
            "oidc_email_confirm_resend:ip:{ip}", limit=5, timespan=MINUTE * 10, ip=client_ip
        )
        ratelimit.prevent(
            "oidc_email_confirm_send:email:{email}",
            limit=5,
            timespan=MINUTE * 10,
            email=pending_email["email"],
        )
    except RateLimitError:
        return RedirectResponse(
            url="/auth/oidc/confirm-email?error=too_many_requests", status_code=303
        )

    response = RedirectResponse(url="/auth/oidc/confirm-email?success=code_sent", status_code=303)
    _set_confirm_cookie(response, pending_email["email"], tenant_id)
    return response


def _get_connection(tenant_id: str, connection_id: str) -> dict | None:
    """Fetch a connection row (no authorization; public auth path).

    Returns ``None`` for a malformed (non-UUID) ``connection_id`` so the
    caller maps it to ``idp_not_found`` rather than letting the database
    raise an unhandled ``DataError`` (500).
    """
    import uuid as uuid_mod

    try:
        uuid_mod.UUID(connection_id)
    except ValueError:
        return None
    return oidc_service.get_connection_row(tenant_id, connection_id)


def _callback_url(request: Request, connection_id: str) -> str:
    """Build the callback URL on the tenant host (always HTTPS)."""
    from utils.urls import tenant_base_url

    return oidc_service.callback_url(tenant_base_url(request), connection_id)


def _log_failure(
    tenant_id: str,
    connection_id: str,
    connection: dict,
    reason: str,
    detail: str | None,
    entry: str,
) -> None:
    """Log an ``oidc_login_failed`` event (best-effort)."""
    try:
        log_event(
            tenant_id=tenant_id,
            actor_user_id=SYSTEM_ACTOR_ID,
            artifact_type="oidc_idp_connection",
            artifact_id=connection_id,
            event_type="oidc_login_failed",
            metadata={
                "idp_name": connection.get("name"),
                "reason": reason,
                "detail": detail,
                "entry": entry,
            },
        )
    except Exception:  # noqa: BLE001 - audit logging must not break the flow
        pass
