"""OIDC upstream login and callback endpoints.

The relying-party authorization-code flow with PKCE:

- ``GET /auth/oidc/{connection_id}/login`` generates ``state``, ``nonce``, and
  a PKCE ``code_verifier`` (S256 challenge), stores all three in the session
  (namespaced per connection), builds the authorize URL, and redirects
  off-origin to the IdP.
- ``GET /auth/oidc/{connection_id}/callback`` validates ``state``, has the
  provider adapter exchange the code and return the user's identity,
  correlates the user, and completes login.
  The session's state/nonce/verifier are cleared on first use so a replayed
  callback fails.

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
- **Audit**: started, completed, failed and refused events carry ``entry``
  (``login_button`` or ``routed``), kept in the session across the hop.
"""

from typing import Annotated

import services.emails as emails_service
import services.oidc_upstream as oidc_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from routers.auth._login_completion import (
    complete_authenticated_login,
    stash_upstream_oidc_session,
)
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.exceptions import ForbiddenError, NotFoundError, RateLimitError
from utils.email import send_mfa_code_email
from utils.mfa import create_email_otp
from utils.ratelimit import MINUTE, ratelimit
from utils.redirects import safe_redirect
from utils.request_metadata import extract_remote_address

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


def _clear_session_state(request: Request, connection_id: str) -> None:
    """Clear the per-connection state/nonce/verifier from the session."""
    for name in ("state", "nonce", "code_verifier", "entry"):
        request.session.pop(_session_key(connection_id, name), None)


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

    request.session[_session_key(connection_id, "state")] = state
    request.session[_session_key(connection_id, "nonce")] = nonce
    request.session[_session_key(connection_id, "code_verifier")] = code_verifier
    request.session[_session_key(connection_id, "entry")] = entry

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

    # Single-use: pop the state/nonce/verifier on first use.
    expected_state = request.session.pop(_session_key(connection_id, "state"), None)
    expected_nonce = request.session.pop(_session_key(connection_id, "nonce"), None)
    code_verifier = request.session.pop(_session_key(connection_id, "code_verifier"), None)
    entry = request.session.pop(_session_key(connection_id, "entry"), None)
    if entry != oidc_service.ENTRY_LOGIN_BUTTON:
        entry = oidc_service.ENTRY_ROUTED

    error = request.query_params.get("error")
    if error:
        _log_failure(tenant_id, connection_id, connection, "idp_error", error, entry)
        return _error_response("auth_failed")

    state = request.query_params.get("state")
    code = request.query_params.get("code")

    if expected_state is None or state != expected_state:
        _log_failure(tenant_id, connection_id, connection, "state_mismatch", None, entry)
        return _error_response("auth_failed")

    if not code:
        _log_failure(tenant_id, connection_id, connection, "missing_code", None, entry)
        return _error_response("auth_failed")

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
            nonce=expected_nonce,
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
    requires_mfa = oidc_service.oidc_connection_requires_platform_mfa(tenant_id, connection_id)

    id_token = identity.id_token
    if identity.upstream_sub:
        # Across the MFA detour the stash rides in the session cookie, so a
        # large ID token is left out there (logout then goes without
        # id_token_hint). Without MFA, login completes in this request.
        stash_upstream_oidc_session(
            request.session,
            connection_id=connection_id,
            user_id=user_id,
            upstream_sub=identity.upstream_sub,
            upstream_sid=identity.upstream_sid,
            id_token=id_token
            if id_token
            and (not requires_mfa or len(id_token) <= _MAX_COOKIE_STASHED_ID_TOKEN_LENGTH)
            else None,
        )

    # Platform MFA gate (mirrors the SAML ACS).
    if requires_mfa:
        mfa_method = user.get("mfa_method") or "email"
        request.session["pending_mfa_user_id"] = user_id
        request.session["pending_mfa_method"] = mfa_method

        if mfa_method == "email":
            code = create_email_otp(tenant_id, user_id)
            primary_email = emails_service.get_primary_email(tenant_id, user_id)
            if primary_email:
                send_mfa_code_email(primary_email, code, tenant_id=tenant_id)

        return RedirectResponse(url="/mfa/verify", status_code=303)

    return complete_authenticated_login(
        request,
        tenant_id,
        user_id,
        mfa_method=user.get("mfa_method") or "email",
    )


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
