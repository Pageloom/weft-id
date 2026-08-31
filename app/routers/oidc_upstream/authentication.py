"""OIDC upstream login and callback endpoints.

The relying-party authorization-code flow with PKCE:

- ``GET /auth/oidc/{connection_id}/login`` generates ``state``, ``nonce``, and
  a PKCE ``code_verifier`` (S256 challenge), stores all three in the session
  (namespaced per connection), builds the authorize URL, and redirects
  off-origin to the IdP.
- ``GET /auth/oidc/{connection_id}/callback`` validates ``state``, exchanges
  the code, validates the ID token, correlates the user, and completes login.
  The session's state/nonce/verifier are cleared on first use so a replayed
  callback fails.

Security (cross-cutting requirements):

- **SSRF**: the token exchange, userinfo, and JWKS fetches all go through
  ``build_safe_client()`` (in the service helpers), never bare ``httpx``.
- **Platform MFA**: when the connection has ``require_platform_mfa``, the
  callback stashes ``pending_mfa_user_id`` / ``pending_mfa_method`` and
  redirects to ``/mfa/verify`` instead of calling
  ``complete_authenticated_login`` -- exactly as the SAML ACS does.
- **Rate limiting**: both routes are rate-limited via ``ratelimit.prevent``.
"""

from typing import Annotated

import services.emails as emails_service
import services.oidc_upstream as oidc_service
from dependencies import get_tenant_id_from_request
from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from services.event_log import SYSTEM_ACTOR_ID, log_event
from services.exceptions import NotFoundError, RateLimitError
from utils.email import send_mfa_code_email
from utils.mfa import create_email_otp
from utils.ratelimit import MINUTE, ratelimit
from utils.redirects import safe_redirect
from utils.request_metadata import extract_remote_address

router = APIRouter()

# Session key namespaces. Per-connection so a user can start two logins.
_SESSION_PREFIX = "oidc_auth"


def _session_key(connection_id: str, name: str) -> str:
    return f"{_SESSION_PREFIX}:{connection_id}:{name}"


def _clear_session_state(request: Request, connection_id: str) -> None:
    """Clear the per-connection state/nonce/verifier from the session."""
    for name in ("state", "nonce", "code_verifier"):
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

    authorization_endpoint = connection.get("authorization_endpoint")
    client_id = connection.get("client_id")
    if not authorization_endpoint or not client_id:
        return _error_response("configuration_error")

    # Build the callback URL on the tenant host.
    callback_url = _callback_url(request, connection_id)

    state = oidc_service.generate_state()
    nonce = oidc_service.generate_nonce()
    code_verifier, code_challenge = oidc_service.generate_pkce_pair()

    scopes = connection.get("scopes") or "openid profile email"

    authorize_url = oidc_service.build_authorize_url(
        authorization_endpoint=authorization_endpoint,
        client_id=client_id,
        redirect_uri=callback_url,
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        scopes=scopes,
        hosted_domain=connection.get("hosted_domain"),
    )

    request.session[_session_key(connection_id, "state")] = state
    request.session[_session_key(connection_id, "nonce")] = nonce
    request.session[_session_key(connection_id, "code_verifier")] = code_verifier

    log_event(
        tenant_id=tenant_id,
        actor_user_id=SYSTEM_ACTOR_ID,
        artifact_type="oidc_idp_connection",
        artifact_id=connection_id,
        event_type="oidc_login_started",
        metadata={"idp_name": connection.get("name")},
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

    Validates ``state``, exchanges the code, validates the ID token, correlates
    the user, and completes login (or routes to ``/mfa/verify``).
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

    error = request.query_params.get("error")
    if error:
        _log_failure(tenant_id, connection_id, connection, "idp_error", error)
        return _error_response("auth_failed")

    state = request.query_params.get("state")
    code = request.query_params.get("code")

    if expected_state is None or state != expected_state:
        _log_failure(tenant_id, connection_id, connection, "state_mismatch", None)
        return _error_response("auth_failed")

    if not code:
        _log_failure(tenant_id, connection_id, connection, "missing_code", None)
        return _error_response("auth_failed")

    if not code_verifier:
        _log_failure(tenant_id, connection_id, connection, "missing_verifier", None)
        return _error_response("auth_failed")

    token_endpoint = connection.get("token_endpoint")
    client_id = connection.get("client_id")
    client_secret_enc = connection.get("client_secret_enc")
    if not token_endpoint or not client_id or not client_secret_enc:
        _log_failure(tenant_id, connection_id, connection, "configuration_error", None)
        return _error_response("configuration_error")

    callback_url = _callback_url(request, connection_id)

    try:
        client_secret = oidc_service.decrypt_client_secret(client_secret_enc)
        token_response = oidc_service.exchange_code(
            token_endpoint=token_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            code=code,
            redirect_uri=callback_url,
            code_verifier=code_verifier,
        )
    except oidc_service.TokenExchangeError as exc:
        _log_failure(tenant_id, connection_id, connection, "token_exchange", str(exc))
        return _error_response("auth_failed")

    id_token = token_response.get("id_token")
    if not id_token:
        _log_failure(tenant_id, connection_id, connection, "missing_id_token", None)
        return _error_response("auth_failed")

    jwks_uri = connection.get("jwks_uri")
    issuer = connection.get("issuer")
    if not jwks_uri or not issuer:
        _log_failure(tenant_id, connection_id, connection, "configuration_error", None)
        return _error_response("configuration_error")

    try:
        claims = oidc_service.validate_id_token(
            token=id_token,
            tenant_id=tenant_id,
            connection_id=connection_id,
            issuer=issuer,
            client_id=client_id,
            jwks_uri=jwks_uri,
            nonce=expected_nonce,
        )
    except oidc_service.IDTokenValidationError as exc:
        _log_failure(tenant_id, connection_id, connection, "id_token", str(exc))
        return _error_response("auth_failed")

    # Optionally merge userinfo claims (email may live there for some IdPs).
    userinfo_endpoint = connection.get("userinfo_endpoint")
    access_token = token_response.get("access_token")
    if userinfo_endpoint and access_token:
        try:
            userinfo = oidc_service.fetch_userinfo(
                userinfo_endpoint=userinfo_endpoint, access_token=access_token
            )
            claims = {**userinfo, **claims}
        except oidc_service.UserinfoError:
            # Userinfo is optional; a failure here must not break login.
            pass

    correlation_claim = connection.get("correlation_claim") or "sub"
    sub = claims.get(correlation_claim)
    if not sub or not isinstance(sub, str):
        _log_failure(tenant_id, connection_id, connection, "missing_sub", None)
        return _error_response("auth_failed")

    try:
        user = oidc_service.authenticate_via_oidc(
            tenant_id=tenant_id,
            connection=connection,
            sub=sub,
            claims=claims,
        )
    except NotFoundError as exc:
        _log_failure(tenant_id, connection_id, connection, "user_not_found", str(exc))
        return _error_response("user_not_found")
    except Exception as exc:  # noqa: BLE001 - ForbiddenError and others
        _log_failure(tenant_id, connection_id, connection, "auth_failed", str(exc))
        return _error_response("auth_failed")

    user_id = str(user["id"])

    # Platform MFA gate (mirrors the SAML ACS).
    if oidc_service.oidc_connection_requires_platform_mfa(tenant_id, connection_id):
        mfa_method = user.get("mfa_method") or "email"
        request.session["pending_mfa_user_id"] = user_id
        request.session["pending_mfa_method"] = mfa_method

        if mfa_method == "email":
            code = create_email_otp(tenant_id, user_id)
            primary_email = emails_service.get_primary_email(tenant_id, user_id)
            if primary_email:
                send_mfa_code_email(primary_email, code, tenant_id=tenant_id)

        return RedirectResponse(url="/mfa/verify", status_code=303)

    from routers.auth._login_completion import complete_authenticated_login

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

    return f"{tenant_base_url(request)}/auth/oidc/{connection_id}/callback"


def _log_failure(
    tenant_id: str,
    connection_id: str,
    connection: dict,
    reason: str,
    detail: str | None,
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
            },
        )
    except Exception:  # noqa: BLE001 - audit logging must not break the flow
        pass
