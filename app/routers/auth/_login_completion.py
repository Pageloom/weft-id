"""Shared post-authentication login completion helper.

Extracted from the tail of `mfa_verify` so that other authenticated
completion paths (enhanced-auth enrollment, passkey login in later
iterations) can reuse the same session regeneration, activity bookkeeping,
and post-auth redirect logic.
"""

import time

import services.oidc_upstream as oidc_upstream_service
import services.settings as settings_service
import services.users as users_service
from fastapi import Request
from fastapi.responses import RedirectResponse
from routers.saml_idp._helpers import (
    extract_pending_returns,
    extract_pending_sso,
    get_post_auth_redirect,
)
from services.event_log import log_event
from utils.redirects import safe_redirect
from utils.session import SESSION_ID_KEY, regenerate_session

# An upstream OIDC sign-in waiting for login completion (possibly after the
# platform MFA step), so the new WeftID session can be linked to the upstream
# session. Bound to the user and short-lived: a stash left behind by an
# abandoned MFA step must not link a later, unrelated login.
PENDING_UPSTREAM_OIDC_SESSION_KEY = "pending_upstream_oidc_session"
PENDING_UPSTREAM_OIDC_SESSION_MAX_AGE = 15 * 60


def stash_upstream_oidc_session(
    session: dict,
    *,
    connection_id: str,
    user_id: str,
    upstream_sub: str,
    upstream_sid: str | None,
) -> None:
    """Remember the upstream OIDC sign-in until login completes."""
    session[PENDING_UPSTREAM_OIDC_SESSION_KEY] = {
        "connection_id": connection_id,
        "user_id": user_id,
        "sub": upstream_sub,
        "sid": upstream_sid,
        "at": int(time.time()),
    }


def _pending_upstream_oidc_session(session: dict, user_id: str) -> dict | None:
    """Pop the stashed upstream sign-in; None unless it is this user's and fresh."""
    pending = session.pop(PENDING_UPSTREAM_OIDC_SESSION_KEY, None)
    if not isinstance(pending, dict):
        return None
    at = pending.get("at")
    if (
        pending.get("user_id") != user_id
        or not isinstance(pending.get("connection_id"), str)
        or not isinstance(pending.get("sub"), str)
        or not isinstance(at, int)
        or time.time() - at > PENDING_UPSTREAM_OIDC_SESSION_MAX_AGE
    ):
        return None
    return pending


def complete_authenticated_login(
    request: Request,
    tenant_id: str,
    user_id: str,
    mfa_method: str,
    timezone: str = "",
    locale: str = "",
) -> RedirectResponse:
    """Finalize login for a user who has just passed authentication.

    This reproduces the final section of `mfa_verify` in `app/routers/mfa.py`:
    1. Extract pending SSO context before session regeneration
    2. Log `user_signed_in`
    3. Compute session max_age from tenant session settings
    4. Regenerate the session (prevents session fixation)
    4a. Link the new session to the upstream OIDC sign-in, if any
    5. Bind SSO context to the authenticated user (if any)
    6. Update the user's tz/locale/last_login as appropriate
    7. Redirect to the post-auth target (dashboard or SSO consent)

    Args:
        request: The current Starlette/FastAPI request with session.
        tenant_id: Tenant ID for scoping.
        user_id: The authenticated user's ID (string).
        mfa_method: The MFA method used (for the user_signed_in metadata).
        timezone: Client-side timezone to persist on the user (optional).
        locale: Client-side locale to persist on the user (optional).

    Returns:
        RedirectResponse to the post-auth target (303).
    """
    # IMPORTANT: Extract pending data BEFORE regenerating session (clear destroys it)
    tz_to_update = timezone or request.session.get("pending_timezone", "")
    locale_to_update = locale or request.session.get("pending_locale", "")

    # Extract pending SSO context (if user was redirected from an SP's AuthnRequest)
    pending_sso = extract_pending_sso(request.session)

    # Extract pending return paths (forward-auth or OAuth2 authorize requests
    # that sent the user to log in). Regeneration clears the session, so these
    # must ride along as additional data to be honoured by the redirect below.
    pending_returns = extract_pending_returns(request.session)

    # The upstream OIDC sign-in (if that is how the user got here), linked to
    # the new session below.
    pending_upstream = _pending_upstream_oidc_session(request.session, user_id)

    # Log successful sign-in event (also updates last_activity_at via log_event)
    log_event(
        tenant_id=tenant_id,
        actor_user_id=user_id,
        artifact_type="user",
        artifact_id=user_id,
        event_type="user_signed_in",
        metadata={"mfa_method": mfa_method},
    )

    # Fetch tenant security settings to configure session persistence
    security_settings = settings_service.get_session_settings(tenant_id)

    if security_settings:
        persistent = security_settings.get("persistent_sessions", True)
        timeout = security_settings.get("session_timeout_seconds")
    else:
        persistent = True
        timeout = None

    # Determine max_age for session cookie
    if not persistent:
        max_age = None  # Session cookie (expires on browser close)
    elif timeout:
        max_age = timeout  # Use configured timeout
    else:
        max_age = 30 * 24 * 3600  # 30 days as default for persistent

    # CRITICAL: Regenerate session to prevent session fixation attacks
    regenerate_session(
        request, user_id, max_age, additional_data={**pending_returns, **(pending_sso or {})}
    )

    if pending_upstream:
        oidc_upstream_service.record_upstream_session(
            tenant_id=tenant_id,
            sid=request.session[SESSION_ID_KEY],
            connection_id=pending_upstream["connection_id"],
            user_id=user_id,
            upstream_sub=pending_upstream["sub"],
            upstream_sid=pending_upstream.get("sid")
            if isinstance(pending_upstream.get("sid"), str)
            else None,
        )

    # Bind pending SSO context to the authenticated user (defense-in-depth)
    if pending_sso:
        request.session["pending_sso_user_id"] = user_id

    # Update timezone and locale if provided
    current_user = users_service.get_user_by_id_raw(tenant_id, user_id)

    tz_changed = tz_to_update and (not current_user or current_user.get("tz") != tz_to_update)
    locale_changed = locale_to_update and (
        not current_user or current_user.get("locale") != locale_to_update
    )

    if tz_changed and locale_changed:
        users_service.update_timezone_locale_and_last_login(
            tenant_id, user_id, tz_to_update, locale_to_update
        )
    elif tz_changed:
        users_service.update_timezone_and_last_login(tenant_id, user_id, tz_to_update)
    elif locale_changed:
        users_service.update_locale_and_last_login(tenant_id, user_id, locale_to_update)
    else:
        users_service.update_last_login(tenant_id, user_id)

    # Redirect to SSO consent, a pending authorize request, or the dashboard
    redirect_url = get_post_auth_redirect(request.session)
    return safe_redirect(redirect_url)
