"""Shared post-authentication login completion helper.

Extracted from the tail of `mfa_verify` so that other authenticated
completion paths (enhanced-auth enrollment, passkey login in later
iterations) can reuse the same session regeneration, activity bookkeeping,
and post-auth redirect logic.
"""

import services.settings as settings_service
import services.users as users_service
from fastapi import Request
from fastapi.responses import RedirectResponse
from routers.saml_idp._helpers import extract_pending_sso, get_post_auth_redirect
from services.event_log import log_event
from utils.session import regenerate_session


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
    regenerate_session(request, user_id, max_age, additional_data=pending_sso)

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

    # Redirect to consent page if pending SSO, otherwise dashboard
    redirect_url = get_post_auth_redirect(request.session)
    return RedirectResponse(url=redirect_url, status_code=303)
