"""Shared helpers for SAML IdP routers."""

from fastapi import Request
from fastapi.responses import RedirectResponse
from utils import auth as auth_utils

# Session keys for pending SSO context
PENDING_SSO_KEYS = (
    "pending_sso_sp_id",
    "pending_sso_sp_entity_id",
    "pending_sso_authn_request_id",
    "pending_sso_relay_state",
    "pending_sso_sp_name",
)

# Session keys holding a server-built relative path to resume after login.
# Each key is honoured by ``get_post_auth_redirect`` only when its value is a
# rooted path under the matching prefix (open-redirect guard). Login completion
# carries these keys across session regeneration (``extract_pending_returns``).
PENDING_FORWARD_AUTH_KEY = "pending_forward_auth_authorize"
PENDING_OAUTH2_AUTHORIZE_KEY = "pending_oauth2_authorize"
PENDING_DEVICE_KEY = "pending_device_verification"
PENDING_RETURN_PREFIXES = {
    PENDING_FORWARD_AUTH_KEY: "/forward-auth/authorize",
    PENDING_OAUTH2_AUTHORIZE_KEY: "/oauth2/authorize",
    PENDING_DEVICE_KEY: "/device",
}


def session_user_id(request: Request, tenant_id: str) -> str | None:
    """The signed-in user's ID, after the checks every authenticated page runs.

    The SAML IdP endpoints read the session directly rather than through the
    ``require_current_user`` dependency. This applies the same checks
    (session timeout, deactivation, forced password reset, server-side
    revocation) and clears the session when one fails.
    """
    user = auth_utils.get_current_user(request, tenant_id)
    return str(user["id"]) if user else None


def get_base_url(request: Request) -> str:
    """Get base URL from request for building SAML URLs (always HTTPS)."""
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"https://{host}"


def redirect_if_force_profile_completion(
    request: Request, tenant_id: str, user_id: str
) -> RedirectResponse | None:
    """Redirect to /account/profile if the user must complete their profile.

    SAML IdP endpoints check the session for ``user_id`` directly rather
    than going through the ``require_current_user`` dependency, so they
    bypass the iter 7 ``force_profile_completion`` gate. This helper
    closes that gap: callers invoke it right after establishing
    ``user_id`` and short-circuit the handler when a redirect is needed.

    Behavior: when the SSO context has already been stamped onto the
    session by ``_handle_sso_request``, redirecting here is benign. The
    pending context will sit untouched until the user completes their
    profile; if the original AuthnRequest expires meanwhile, the SP will
    simply re-issue one on the next attempt.
    """
    user = auth_utils.get_current_user(request, tenant_id)
    if user and user.get("force_profile_completion"):
        return RedirectResponse(url="/account/profile", status_code=303)
    return None


def extract_pending_sso(session: dict) -> dict[str, str] | None:
    """Extract pending SSO context from session.

    Returns dict of pending_sso_* keys if present, None otherwise.
    """
    sp_entity_id = session.get("pending_sso_sp_entity_id")
    if not sp_entity_id:
        return None

    return {key: session.get(key, "") for key in PENDING_SSO_KEYS}


def extract_pending_returns(session: dict) -> dict[str, str]:
    """Extract the pending return-path keys from the session.

    Returns only the keys that are present, so the result can be passed as
    ``additional_data`` to ``regenerate_session`` and survive the clear.
    """
    return {
        key: session[key]
        for key in PENDING_RETURN_PREFIXES
        if isinstance(session.get(key), str) and session[key]
    }


def _is_safe_return_path(target: str, prefix: str) -> bool:
    """True when ``target`` is a rooted relative path under ``prefix``."""
    return (
        target.startswith(prefix)
        and not target.startswith("//")
        and "://" not in target
        and "\r" not in target
        and "\n" not in target
    )


def get_post_auth_redirect(session: dict, default: str = "/dashboard") -> str:
    """Return the post-login destination.

    Priority:
      1. Pending SAML SSO consent (``/saml/idp/consent``).
      2. A pending forward-auth authorize step (``pending_forward_auth_authorize``),
         consumed here.
      3. A pending OAuth2/OIDC authorize request (``pending_oauth2_authorize``),
         consumed here.
      4. A pending device verification page (``pending_device_verification``),
         consumed here.
      5. ``default`` (``/dashboard``).

    For 2 to 4 only a safe rooted-relative path under the expected prefix is
    honored; anything else is ignored (open-redirect guard). The keys are
    popped either way so a stale or tampered value is never replayed.
    """
    if session.get("pending_sso_sp_entity_id"):
        return "/saml/idp/consent"

    for key, prefix in PENDING_RETURN_PREFIXES.items():
        target = session.pop(key, None)
        if isinstance(target, str) and _is_safe_return_path(target, prefix):
            return target

    return default
