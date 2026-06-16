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


def get_post_auth_redirect(session: dict, default: str = "/dashboard") -> str:
    """Return the post-login destination.

    Priority:
      1. Pending SAML SSO consent (``/saml/idp/consent``).
      2. A pending forward-auth authorize step (``pending_forward_auth_authorize``),
         consumed here. Only a safe rooted-relative path is honored; anything else
         is ignored (open-redirect guard).
      3. ``default`` (``/dashboard``).
    """
    if session.get("pending_sso_sp_entity_id"):
        return "/saml/idp/consent"

    fa_target = session.pop("pending_forward_auth_authorize", None)
    if (
        isinstance(fa_target, str)
        and fa_target.startswith("/forward-auth/authorize")
        and not fa_target.startswith("//")
        and "://" not in fa_target
        and "\r" not in fa_target
        and "\n" not in fa_target
    ):
        return fa_target

    return default
