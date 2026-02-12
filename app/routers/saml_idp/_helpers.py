"""Shared helpers for SAML IdP routers."""

from fastapi import Request

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


def extract_pending_sso(session: dict) -> dict[str, str] | None:
    """Extract pending SSO context from session.

    Returns dict of pending_sso_* keys if present, None otherwise.
    """
    sp_entity_id = session.get("pending_sso_sp_entity_id")
    if not sp_entity_id:
        return None

    return {key: session.get(key, "") for key in PENDING_SSO_KEYS}


def get_post_auth_redirect(session: dict, default: str = "/dashboard") -> str:
    """Return /saml/idp/consent if pending SSO context exists, else default."""
    if session.get("pending_sso_sp_entity_id"):
        return "/saml/idp/consent"
    return default
