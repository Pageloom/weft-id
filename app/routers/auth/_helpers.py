"""Shared helpers for auth router modules."""

import services.saml as saml_service
from fastapi import Request, Response
from utils.csp_nonce import get_csp_nonce
from utils.redirects import safe_redirect
from utils.templates import templates


def _get_client_ip(request: Request) -> str:
    """Get client IP address from request headers or connection."""
    # Check X-Forwarded-For header (set by reverse proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain (original client)
        return forwarded_for.split(",")[0].strip()
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    return "unknown"


def _idp_handoff(request: Request, target: str) -> Response:
    """Render a same-origin hand-off page that navigates (GET) to an IdP hop.

    The email step is a form POST. Chromium applies the login page's CSP
    ``form-action 'self'`` to every hop of the redirect chain that follows a
    form submission, so a 303 from here to ``/saml/login/{id}`` or
    ``/auth/oidc/{id}/login`` is cut off at the next hop: the off-origin
    redirect to the identity provider (and any further redirects the provider
    itself makes) is refused and the user is left on the login page.

    A 200 page whose ``<meta http-equiv="refresh">`` starts a fresh top-level
    GET navigation is outside that chain, so the IdP hop is no longer governed
    by ``form-action``. ``target`` is always a same-origin path built from a
    literal prefix plus the routed IdP id; it is never request-supplied.
    """
    return templates.TemplateResponse(
        request,
        "auth_idp_handoff.html",
        {"request": request, "target": target, "csp_nonce": get_csp_nonce(request)},
    )


def _route_after_email_verification(request: Request, tenant_id: str, email: str) -> Response:
    """
    Route user to appropriate auth flow after email possession is verified.

    This is safe to call because the user has proven they own the email address.
    """
    from urllib.parse import quote

    result = saml_service.determine_auth_route(tenant_id, email)

    if result.route_type == "password":
        return safe_redirect(f"/login?prefill_email={quote(email)}&show_password=true")

    if result.route_type in ("idp", "idp_jit"):
        return _idp_handoff(request, f"/saml/login/{result.idp_id}")

    if result.route_type in ("idp_oidc", "idp_oidc_jit"):
        return _idp_handoff(request, f"/auth/oidc/{result.idp_id}/login")

    if result.route_type == "inactivated":
        return safe_redirect(f"/login?error=account_inactivated&prefill_email={quote(email)}")

    if result.route_type == "not_found":
        return safe_redirect(f"/login?error=user_not_found&prefill_email={quote(email)}")

    if result.route_type in ("idp_disabled", "idp_oidc_disabled"):
        return safe_redirect(f"/login?error=idp_disabled&prefill_email={quote(email)}")

    if result.route_type == "no_auth_method":
        return safe_redirect(f"/login?error=no_auth_method&prefill_email={quote(email)}")

    if result.route_type == "invalid_email":
        return safe_redirect(f"/login?error=invalid_email&prefill_email={quote(email)}")

    # Unknown route type - fallback to password form
    return safe_redirect(f"/login?prefill_email={quote(email)}&show_password=true")


def _route_without_verification(request: Request, tenant_id: str, email: str) -> Response:
    """
    Route user to auth flow without email possession verification.

    Maps inactivated, not_found, idp_disabled, and no_auth_method all to the
    password form to prevent information leakage. Only the idp/idp_jit and
    idp_oidc/idp_oidc_jit routes get an IdP hand-off; password gets the
    password form; invalid_email shows an error.
    """
    from urllib.parse import quote

    result = saml_service.determine_auth_route(tenant_id, email)

    if result.route_type in ("idp", "idp_jit"):
        return _idp_handoff(request, f"/saml/login/{result.idp_id}")

    if result.route_type in ("idp_oidc", "idp_oidc_jit"):
        return _idp_handoff(request, f"/auth/oidc/{result.idp_id}/login")

    if result.route_type == "invalid_email":
        return safe_redirect(f"/login?error=invalid_email&prefill_email={quote(email)}")

    # Everything else (password, inactivated, not_found, idp_disabled,
    # idp_oidc_disabled, no_auth_method, unknown) routes to password form with
    # no disclosure
    return safe_redirect(f"/login?prefill_email={quote(email)}&show_password=true")
