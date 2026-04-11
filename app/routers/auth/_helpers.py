"""Shared helpers for auth router modules."""

import services.saml as saml_service
from fastapi import Request
from fastapi.responses import RedirectResponse


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


def _route_after_email_verification(
    request: Request, tenant_id: str, email: str
) -> RedirectResponse:
    """
    Route user to appropriate auth flow after email possession is verified.

    This is safe to call because the user has proven they own the email address.
    """
    from urllib.parse import quote

    result = saml_service.determine_auth_route(tenant_id, email)

    if result.route_type == "password":
        return RedirectResponse(
            url=f"/login?prefill_email={quote(email)}&show_password=true",
            status_code=303,
        )

    if result.route_type in ("idp", "idp_jit"):
        return RedirectResponse(
            url=f"/saml/login/{result.idp_id}",
            status_code=303,
        )

    if result.route_type == "inactivated":
        return RedirectResponse(
            url=f"/login?error=account_inactivated&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "not_found":
        return RedirectResponse(
            url=f"/login?error=user_not_found&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "idp_disabled":
        return RedirectResponse(
            url=f"/login?error=idp_disabled&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "no_auth_method":
        return RedirectResponse(
            url=f"/login?error=no_auth_method&prefill_email={quote(email)}",
            status_code=303,
        )

    if result.route_type == "invalid_email":
        return RedirectResponse(
            url=f"/login?error=invalid_email&prefill_email={quote(email)}",
            status_code=303,
        )

    # Unknown route type - fallback to password form
    return RedirectResponse(
        url=f"/login?prefill_email={quote(email)}&show_password=true",
        status_code=303,
    )


def _route_without_verification(request: Request, tenant_id: str, email: str) -> RedirectResponse:
    """
    Route user to auth flow without email possession verification.

    Maps inactivated, not_found, idp_disabled, and no_auth_method all to the
    password form to prevent information leakage. Only idp/idp_jit get an IdP
    redirect; password gets the password form; invalid_email shows an error.
    """
    from urllib.parse import quote

    result = saml_service.determine_auth_route(tenant_id, email)

    if result.route_type in ("idp", "idp_jit"):
        return RedirectResponse(
            url=f"/saml/login/{result.idp_id}",
            status_code=303,
        )

    if result.route_type == "invalid_email":
        return RedirectResponse(
            url=f"/login?error=invalid_email&prefill_email={quote(email)}",
            status_code=303,
        )

    # Everything else (password, inactivated, not_found, idp_disabled,
    # no_auth_method, unknown) routes to password form with no disclosure
    return RedirectResponse(
        url=f"/login?prefill_email={quote(email)}&show_password=true",
        status_code=303,
    )
