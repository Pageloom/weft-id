"""Shared helpers for auth router modules."""

import services.saml as saml_service
import services.users as users_service
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
        # Check if super admin - allow self-reactivation
        if result.user_id:
            user = users_service.get_user_by_id_raw(tenant_id, result.user_id)
            if user and user.get("role") == "super_admin":
                return RedirectResponse(
                    url=f"/login/super-admin-reactivate?user_id={result.user_id}&prefill_email={quote(email)}",
                    status_code=303,
                )
        # Regular users/admins see inactivation error
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
