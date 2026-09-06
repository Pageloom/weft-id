"""Template context helpers for adding common data to templates."""

import base64
import logging

from dependencies import build_requesting_user, get_current_user
from fastapi import Request
from middleware.csrf import get_csrf_token
from pages import get_navigation_context
from services import reactivation as reactivation_service
from services import users as users_service
from services.branding import get_branding_for_template
from utils import requests_badge
from utils.csp_nonce import get_csp_nonce
from utils.datetime_format import create_datetime_formatter, create_relative_date_formatter
from utils.mandala import generate_mandala_svg
from utils.static_assets import static_url

logger = logging.getLogger(__name__)


def _get_requests_badge_count(user: dict, tenant_id: str) -> int:
    """Count pending items behind the Directory > Requests nav badge.

    Sums pending reactivation requests and users with incomplete required
    profiles. Both service functions require admin/super_admin, matching
    the Requests page's own permission -- non-admins never see the badge.

    The sum is cached per tenant (short TTL) because it renders on every
    Directory-section page and the profile-completion count is a CROSS JOIN
    over users x attributes. Invalidated on approve/deny/force-complete.
    """
    if user.get("role") not in ("admin", "super_admin"):
        return 0

    cached = requests_badge.get_count(tenant_id)
    if cached is not None:
        return cached

    requesting_user = build_requesting_user(user, tenant_id)
    try:
        count = reactivation_service.count_pending_requests(
            requesting_user
        ) + users_service.count_users_with_missing_required(requesting_user)
    except Exception:
        # A DB error here must not 500 the page render (or the error page
        # itself, which also calls get_template_context). Degrade to 0 and
        # leave the cache empty so the next render retries.
        logger.exception("Failed to compute requests badge count for tenant %s", tenant_id)
        return 0

    requests_badge.set_count(tenant_id, count)
    return count


def get_template_context(request: Request, tenant_id: str, **kwargs):
    """Get common template context including user and navigation."""
    user = get_current_user(request, tenant_id)

    # Get the current path from the request
    current_path = request.url.path

    # Get navigation context
    nav_context = {}
    if user:
        nav_context = get_navigation_context(current_path, user.get("role"))
        # The badge only ever renders next to the Directory > Requests sub-nav
        # link (base.html), which only appears when Directory is the active
        # top-level section. Skip the two service calls otherwise.
        active_top_level = nav_context.get("active_top_level")
        if active_top_level and active_top_level.path == "/directory":
            nav_context["requests_badge_count"] = _get_requests_badge_count(user, tenant_id)
        else:
            nav_context["requests_badge_count"] = 0

    # Create datetime formatter with user's timezone and locale
    user_timezone = user.get("tz") if user else None
    user_locale = user.get("locale", "en_US") if user else "en_US"
    fmt_datetime = create_datetime_formatter(user_timezone, user_locale)
    fmt_relative = create_relative_date_formatter(user_timezone, user_locale)

    # Create CSRF token getter that captures the request
    def csrf_token() -> str:
        """Get the CSRF token for this request."""
        return get_csrf_token(request)

    # Generate tenant mandala SVGs for navigation (light + dark + favicon)
    # Always generate mandalas as fallback even in custom mode
    mandala_light = ""
    mandala_dark = ""
    mandala_favicon = ""
    branding = {
        "logo_mode": "mandala",
        "use_logo_as_favicon": False,
        "has_logo_light": False,
        "has_logo_dark": False,
        "site_title": "WeftID",
        "show_title_in_nav": True,
    }
    if user and user.get("tenant_id"):
        mandala_light, mandala_dark, favicon_svg = generate_mandala_svg(user["tenant_id"])
        b64 = base64.b64encode(favicon_svg.encode()).decode()
        mandala_favicon = f"data:image/svg+xml;base64,{b64}"
        branding = get_branding_for_template(str(user["tenant_id"]))

    # If user logged in via SAML with SLO configured, allow the IdP SLO URL
    # in CSP form-action so the logout form's redirect chain can reach the IdP.
    saml_slo_url = request.session.get("saml_slo_url") if hasattr(request, "session") else None
    if saml_slo_url and not getattr(request.state, "csp_form_action_url", None):
        request.state.csp_form_action_url = saml_slo_url

    context = {
        "request": request,
        "user": user,
        "nav_items": nav_context.get("top_level_items", []),  # Keep for backward compatibility
        "nav": nav_context,  # Full navigation context
        "fmt_datetime": fmt_datetime,  # Datetime formatter function
        "fmt_relative": fmt_relative,  # Relative date formatter function
        "csrf_token": csrf_token,  # CSRF token getter function
        "csp_nonce": get_csp_nonce(request),  # CSP nonce for inline scripts
        "static_url": static_url,  # Cache-busting static asset URLs
        "mandala_light": mandala_light,  # Light-mode mandala SVG
        "mandala_dark": mandala_dark,  # Dark-mode mandala SVG (with backdrop)
        "mandala_favicon": mandala_favicon,  # Favicon data URI
        "branding": branding,  # Tenant branding settings
        "site_title": branding.get("site_title", "WeftID"),  # For title blocks
        **kwargs,
    }

    return context
