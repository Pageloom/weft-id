"""301 redirects from pre-restructure admin nav paths to their new homes.

The admin navigation was restructured around concepts rather than permissions
(see ``.claude/ITERATION_nav_restructure.md``). Every old path under
``/admin/*`` -- static index/list/new pages, per-instance detail pages, and
query strings -- is rewritten here so old bookmarks, emailed links, and stale
documentation keep working.

A single catch-all handler rewrites against a longest-prefix-first table: the
old prefix is replaced with its new prefix, the remainder of the path
(per-instance IDs, sub-tabs) is preserved, and the original query string is
re-appended so filters, pagination, and flash params survive the hop.
``safe_redirect`` validates the result -- the ``redirect-validation``
compliance check only inspects ``RedirectResponse`` calls, and
``safe_redirect`` is the sanctioned same-origin builder (see
``routers/groups/members.py`` for the same pattern).
"""

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from utils.redirects import safe_redirect

router = APIRouter(tags=["legacy-redirects"], include_in_schema=False)

# (old_prefix, new_prefix) -- longest prefix first so a more specific mapping
# (e.g. /admin/integrations/apps) wins over its container (/admin/integrations)
# and a renamed leaf (e.g. /admin/audit/user-export) wins over its section
# (/admin/audit). The remainder of the path after the old prefix is preserved.
# The bare /admin wrapper is terminal: any path that falls through to it lands
# on the dashboard, not on /dashboard/<leftover>.
LEGACY_PREFIX_MAP = [
    ("/admin/settings/oidc-identity-providers", "/identity-providers/oidc"),
    ("/admin/settings/identity-providers", "/identity-providers/saml"),
    ("/admin/settings/privileged-domains", "/identity-providers/domain-routing"),
    ("/admin/settings/service-providers", "/applications/saml"),
    ("/admin/settings/protected-domains", "/applications/forward-auth/domains"),
    ("/admin/settings/user-attributes", "/directory/attributes"),
    ("/admin/settings/proxy-apps", "/applications/forward-auth/apps"),
    ("/admin/audit/user-export", "/directory/exports"),
    ("/admin/settings/security", "/security"),
    ("/admin/integrations/apps", "/applications/oauth"),
    ("/admin/settings/branding", "/settings/branding"),
    ("/admin/integrations/b2b", "/applications/service-accounts"),
    ("/admin/integrations", "/applications"),
    ("/admin/settings", "/settings"),
    ("/admin/groups", "/groups"),
    ("/admin/audit", "/audit"),
    ("/admin/todo", "/directory/requests"),
    ("/admin", "/dashboard"),
]


def _rewrite_legacy_path(path: str) -> str | None:
    """Return the new path for a pre-restructure ``/admin`` path, else None.

    The longest matching prefix is replaced with its new prefix and the
    remainder (per-instance IDs, sub-tabs) is preserved. A trailing slash on
    the remainder is stripped so ``/admin/groups/`` lands on the canonical
    ``/groups`` rather than ``/groups/``.
    """
    for old_prefix, new_prefix in LEGACY_PREFIX_MAP:
        if path == old_prefix or path.startswith(old_prefix + "/"):
            if old_prefix == "/admin":
                # The retired wrapper is terminal: an unknown or removed page
                # under /admin lands on the dashboard, not /dashboard/<leftover>.
                return "/dashboard"
            remainder = path[len(old_prefix) :].rstrip("/")
            return new_prefix + remainder
    return None


@router.get("/admin/{rest:path}")
def redirect_legacy_admin_path(request: Request, rest: str) -> RedirectResponse:
    """301 a pre-restructure ``/admin`` path to its new home.

    ``rest`` is the path after ``/admin`` (e.g. ``groups/123/membership``).
    The original query string is re-appended so filters, pagination, and flash
    params survive the hop. Unknown paths fall back to ``/dashboard``.
    """
    path = f"/admin/{rest}" if rest else "/admin"
    new_path = _rewrite_legacy_path(path) or "/dashboard"

    qs = request.url.query
    if qs:
        new_path += f"?{qs}"
    return safe_redirect(new_path, default="/dashboard", status_code=301)


@router.get("/admin")
def redirect_admin() -> RedirectResponse:
    """Bare ``/admin`` (the retired top-level wrapper) always goes to dashboard."""
    return safe_redirect("/dashboard", status_code=301)
