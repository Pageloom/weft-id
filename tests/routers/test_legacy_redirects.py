"""Tests for routers/legacy_redirects.py: 301 redirects from pre-restructure paths.

These redirects must work for unauthenticated clients too (a stale bookmark or
emailed link should redirect straight to the new URL; the destination route
enforces its own auth/role checks after the redirect completes). No auth
overrides are set up here on purpose -- that is the point of the test.
"""

import pytest
from fastapi.testclient import TestClient
from main import app
from routers import legacy_redirects

client = TestClient(app)


def _declared_redirects() -> list[tuple[str, str, int]]:
    """Read (old_path, target, status) straight off the router's own routes.

    The handlers take no arguments and return a literal ``RedirectResponse``,
    so calling them directly yields the redirect this module actually serves.
    This is the source of truth the hand-maintained table below is checked
    against, so a redirect added to the module without a table entry (or with
    a different target) fails instead of going untested.
    """
    declared = []
    for route in legacy_redirects.router.routes:
        response = route.endpoint()
        declared.append((route.path, response.headers["location"], response.status_code))
    return declared


def _registered_get_paths() -> set[str]:
    """Every GET path the mounted app serves, including included sub-routers."""

    def walk(routes, prefix=""):
        for route in routes:
            original = getattr(route, "original_router", None)
            if original is not None:
                # FastAPI defers included routers behind a wrapper route.
                context_prefix = getattr(getattr(route, "include_context", None), "prefix", "")
                yield from walk(original.routes, prefix + context_prefix)
                continue
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None)
            if path and methods:
                yield prefix + path, methods

    paths = {path for path, methods in walk(app.routes) if "GET" in methods}
    # Guard: if the walker ever stops seeing included routers (FastAPI internals
    # change), every resolution assertion below would pass vacuously.
    assert "/dashboard" in paths, "route walker failed to enumerate included routers"
    return paths


LEGACY_REDIRECTS = [
    ("/admin/groups", "/groups"),
    ("/admin/groups/", "/groups"),
    ("/admin/groups/list", "/groups/list"),
    ("/admin/groups/new", "/groups/new"),
    ("/admin/todo", "/directory/requests"),
    ("/admin/todo/", "/directory/requests"),
    ("/admin/todo/reactivation", "/directory/requests/reactivation"),
    (
        "/admin/todo/reactivation/history",
        "/directory/requests/reactivation/history",
    ),
    ("/admin/todo/user-attributes", "/directory/requests/user-attributes"),
    ("/admin/settings/user-attributes", "/directory/attributes"),
    ("/admin/audit/user-export", "/directory/exports"),
    ("/admin/settings/identity-providers", "/identity-providers/saml"),
    ("/admin/settings/identity-providers/", "/identity-providers/saml"),
    ("/admin/settings/identity-providers/new", "/identity-providers/saml/new"),
    ("/admin/settings/oidc-identity-providers", "/identity-providers/oidc"),
    ("/admin/settings/oidc-identity-providers/", "/identity-providers/oidc"),
    ("/admin/settings/oidc-identity-providers/new", "/identity-providers/oidc/new"),
    ("/admin/settings/privileged-domains", "/identity-providers/domain-routing"),
    ("/admin/settings/service-providers", "/applications/saml"),
    ("/admin/settings/service-providers/", "/applications/saml"),
    ("/admin/settings/service-providers/new", "/applications/saml/new"),
    ("/admin/integrations/apps", "/applications/oauth"),
    ("/admin/settings/protected-domains", "/applications/forward-auth/domains"),
    ("/admin/settings/proxy-apps", "/applications/forward-auth/apps"),
    ("/admin/integrations/b2b", "/applications/service-accounts"),
    ("/admin/integrations", "/applications"),
    ("/admin/integrations/", "/applications"),
    ("/admin/settings/security", "/security"),
    ("/admin/settings/security/sessions", "/security/sessions"),
    ("/admin/settings/security/certificates", "/security/certificates"),
    ("/admin/settings/security/passwords", "/security/passwords"),
    ("/admin/settings/security/permissions", "/security/permissions"),
    ("/admin/settings/security/authentication", "/security/authentication"),
    ("/admin/audit", "/audit"),
    ("/admin/audit/", "/audit"),
    ("/admin/audit/events", "/audit/events"),
    ("/admin/audit/saml-debug", "/audit/saml-debug"),
    ("/admin/settings", "/settings"),
    ("/admin/settings/", "/settings"),
    ("/admin/settings/branding", "/settings/branding"),
    ("/admin/settings/branding/global", "/settings/branding/global"),
    ("/admin/settings/branding/groups", "/settings/branding/groups"),
    ("/admin/settings/about", "/settings/about"),
    ("/admin", "/dashboard"),
    ("/admin/", "/dashboard"),
]


@pytest.mark.parametrize("old_path,new_path", LEGACY_REDIRECTS)
def test_legacy_redirect_301_to_new_path(old_path, new_path):
    """Every moved static path 301-redirects to its new home."""
    response = client.get(old_path, follow_redirects=False)

    assert response.status_code == 301
    assert response.headers["location"] == new_path


def test_legacy_redirect_does_not_require_authentication():
    """Legacy redirects fire before any auth check -- no login required to be redirected."""
    response = client.get("/admin/groups", follow_redirects=False)

    assert response.status_code == 301
    assert response.headers["location"] == "/groups"


def test_table_matches_the_routes_the_module_actually_declares():
    """The table above must list every declared redirect, with the same target.

    Guards the failure mode where a section moves and its redirects are added
    to ``legacy_redirects.py`` but never added here, leaving them untested.
    """
    declared = {path: target for path, target, _ in _declared_redirects()}

    assert declared == dict(LEGACY_REDIRECTS)


def test_every_declared_redirect_is_permanent():
    """Old bookmarks must be updated by the browser, so every hop is a 301."""
    assert {status for _, _, status in _declared_redirects()} == {301}


@pytest.mark.parametrize("target", sorted({t for _, t, _ in _declared_redirects()}))
def test_redirect_target_resolves_to_a_registered_route(target):
    """No redirect may point at a path the app does not serve.

    The 301 assertions above only compare header strings, so a target that a
    later move renamed again would still "pass" while sending the user to a
    404. This walks the mounted route table instead. A target registered only
    with a trailing slash is accepted: FastAPI answers the slashless form with
    its own 307 to the canonical path.
    """
    registered = _registered_get_paths()

    assert target in registered or f"{target}/" in registered
