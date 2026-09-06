"""Tests for routers/legacy_redirects.py: 301 redirects from pre-restructure paths.

These redirects must work for unauthenticated clients too (a stale bookmark or
emailed link should redirect straight to the new URL; the destination route
enforces its own auth/role checks after the redirect completes). No auth
overrides are set up here on purpose -- that is the point of the test.
"""

import re

import pytest
from fastapi.testclient import TestClient
from main import app
from routers import legacy_redirects

client = TestClient(app)


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

# Per-instance detail-page bookmarks: the old path keeps its ID and sub-tabs,
# only the section prefix moves. These used to 404 before the catch-all.
LEGACY_INSTANCE_REDIRECTS = [
    ("/admin/groups/123/membership", "/groups/123/membership"),
    ("/admin/groups/123/applications", "/groups/123/applications"),
    ("/admin/groups/123/members/add", "/groups/123/members/add"),
    ("/admin/audit/events/abc-123", "/audit/events/abc-123"),
    ("/admin/audit/saml-debug/def-456", "/audit/saml-debug/def-456"),
    (
        "/admin/settings/identity-providers/idp-1/certificates",
        "/identity-providers/saml/idp-1/certificates",
    ),
    (
        "/admin/settings/identity-providers/idp-1/attributes",
        "/identity-providers/saml/idp-1/attributes",
    ),
    (
        "/admin/settings/oidc-identity-providers/conn-1/claim-mapping",
        "/identity-providers/oidc/conn-1/claim-mapping",
    ),
    (
        "/admin/settings/service-providers/sp-1/groups",
        "/applications/saml/sp-1/groups",
    ),
    (
        "/admin/settings/service-providers/sp-1/certificates",
        "/applications/saml/sp-1/certificates",
    ),
    ("/admin/integrations/apps/client-1", "/applications/oauth/client-1"),
    ("/admin/integrations/b2b/client-2", "/applications/service-accounts/client-2"),
    (
        "/admin/settings/protected-domains/detail/dom-1",
        "/applications/forward-auth/domains/detail/dom-1",
    ),
    (
        "/admin/settings/proxy-apps/detail/proxy-1",
        "/applications/forward-auth/apps/detail/proxy-1",
    ),
]


@pytest.mark.parametrize("old_path,new_path", LEGACY_REDIRECTS)
def test_legacy_redirect_301_to_new_path(old_path, new_path):
    """Every moved static path 301-redirects to its new home."""
    response = client.get(old_path, follow_redirects=False)

    assert response.status_code == 301
    assert response.headers["location"] == new_path


@pytest.mark.parametrize("old_path,new_path", LEGACY_INSTANCE_REDIRECTS)
def test_legacy_instance_redirect_301_to_new_path(old_path, new_path):
    """Per-instance detail-page bookmarks 301 to the same ID under the new prefix."""
    response = client.get(old_path, follow_redirects=False)

    assert response.status_code == 301
    assert response.headers["location"] == new_path


@pytest.mark.parametrize(
    "old_path,new_path",
    [
        ("/admin/audit/events", "/audit/events"),
        ("/admin/groups/list", "/groups/list"),
        ("/admin/todo/user-attributes", "/directory/requests/user-attributes"),
        ("/admin/audit/user-export", "/directory/exports"),
        (
            "/admin/settings/identity-providers/idp-1/certificates",
            "/identity-providers/saml/idp-1/certificates",
        ),
    ],
)
def test_legacy_redirect_preserves_query_string(old_path, new_path):
    """Query strings (filters, pagination, flash params) survive the 301."""
    response = client.get(f"{old_path}?tiers=security&page=3&size=100", follow_redirects=False)

    assert response.status_code == 301
    assert response.headers["location"] == f"{new_path}?tiers=security&page=3&size=100"


def test_legacy_redirect_does_not_require_authentication():
    """Legacy redirects fire before any auth check -- no login required to be redirected."""
    response = client.get("/admin/groups", follow_redirects=False)

    assert response.status_code == 301
    assert response.headers["location"] == "/groups"


def test_unknown_admin_path_falls_back_to_dashboard():
    """A stale bookmark to a removed page lands on the dashboard, not a 404."""
    response = client.get("/admin/removed-page/123", follow_redirects=False)

    assert response.status_code == 301
    assert response.headers["location"] == "/dashboard"


def test_table_matches_the_rewrite_the_module_actually_serves():
    """The static table must match the module's prefix rewrite exactly.

    Guards the failure mode where a section moves and its redirect is added to
    ``legacy_redirects.py`` but never added here, leaving it untested -- and
    the reverse, where a table entry drifts from what the module serves.
    """
    for old_path, new_path in LEGACY_REDIRECTS:
        assert legacy_redirects._rewrite_legacy_path(old_path) == new_path, old_path


def test_instance_table_matches_the_rewrite_the_module_actually_serves():
    """The per-instance table must match the module's prefix rewrite exactly."""
    for old_path, new_path in LEGACY_INSTANCE_REDIRECTS:
        assert legacy_redirects._rewrite_legacy_path(old_path) == new_path, old_path


def test_prefix_map_is_longest_prefix_first():
    """The map is ordered longest-prefix-first so specific mappings win.

    A shorter prefix (e.g. /admin/integrations) must never shadow a longer one
    (e.g. /admin/integrations/apps); the ordering is load-bearing.
    """
    lengths = [len(old) for old, _ in legacy_redirects.LEGACY_PREFIX_MAP]
    assert lengths == sorted(lengths, reverse=True)


def test_every_prefix_is_exercised_by_the_tables():
    """No prefix in the module's map goes untested.

    Each prefix must be represented by at least one static or instance entry,
    so a new mapping added to the module without a test entry fails here.
    """
    covered = {old for old, _ in LEGACY_REDIRECTS + LEGACY_INSTANCE_REDIRECTS}
    for old_prefix, _ in legacy_redirects.LEGACY_PREFIX_MAP:
        assert any(path == old_prefix or path.startswith(old_prefix + "/") for path in covered), (
            f"prefix {old_prefix} has no test entry"
        )


def _route_matches(path: str, route_pattern: str) -> bool:
    """Whether a concrete path matches a FastAPI route pattern.

    Converts ``{param}`` to a single segment and ``{param:path}`` to any
    remainder, so a per-instance target like ``/groups/123/membership`` matches
    the registered pattern ``/groups/{group_id}/membership``.
    """
    regex = re.sub(r"\{[^/}]+:path\}", ".+", route_pattern)
    regex = re.sub(r"\{[^}]+\}", "[^/]+", regex)
    return re.fullmatch(regex, path) is not None


@pytest.mark.parametrize(
    "target", sorted({t for _, t in LEGACY_REDIRECTS + LEGACY_INSTANCE_REDIRECTS})
)
def test_redirect_target_resolves_to_a_registered_route(target):
    """No redirect may point at a path the app does not serve.

    The 301 assertions above only compare header strings, so a target that a
    later move renamed again would still "pass" while sending the user to a
    404. This walks the mounted route table instead, matching parameterized
    patterns (per-instance targets) as well as literal ones. A target
    registered only with a trailing slash is accepted: FastAPI answers the
    slashless form with its own 307 to the canonical path.
    """
    registered = _registered_get_paths()

    assert any(_route_matches(target, p) or _route_matches(target + "/", p) for p in registered), (
        f"{target} does not match any registered route"
    )
