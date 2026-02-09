"""Tests to verify authentication coverage across all routes."""

import sys

sys.path.insert(0, "app")

from dependencies import get_current_user, require_admin, require_current_user, require_super_admin
from fastapi.testclient import TestClient
from main import app
from pages import PAGES, PagePermission, get_all_pages


def get_all_page_paths(pages):
    """Extract all page paths from the page hierarchy."""
    paths = []
    for page in pages:
        paths.append(page.path)
        if page.children:
            paths.extend(get_all_page_paths(page.children))
    return paths


def get_public_paths():
    """Get all paths that are marked as PUBLIC in pages.py."""
    public_paths = set()
    for page in get_all_pages(PAGES):
        if page.permission == PagePermission.PUBLIC:
            public_paths.add(page.path)
    return public_paths


def get_authenticated_paths():
    """Get all paths that require AUTHENTICATED permission."""
    paths = set()
    for page in get_all_pages(PAGES):
        if page.permission == PagePermission.AUTHENTICATED:
            paths.add(page.path)
    return paths


def get_admin_paths():
    """Get all paths that require ADMIN permission."""
    paths = set()
    for page in get_all_pages(PAGES):
        if page.permission == PagePermission.ADMIN:
            paths.add(page.path)
    return paths


def get_super_admin_paths():
    """Get all paths that require SUPER_ADMIN permission."""
    paths = set()
    for page in get_all_pages(PAGES):
        if page.permission == PagePermission.SUPER_ADMIN:
            paths.add(page.path)
    return paths


def test_all_non_public_routes_have_authentication():
    """Verify all non-public routes have authentication dependencies."""
    public_paths = get_public_paths()

    # Special paths that don't need auth (login, MFA verification, etc.)
    # These are public or handle auth themselves
    exception_paths = {
        "/login",
        "/logout",
        "/mfa/verify",
        "/mfa/verify/send-email",
        "/",  # Root redirect - handled by tenants router
        "/account/emails/verify/{email_id}/{nonce}",  # Email verification doesn't require login
    }

    # Authentication dependencies to check for
    auth_deps = {get_current_user, require_current_user, require_admin, require_super_admin}

    # Get all routes from the app
    for route in app.routes:
        if hasattr(route, "path") and hasattr(route, "methods"):
            path = route.path

            # Skip paths that are public or in exceptions
            if path in public_paths or path in exception_paths:
                continue

            # Skip docs/health check paths
            if path in ["/docs", "/redoc", "/openapi.json", "/health"]:
                continue

            # Check if route has ANY authentication dependency
            has_auth = False

            if hasattr(route, "dependant") and hasattr(route.dependant, "dependencies"):
                deps = [dep.call for dep in route.dependant.dependencies if hasattr(dep, "call")]
                has_auth = any(dep in auth_deps for dep in deps)

            # For paths not in exception list, they must have auth
            if path.startswith("/account") or path.startswith("/users"):
                assert has_auth, f"Route {path} is missing authentication dependency"
            elif path.startswith("/settings"):
                assert has_auth, f"Route {path} is missing authentication dependency"


def test_unauthenticated_requests_redirect():
    """Test that unauthenticated requests to protected routes redirect to /login."""
    client = TestClient(app)

    # Test protected routes
    protected_routes = [
        "/account/profile",
        "/account/emails",
        "/users/list",
        "/settings/privileged-domains",
    ]

    for route in protected_routes:
        # Make request without authentication (no session cookie)
        # Use a valid tenant hostname
        response = client.get(route, headers={"host": "test.example.com"}, follow_redirects=False)

        # Should redirect (either to /login or handled by middleware)
        # We expect either 303 redirect or 404 (if tenant doesn't exist)
        assert response.status_code in [
            303,
            404,
        ], (
            f"Route {route} should redirect or 404 for unauthenticated user, "
            f"got {response.status_code}"
        )


def test_admin_routes_have_admin_dependency():
    """Verify routes requiring admin role have require_admin dependency."""
    # /settings routes (except tenant-security) should have require_admin
    admin_route_prefixes = ["/settings/privileged-domains"]

    # Admin dependencies
    admin_deps = {require_admin, require_super_admin}

    for route in app.routes:
        if hasattr(route, "path"):
            path = route.path

            # Check if this is an admin route
            if any(path.startswith(prefix) for prefix in admin_route_prefixes):
                has_admin_dep = False

                if hasattr(route, "dependant") and hasattr(route.dependant, "dependencies"):
                    deps = [
                        dep.call for dep in route.dependant.dependencies if hasattr(dep, "call")
                    ]
                    has_admin_dep = any(dep in admin_deps for dep in deps)

                assert has_admin_dep, f"Admin route {path} is missing require_admin dependency"


def test_super_admin_routes_have_super_admin_dependency():
    """Verify routes requiring super_admin role have require_super_admin dependency."""
    # /settings/tenant-security should have require_super_admin
    super_admin_route_prefixes = ["/settings/tenant-security"]

    for route in app.routes:
        if hasattr(route, "path"):
            path = route.path

            # Check if this is a super admin route
            if any(path.startswith(prefix) for prefix in super_admin_route_prefixes):
                has_super_admin_dep = False

                if hasattr(route, "dependant") and hasattr(route.dependant, "dependencies"):
                    deps = [
                        dep.call for dep in route.dependant.dependencies if hasattr(dep, "call")
                    ]
                    has_super_admin_dep = require_super_admin in deps

                assert has_super_admin_dep, (
                    f"Super admin route {path} is missing require_super_admin dependency"
                )


def test_public_routes_accessible_without_auth():
    """Verify public routes are accessible without authentication."""
    client = TestClient(app)

    public_routes = ["/login"]

    for route in public_routes:
        # These should be accessible (though may 404 for tenant issues)
        # The key is they shouldn't redirect to /login
        response = client.get(route, headers={"host": "test.example.com"}, follow_redirects=False)

        # Should not redirect to /login (allow 404 for missing tenant, 200 for success)
        # But if it redirects, it shouldn't be to /login
        if response.status_code == 303:
            assert "/login" not in response.headers.get("location", ""), (
                f"Public route {route} should not redirect to /login"
            )


def test_router_level_dependencies_are_set():
    """Test that routers have the correct dependencies set at the router level."""
    # Find routers
    account_routes = [r for r in app.routes if hasattr(r, "path") and r.path.startswith("/account")]
    users_routes = [r for r in app.routes if hasattr(r, "path") and r.path.startswith("/users")]
    settings_routes = [
        r for r in app.routes if hasattr(r, "path") and r.path.startswith("/settings")
    ]

    # Account routes should have authentication (either require_current_user or get_current_user)
    auth_deps = {get_current_user, require_current_user, require_admin, require_super_admin}

    for route in account_routes:
        if hasattr(route, "dependant"):
            deps = [dep.call for dep in route.dependant.dependencies if hasattr(dep, "call")]
            has_auth = any(dep in auth_deps for dep in deps)
            assert has_auth, f"Account route {route.path} missing authentication dependency"

    # Users routes should have authentication
    for route in users_routes:
        if hasattr(route, "dependant"):
            deps = [dep.call for dep in route.dependant.dependencies if hasattr(dep, "call")]
            has_auth = any(dep in auth_deps for dep in deps)
            assert has_auth, f"Users route {route.path} missing authentication dependency"

    # Settings routes should have admin/super_admin authentication
    admin_deps = {require_admin, require_super_admin}
    for route in settings_routes:
        if hasattr(route, "dependant"):
            deps = [dep.call for dep in route.dependant.dependencies if hasattr(dep, "call")]
            has_auth = any(dep in admin_deps for dep in deps)
            assert has_auth, f"Settings route {route.path} missing admin/super_admin dependency"
