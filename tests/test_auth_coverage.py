"""Tests to verify authentication coverage across all routes."""

import sys

sys.path.insert(0, "app")

from dependencies import get_current_user, require_admin, require_current_user, require_super_admin
from main import app
from pages import PAGES, PagePermission, get_all_pages


def get_public_paths():
    """Get all paths that are marked as PUBLIC in pages.py."""
    public_paths = set()
    for page in get_all_pages(PAGES):
        if page.permission == PagePermission.PUBLIC:
            public_paths.add(page.path)
    return public_paths


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
        "/account-recovery/{token}",  # Account recovery after proof of email possession
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
            if path in ["/api/docs", "/api/redoc", "/openapi.json", "/health"]:
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


def test_router_level_dependencies_are_set():
    """Test that routers have the correct dependencies set at the router level."""
    # Find routers
    account_routes = [r for r in app.routes if hasattr(r, "path") and r.path.startswith("/account")]
    users_routes = [r for r in app.routes if hasattr(r, "path") and r.path.startswith("/users")]
    settings_routes = [
        r for r in app.routes if hasattr(r, "path") and r.path.startswith("/admin/settings")
    ]

    # Account routes should have authentication (either require_current_user or get_current_user)
    auth_deps = {get_current_user, require_current_user, require_admin, require_super_admin}

    # Paths that start with /account but don't require authentication
    account_exceptions = {"/account-recovery/{token}"}

    for route in account_routes:
        if hasattr(route, "dependant"):
            if route.path in account_exceptions:
                continue
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
