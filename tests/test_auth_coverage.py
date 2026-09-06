"""Tests to verify authentication coverage across all routes."""

import sys

sys.path.insert(0, "app")

from dependencies import get_current_user, require_admin, require_current_user, require_super_admin
from main import app
from pages import PAGES, PagePermission, get_all_pages


def _iter_routes(routes, prefix=""):
    """Yield (full_path, route) for every APIRoute, recursing into included routers.

    FastAPI 0.138 defers included routers behind ``_IncludedRouter`` wrappers
    that carry no ``path``/``methods``/``dependant`` of their own; the real
    routes live on ``original_router.routes``. Walking ``app.routes`` directly
    would therefore see nothing and every assertion below would pass vacuously.
    """
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            context_prefix = getattr(getattr(route, "include_context", None), "prefix", "")
            yield from _iter_routes(original.routes, prefix + context_prefix)
            continue
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        # Only FastAPI APIRoutes carry a dependant; the starlette Route objects
        # FastAPI adds for /openapi.json and the docs pages do not.
        if path and methods and hasattr(route, "dependant"):
            yield prefix + path, route


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

    # Guard: if the walker ever stops seeing included routers (FastAPI internals
    # change), every assertion below would pass vacuously.
    all_paths = {path for path, _ in _iter_routes(app.routes)}
    assert "/dashboard" in all_paths, "route walker failed to enumerate included routers"

    for path, route in _iter_routes(app.routes):
        # Skip paths that are public or in exceptions
        if path in public_paths or path in exception_paths:
            continue

        # Skip docs/health check paths
        if path in ["/api/docs", "/api/redoc", "/openapi.json", "/health"]:
            continue

        # Check if route has ANY authentication dependency
        deps = [dep.call for dep in route.dependant.dependencies if hasattr(dep, "call")]
        has_auth = any(dep in auth_deps for dep in deps)

        # For paths not in exception list, they must have auth
        if path.startswith("/account") or path.startswith("/users"):
            assert has_auth, f"Route {path} is missing authentication dependency"
        elif path.startswith("/settings") or path.startswith("/security"):
            assert has_auth, f"Route {path} is missing authentication dependency"


def test_router_level_dependencies_are_set():
    """Test that routers have the correct dependencies set at the router level."""
    # Guard: if the walker ever stops seeing included routers (FastAPI internals
    # change), every assertion below would pass vacuously.
    all_paths = {path for path, _ in _iter_routes(app.routes)}
    assert "/dashboard" in all_paths, "route walker failed to enumerate included routers"

    # Account routes should have authentication (either require_current_user or get_current_user)
    auth_deps = {get_current_user, require_current_user, require_admin, require_super_admin}
    # Settings/security routes should have admin/super_admin authentication
    admin_deps = {require_admin, require_super_admin}

    # Paths that start with /account but don't require authentication
    account_exceptions = {"/account-recovery/{token}"}

    for path, route in _iter_routes(app.routes):
        deps = [dep.call for dep in route.dependant.dependencies if hasattr(dep, "call")]

        if path.startswith("/account"):
            if path in account_exceptions:
                continue
            has_auth = any(dep in auth_deps for dep in deps)
            assert has_auth, f"Account route {path} missing authentication dependency"

        if path.startswith("/users"):
            has_auth = any(dep in auth_deps for dep in deps)
            assert has_auth, f"Users route {path} missing authentication dependency"

        if path.startswith("/settings") or path.startswith("/security"):
            has_auth = any(dep in admin_deps for dep in deps)
            assert has_auth, f"Settings route {path} missing admin/super_admin dependency"
