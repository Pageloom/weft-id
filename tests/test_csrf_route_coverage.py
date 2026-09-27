"""Static analysis test to verify CSRF protection covers all frontend routes.

This test serves as a guardrail to ensure all non-GET routes in frontend
routers are protected by CSRF middleware. It fails if any frontend route
would bypass CSRF protection.
"""

import ast
from pathlib import Path

import pytest


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


def get_app_path() -> Path:
    """Get the app directory path."""
    return get_project_root() / "app"


def get_frontend_router_files() -> list[Path]:
    """Get all frontend router files (excluding API routers).

    Frontend routers are in app/routers/*.py (not under api/ subdirectory).
    """
    routers_path = get_app_path() / "routers"

    frontend_routers = []
    for py_file in routers_path.glob("*.py"):
        if py_file.name.startswith("__"):
            continue
        frontend_routers.append(py_file)

    return frontend_routers


def get_csrf_exempt_paths() -> list[str]:
    """Extract CSRF exempt paths from the middleware module."""
    csrf_module = get_app_path() / "middleware" / "csrf.py"

    with open(csrf_module) as f:
        source = f.read()

    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "CSRF_EXEMPT_PATHS":
                    if isinstance(node.value, ast.List):
                        paths = []
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant):
                                paths.append(elt.value)
                        return paths

    return []


def extract_routes_from_file(file_path: Path) -> list[dict]:
    """Extract route definitions from a router file.

    Returns list of dicts with:
    - method: HTTP method (get, post, put, patch, delete)
    - path: Route path from decorator
    - function_name: Handler function name
    - line_number: Line number in file
    - prefix: Router prefix if defined
    """
    with open(file_path) as f:
        source = f.read()

    tree = ast.parse(source)
    routes = []
    router_prefix = ""

    # First pass: find router prefix
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "router":
                    if isinstance(node.value, ast.Call):
                        for keyword in node.value.keywords:
                            if keyword.arg == "prefix":
                                if isinstance(keyword.value, ast.Constant):
                                    router_prefix = keyword.value.value

    # Second pass: find route decorators
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            for decorator in node.decorator_list:
                method = None
                path = ""

                # @router.post("/path") or @router.get("/path")
                if isinstance(decorator, ast.Call):
                    if isinstance(decorator.func, ast.Attribute):
                        if decorator.func.attr in (
                            "get",
                            "post",
                            "put",
                            "patch",
                            "delete",
                        ):
                            method = decorator.func.attr
                            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                                path = decorator.args[0].value

                # @router.post (without parentheses - rare but possible)
                elif isinstance(decorator, ast.Attribute):
                    if decorator.attr in ("get", "post", "put", "patch", "delete"):
                        method = decorator.attr

                if method:
                    full_path = router_prefix + path
                    routes.append(
                        {
                            "method": method,
                            "path": full_path,
                            "function_name": node.name,
                            "line_number": node.lineno,
                            "file": str(file_path.relative_to(get_project_root())),
                        }
                    )

    return routes


def is_path_csrf_exempt(path: str, exempt_paths: list[str]) -> bool:
    """Check if a path is exempt from CSRF protection."""
    for exempt in exempt_paths:
        if path.startswith(exempt):
            return True
    return False


class TestCSRFRouteCoverage:
    """Tests to verify CSRF protection covers all frontend routes."""

    def test_csrf_middleware_is_registered(self):
        """Verify CSRFMiddleware is registered in main.py."""
        main_py = get_app_path() / "main.py"

        with open(main_py) as f:
            source = f.read()

        tree = ast.parse(source)

        csrf_middleware_added = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "add_middleware":
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and arg.id == "CSRFMiddleware":
                                csrf_middleware_added = True
                                break

        assert csrf_middleware_added, (
            "CSRFMiddleware is not registered in app/main.py. "
            "All POST/PUT/PATCH/DELETE routes require CSRF protection."
        )

    def test_csrf_exempt_paths_are_documented(self):
        """Verify all CSRF exempt paths have documented justification.

        This test ensures new exempt paths aren't added without explicit
        acknowledgment. If you need to add a new exempt path, add it to
        the expected_exempt dict below with a justification comment.
        """
        exempt_paths = get_csrf_exempt_paths()

        # These are the expected exempt paths with justification
        expected_exempt = {
            "/api/": "API routes use Bearer token authentication",
            "/scim/": "Inbound SCIM receiver is called by IdPs with a bearer token",
            "/saml/acs": "SAML Assertion Consumer Service receives POST from external IdPs",
            "/saml/slo": "SAML SP SLO endpoint receives POST from external IdPs",
            "/saml/idp/sso": "SAML IdP SSO endpoint receives POST from external SPs",
            "/saml/idp/slo": "SAML IdP SLO endpoint receives POST from external SPs",
            "/oauth2/token": "OAuth2 token endpoint is called by OAuth clients",
        }

        for path in exempt_paths:
            assert path in expected_exempt, (
                f"Unexpected CSRF exempt path: '{path}'. "
                "If this is intentional, add it to the expected_exempt dict in "
                "tests/test_csrf_route_coverage.py with a justification comment."
            )

    def test_no_frontend_routes_accidentally_exempt(self):
        """Verify no frontend routes accidentally use CSRF-exempt path prefixes.

        Some routes are intentionally exempt (SAML ACS, OAuth2 token) because they
        receive requests from external systems. This test ensures any exempt routes
        are explicitly documented.
        """
        exempt_paths = get_csrf_exempt_paths()
        frontend_routers = get_frontend_router_files()

        # Routes that are intentionally exempt with documented justification
        intentionally_exempt_routes = {
            # SAML ACS receives POST from external Identity Providers
            ("/saml/acs", "post"): "Receives SAML assertions from external IdPs",
            # SAML SP SLO receives POST from external Identity Providers
            ("/saml/slo", "post"): "Receives SLO requests/responses from external IdPs",
            ("/saml/slo", "get"): "Receives SLO redirects from external IdPs",
            # OAuth2 token endpoint is called by OAuth clients
            ("/oauth2/token", "post"): "OAuth2 token endpoint called by OAuth clients",
        }

        problematic_routes = []

        for router_file in frontend_routers:
            routes = extract_routes_from_file(router_file)

            for route in routes:
                # Skip GET routes - they don't need CSRF protection
                if route["method"] == "get":
                    continue

                # Check if this non-GET route would be exempt
                if is_path_csrf_exempt(route["path"], exempt_paths):
                    # Check if this is an intentionally exempt route
                    route_key = (route["path"], route["method"])
                    if route_key not in intentionally_exempt_routes:
                        problematic_routes.append(route)

        if problematic_routes:
            details = "\n".join(
                f"  - {r['method'].upper()} {r['path']} "
                f"({r['file']}:{r['line_number']} - {r['function_name']})"
                for r in problematic_routes
            )
            pytest.fail(
                f"Found {len(problematic_routes)} frontend route(s) that would bypass "
                f"CSRF protection without documentation:\n{details}\n\n"
                "Either:\n"
                "1. Change the route path to not match CSRF_EXEMPT_PATHS prefixes, or\n"
                "2. Add the route to intentionally_exempt_routes in this test with "
                "a documented justification."
            )

    def test_frontend_routers_exist(self):
        """Verify frontend router files exist for this test to be meaningful."""
        frontend_routers = get_frontend_router_files()
        assert len(frontend_routers) > 0, "No frontend router files found to analyze"

    def test_csrf_exempt_paths_constant_exists(self):
        """Verify CSRF_EXEMPT_PATHS constant exists in csrf.py."""
        exempt_paths = get_csrf_exempt_paths()
        assert len(exempt_paths) > 0, (
            "CSRF_EXEMPT_PATHS not found or empty in app/middleware/csrf.py. "
            "This constant should define paths that bypass CSRF validation."
        )

    def test_csrf_middleware_runs_inside_session_and_body_limit(self):
        """CSRF must be registered before (so run inside) the session middleware.

        ``app.user_middleware`` lists layers outermost first. The session
        middleware must appear BEFORE the CSRF middleware so the session is
        decoded by the time the token is checked, and the body limit must
        also come first so an oversized form is rejected before the CSRF
        layer parses it. CSRF was registered on the wrong side of the session
        middleware from 2025-10-18 to 2026-09-14 and, because it failed open
        on a missing session, no form POST was ever validated in that time.
        """
        from main import app
        from middleware.body_limit import BodyLimitMiddleware
        from middleware.csrf import CSRFMiddleware
        from middleware.session import DynamicSessionMiddleware

        order = [m.cls for m in app.user_middleware]
        session_idx = order.index(DynamicSessionMiddleware)
        body_limit_idx = order.index(BodyLimitMiddleware)
        csrf_idx = order.index(CSRFMiddleware)

        assert session_idx < csrf_idx, (
            "CSRFMiddleware runs OUTSIDE DynamicSessionMiddleware. It must be "
            "added to the app BEFORE the session middleware (add_middleware prepends)."
        )
        assert body_limit_idx < csrf_idx, (
            "CSRFMiddleware runs OUTSIDE BodyLimitMiddleware, so it would parse an "
            "oversized form before the limit rejects it."
        )


# ============================================================================
# Guardrails derived from the real application's routing tree
# ============================================================================
#
# The static checks above read source files. These walk ``main.app`` so they
# see every route, including those in router packages, with the dependencies
# FastAPI actually resolved. They exist because turning CSRF enforcement on
# (2026-09-14) broke inbound SCIM: a bearer-authenticated surface outside
# ``/api/`` that had never been exempted, which no test noticed because the
# test client sends a valid token to every route.

# Dependencies that authenticate a caller WITHOUT the session cookie. A route
# using one of these is called by machines (an IdP, an API client) that can
# never present a CSRF token, so it must be exempt.
NON_SESSION_AUTH_DEPENDENCIES = frozenset(
    {"require_inbound_scim_auth", "get_current_user_api", "get_oidc_userinfo_token"}
)

# Dependencies that authenticate via the session cookie. A state-changing
# route using one of these must NOT be exempt.
SESSION_AUTH_DEPENDENCIES = frozenset(
    {"get_current_user", "require_current_user", "require_admin", "require_super_admin"}
)

# Exempt routes that legitimately combine a session with an exemption, with
# the reason. ``/oauth2/authorize`` accepts an RP-originated cross-site POST
# (OpenID Connect Core 1.0, 3.1.2.1) validated against the client's
# registration rather than the session.
SESSION_ROUTES_EXEMPT_BY_DESIGN = {"/oauth2/authorize"}

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def iter_app_routes(routes, prefix: str = "", inherited: tuple = ()):
    """Yield ``(full_path, route, inherited_dependency_names)`` for every APIRoute.

    FastAPI keeps included routers as wrappers that carry the include-time
    prefix and dependencies; walk them so paths and dependencies are the
    ones the app actually applies.
    """
    from fastapi.routing import APIRoute

    for route in routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route, inherited
        elif hasattr(route, "original_router") and hasattr(route, "include_context"):
            context = route.include_context
            extra = tuple(getattr(dep, "dependency", dep).__name__ for dep in context.dependencies)
            yield from iter_app_routes(
                route.original_router.routes, prefix + context.prefix, inherited + extra
            )
        elif hasattr(route, "routes"):
            yield from iter_app_routes(route.routes, prefix + getattr(route, "path", ""), inherited)


def dependency_names(dependant, acc: set | None = None) -> set:
    """All dependency callables (transitively) of a resolved FastAPI dependant."""
    acc = set() if acc is None else acc
    for sub in dependant.dependencies:
        acc.add(getattr(sub.call, "__name__", repr(sub.call)))
        dependency_names(sub, acc)
    return acc


def unsafe_app_routes() -> list[tuple[str, set[str], set[str]]]:
    """``(path, methods, dependency_names)`` for every state-changing route on main.app."""
    from main import app

    rows = []
    for path, route, inherited in iter_app_routes(app.routes):
        methods = route.methods & UNSAFE_METHODS
        if methods:
            rows.append((path, methods, dependency_names(route.dependant) | set(inherited)))
    assert len(rows) > 200, f"route walk found only {len(rows)} routes; the walker is broken"
    return rows


class TestCSRFExemptionsMatchAuthentication:
    def test_bearer_authenticated_routes_are_exempt(self):
        """Machine-called routes (SCIM receiver, API) cannot send a token; they must be exempt."""
        from middleware.csrf import _is_exempt

        offenders = [
            (sorted(methods), path, sorted(deps & NON_SESSION_AUTH_DEPENDENCIES))
            for path, methods, deps in unsafe_app_routes()
            if deps & NON_SESSION_AUTH_DEPENDENCIES and not _is_exempt(path)
        ]
        assert not offenders, (
            "Bearer-authenticated state-changing routes are NOT CSRF-exempt and will "
            "403 for every real caller. Add their prefix to CSRF_EXEMPT_PATHS in "
            f"app/middleware/csrf.py (and document it above):\n{offenders}"
        )

    def test_session_authenticated_routes_are_never_exempt(self):
        """A route that trusts the session cookie must be behind the CSRF check."""
        from middleware.csrf import _is_exempt

        offenders = [
            (sorted(methods), path, sorted(deps & SESSION_AUTH_DEPENDENCIES))
            for path, methods, deps in unsafe_app_routes()
            if deps & SESSION_AUTH_DEPENDENCIES
            and _is_exempt(path)
            and path not in SESSION_ROUTES_EXEMPT_BY_DESIGN
        ]
        assert not offenders, (
            "Session-authenticated state-changing routes fall under a CSRF-exempt "
            f"prefix and are open to cross-site request forgery:\n{offenders}"
        )

    def test_every_exempt_route_is_machine_or_protocol_facing(self):
        """Nothing under an exempt prefix may be an ordinary browser form.

        Every exempt state-changing route must either use non-session auth,
        be a protocol endpoint that authenticates the message itself (SAML
        ACS/SLO/SSO, OAuth2 token), or be listed as exempt by design.
        """
        from middleware.csrf import _is_exempt

        protocol_prefixes = ("/saml/", "/oauth2/token")
        offenders = [
            (sorted(methods), path)
            for path, methods, deps in unsafe_app_routes()
            if _is_exempt(path)
            and not deps & NON_SESSION_AUTH_DEPENDENCIES
            and not path.startswith(protocol_prefixes)
            and path not in SESSION_ROUTES_EXEMPT_BY_DESIGN
        ]
        assert not offenders, f"Unexplained CSRF-exempt routes:\n{offenders}"
