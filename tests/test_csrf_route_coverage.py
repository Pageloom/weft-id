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
            "/saml/acs": "SAML Assertion Consumer Service receives POST from external IdPs",
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
