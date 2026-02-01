#!/usr/bin/env python3
"""
Compliance checking script for architectural principles verification.

This script programmatically checks for architectural violations to reduce
the token usage of manual compliance scanning by the AI agent.

Usage:
    python scripts/compliance_check.py [--check PRINCIPLE] [--json]

Principles checked:
    1. architecture   - Router should not import from database layer
    2. activity       - Service functions with RequestingUser must call track_activity()
                        or log_event()
    3. tenant         - SQL queries should filter by tenant_id
    4. api-first      - Service operations should have corresponding API endpoints
    5. authorization  - Web routes have proper auth dependencies matching pages.py

Output:
    By default, outputs human-readable text. Use --json for machine-readable JSON output.
"""

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Violation:
    """Represents a compliance violation."""

    principle: str
    severity: str  # 'high', 'medium', 'low'
    file_path: str
    line_number: int
    function_name: str | None
    description: str
    evidence: str
    suggested_fix: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "principle": self.principle,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "function_name": self.function_name,
            "description": self.description,
            "evidence": self.evidence,
            "suggested_fix": self.suggested_fix,
        }


@dataclass
class ComplianceReport:
    """Compliance scan results."""

    violations: list[Violation] = field(default_factory=list)
    files_scanned: int = 0
    functions_analyzed: int = 0

    def add(self, violation: Violation) -> None:
        self.violations.append(violation)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total_violations": len(self.violations),
                "high_severity": len([v for v in self.violations if v.severity == "high"]),
                "medium_severity": len([v for v in self.violations if v.severity == "medium"]),
                "low_severity": len([v for v in self.violations if v.severity == "low"]),
                "files_scanned": self.files_scanned,
                "functions_analyzed": self.functions_analyzed,
            },
            "violations": [v.to_dict() for v in self.violations],
        }


def get_project_root() -> Path:
    """Get the project root directory."""
    # Script is in scripts/, so go up one level
    return Path(__file__).parent.parent


def get_app_path() -> Path:
    """Get the app directory path."""
    return get_project_root() / "app"


# =============================================================================
# Principle 1: Service Layer Architecture (Router Import Violations)
# =============================================================================


def check_architecture_violations(report: ComplianceReport) -> None:
    """
    Check that routers don't import directly from the database layer.

    Violation: Router files importing from 'database' or 'app.database'
    """
    routers_path = get_app_path() / "routers"

    if not routers_path.exists():
        return

    for py_file in routers_path.rglob("*.py"):
        if py_file.name.startswith("__"):
            continue

        report.files_scanned += 1

        try:
            with open(py_file) as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            # Check 'import database' or 'import app.database'
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "database" or alias.name.startswith("database."):
                        report.add(
                            Violation(
                                principle="Service Layer Architecture",
                                severity="high",
                                file_path=str(py_file.relative_to(get_project_root())),
                                line_number=node.lineno,
                                function_name=None,
                                description="Router imports directly from database layer",
                                evidence=f"import {alias.name}",
                                suggested_fix=(
                                    "Import from services layer instead: "
                                    "from services import module_name"
                                ),
                            )
                        )
                    if alias.name.startswith("app.database"):
                        report.add(
                            Violation(
                                principle="Service Layer Architecture",
                                severity="high",
                                file_path=str(py_file.relative_to(get_project_root())),
                                line_number=node.lineno,
                                function_name=None,
                                description="Router imports directly from database layer",
                                evidence=f"import {alias.name}",
                                suggested_fix="Import from services layer instead",
                            )
                        )

            # Check 'from database import ...' or 'from app.database import ...'
            if isinstance(node, ast.ImportFrom):
                if node.module and (
                    node.module == "database"
                    or node.module.startswith("database.")
                    or node.module.startswith("app.database")
                ):
                    names = ", ".join(alias.name for alias in node.names)
                    report.add(
                        Violation(
                            principle="Service Layer Architecture",
                            severity="high",
                            file_path=str(py_file.relative_to(get_project_root())),
                            line_number=node.lineno,
                            function_name=None,
                            description="Router imports directly from database layer",
                            evidence=f"from {node.module} import {names}",
                            suggested_fix=(
                                "Call service layer functions instead of "
                                "database functions directly"
                            ),
                        )
                    )


# =============================================================================
# Principle 2: Activity Tracking & Event Logging
# =============================================================================


class ServiceFunctionVisitor(ast.NodeVisitor):
    """AST visitor that analyzes service functions for activity/event logging."""

    def __init__(self, source_lines: list[str], file_path: Path, report: ComplianceReport):
        self.source_lines = source_lines
        self.file_path = file_path
        self.report = report
        self.current_function: str | None = None
        self.current_function_node: ast.FunctionDef | None = None
        self.has_requesting_user = False
        self.has_track_activity = False
        self.has_log_event = False
        self.has_mutation = False
        self.mutation_evidence: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        # Skip private functions (but not _require_admin etc which are helpers)
        if node.name.startswith("__"):
            self.generic_visit(node)
            return

        # Reset state for this function
        self.current_function = node.name
        self.current_function_node = node
        self.has_requesting_user = False
        self.has_track_activity = False
        self.has_log_event = False
        self.has_mutation = False
        self.mutation_evidence = []

        self.report.functions_analyzed += 1

        # Check if function has RequestingUser parameter
        for arg in node.args.args:
            if arg.arg == "requesting_user":
                self.has_requesting_user = True
                break

            # Also check type annotation
            if arg.annotation:
                ann_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                if "RequestingUser" in ann_str:
                    self.has_requesting_user = True
                    break

        if not self.has_requesting_user:
            self.generic_visit(node)
            return

        # Visit function body to check for track_activity, log_event, and mutations
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self._check_call(child)

        # Report violations
        if self.has_requesting_user:
            if self.has_mutation and not self.has_log_event:
                # Write operation without log_event - HIGH severity
                self.report.add(
                    Violation(
                        principle="Activity/Event Logging",
                        severity="high",
                        file_path=str(self.file_path.relative_to(get_project_root())),
                        line_number=node.lineno,
                        function_name=node.name,
                        description="Service function performs mutation without log_event()",
                        evidence="; ".join(self.mutation_evidence[:3]),  # First 3 mutations
                        suggested_fix=(
                            "Add log_event() call after successful mutation:\n"
                            "log_event(\n"
                            '    tenant_id=requesting_user["tenant_id"],\n'
                            '    actor_user_id=requesting_user["id"],\n'
                            '    artifact_type="...",\n'
                            "    artifact_id=...,\n"
                            '    event_type="..._created|updated|deleted",\n'
                            ")"
                        ),
                    )
                )
            elif not self.has_mutation and not self.has_track_activity and not self.has_log_event:
                # Read operation without track_activity - MEDIUM severity
                # Skip if function name suggests it's a helper
                if not node.name.startswith("_"):
                    self.report.add(
                        Violation(
                            principle="Activity/Event Logging",
                            severity="medium",
                            file_path=str(self.file_path.relative_to(get_project_root())),
                            line_number=node.lineno,
                            function_name=node.name,
                            description=(
                                "Service function with RequestingUser " "missing track_activity()"
                            ),
                            evidence=(
                                f"Function {node.name} has RequestingUser " "but no tracking call"
                            ),
                            suggested_fix=(
                                "Add track_activity() at function start:\n"
                                "track_activity(requesting_user['tenant_id'], "
                                "requesting_user['id'])"
                            ),
                        )
                    )

        self.generic_visit(node)

    def _check_call(self, node: ast.Call) -> None:
        """Check a function call for activity tracking, logging, or mutations."""
        func_name = self._get_call_name(node)

        if func_name == "track_activity":
            self.has_track_activity = True

        if func_name == "log_event":
            self.has_log_event = True

        # Check for mutations (database.*.create_*, update_*, delete_*, set_*)
        if func_name:
            # Pattern: database.module.create_*, database.module.update_*, etc.
            mutation_patterns = [
                r"database\.\w+\.create_",
                r"database\.\w+\.update_",
                r"database\.\w+\.delete_",
                r"database\.\w+\.set_",
                r"database\.\w+\.add_",
                r"database\.\w+\.remove_",
                r"database\.\w+\.clear_",
                r"database\.\w+\.revoke_",
                r"database\.\w+\.upsert_",
                r"database\.\w+\.anonymize_",
                r"database\.\w+\.inactivate_",
                r"database\.\w+\.reactivate_",
            ]
            for pattern in mutation_patterns:
                if re.match(pattern, func_name):
                    self.has_mutation = True
                    self.mutation_evidence.append(func_name)
                    break

    def _get_call_name(self, node: ast.Call) -> str | None:
        """Get the full name of a function call (e.g., 'database.users.create_user')."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None


def check_activity_logging_violations(report: ComplianceReport) -> None:
    """
    Check that service functions properly call track_activity() or log_event().

    Rules:
    - Functions with RequestingUser parameter that perform reads: must call track_activity()
    - Functions with RequestingUser parameter that perform writes: must call log_event()
    """
    services_path = get_app_path() / "services"

    if not services_path.exists():
        return

    # Skip these files (they're infrastructure, not business logic)
    skip_files = {"__init__.py", "activity.py", "event_log.py", "exceptions.py", "types.py"}

    for py_file in services_path.glob("*.py"):
        if py_file.name in skip_files:
            continue

        report.files_scanned += 1

        try:
            with open(py_file) as f:
                source = f.read()
            source_lines = source.splitlines()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        visitor = ServiceFunctionVisitor(source_lines, py_file, report)
        visitor.visit(tree)


# =============================================================================
# Principle 3: Tenant Isolation
# =============================================================================


class TenantIsolationVisitor(ast.NodeVisitor):
    """
    AST visitor that checks database functions for tenant isolation.

    This codebase uses Row-Level Security (RLS) at the connection level,
    where tenant_id is passed to wrapper functions (fetchall, fetchone, execute).

    Functions can explicitly use UNSCOPED to indicate intentional cross-tenant access.

    We check:
    1. Database functions that don't take tenant_id as a parameter
    2. Functions that don't use tenant scoping BUT also don't use UNSCOPED marker
    """

    def __init__(self, file_path: Path, report: ComplianceReport):
        self.file_path = file_path
        self.report = report
        # Wrapper functions that handle RLS scoping
        self.rls_wrappers = {"fetchall", "fetchone", "execute", "fetchval"}
        # Functions that intentionally bypass RLS (documented cross-tenant operations)
        self.skip_functions = {"delete_old_debug_entries"}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        # Skip private/dunder functions
        if node.name.startswith("_"):
            self.generic_visit(node)
            return

        # Skip functions that are documented as intentionally cross-tenant
        if node.name in self.skip_functions:
            self.generic_visit(node)
            return

        # Check if this is a public database function
        # It should have tenant_id as a parameter OR use UNSCOPED explicitly
        if node.args.args:
            # Check if tenant_id appears anywhere in parameters
            has_tenant_arg = any(arg.arg in ("tenant_id", "tenant") for arg in node.args.args)

            if not has_tenant_arg:
                # Check if function body contains SQL operations
                has_sql_ops = False
                uses_unscoped = False

                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        func_name = self._get_simple_name(child.func)
                        if func_name in self.rls_wrappers:
                            has_sql_ops = True
                            # Check if first argument is UNSCOPED
                            if child.args and isinstance(child.args[0], ast.Name):
                                if child.args[0].id == "UNSCOPED":
                                    uses_unscoped = True

                # Only report if it has SQL ops but doesn't use UNSCOPED
                # (UNSCOPED indicates intentional cross-tenant access)
                if has_sql_ops and not uses_unscoped:
                    self.report.add(
                        Violation(
                            principle="Tenant Isolation",
                            severity="high",
                            file_path=str(self.file_path.relative_to(get_project_root())),
                            line_number=node.lineno,
                            function_name=node.name,
                            description="Database function missing tenant_id parameter",
                            evidence=(
                                f"Function {node.name} performs SQL operations "
                                "but has no tenant_id parameter"
                            ),
                            suggested_fix=(
                                "Add tenant_id as the first parameter to ensure "
                                "RLS scoping, or use UNSCOPED if cross-tenant "
                                "access is intentional"
                            ),
                        )
                    )

        self.generic_visit(node)

    def _get_simple_name(self, node: ast.expr) -> str | None:
        """Get simple function name from a call."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None


def check_tenant_isolation_violations(report: ComplianceReport) -> None:
    """
    Check that database functions properly scope to tenant_id.

    This codebase uses Row-Level Security (RLS) where:
    - Database wrapper functions (fetchall, fetchone, execute) take tenant_id
    - The tenant_id is used to set RLS context at the connection level
    - SQL queries don't need explicit tenant_id in WHERE clauses

    We check that:
    1. Public database functions have tenant_id as a parameter
    2. No raw SQL execution bypasses the RLS wrappers
    """
    database_path = get_app_path() / "database"

    if not database_path.exists():
        return

    # Skip infrastructure files
    skip_files = {"__init__.py", "connection.py", "utils.py"}

    for py_file in database_path.glob("*.py"):
        if py_file.name in skip_files:
            continue

        report.files_scanned += 1

        try:
            with open(py_file) as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        visitor = TenantIsolationVisitor(py_file, report)
        visitor.visit(tree)


# =============================================================================
# Principle 4: API-First Methodology
# =============================================================================


def check_api_first_violations(report: ComplianceReport) -> None:
    """
    Check that service operations have corresponding API endpoints.

    This is a comparison check:
    1. Extract public functions from service modules
    2. Extract API endpoints from api/v1 routers
    3. Flag service operations without API coverage
    """
    services_path = get_app_path() / "services"
    api_path = get_app_path() / "routers" / "api" / "v1"

    if not services_path.exists() or not api_path.exists():
        return

    # Skip infrastructure services
    skip_services = {
        "__init__.py",
        "activity.py",
        "event_log.py",
        "exceptions.py",
        "types.py",
        "bg_tasks.py",
    }

    # Services whose API endpoints are consolidated in another router
    # e.g., mfa and emails are exposed via /api/v1/users/me/mfa/* and /api/v1/users/me/emails/*
    service_to_api_router = {
        "mfa": "users",
        "emails": "users",
    }

    # Collect service functions
    service_functions: dict[str, list[str]] = {}  # module -> [functions]

    for py_file in services_path.glob("*.py"):
        if py_file.name in skip_services:
            continue

        module_name = py_file.stem

        try:
            with open(py_file) as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        functions = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Skip private functions
                if node.name.startswith("_"):
                    continue
                # Check if it has RequestingUser (indicates it's a business operation)
                has_requesting_user = any(arg.arg == "requesting_user" for arg in node.args.args)
                if has_requesting_user:
                    functions.append(node.name)

        if functions:
            service_functions[module_name] = functions

    # Collect API endpoints
    api_endpoints: set[str] = set()

    for py_file in api_path.glob("*.py"):
        if py_file.name.startswith("__"):
            continue

        try:
            with open(py_file) as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Look for route decorators
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call):
                        if isinstance(decorator.func, ast.Attribute):
                            if decorator.func.attr in ("get", "post", "put", "patch", "delete"):
                                api_endpoints.add(node.name)
                    elif isinstance(decorator, ast.Attribute):
                        if decorator.attr in ("get", "post", "put", "patch", "delete"):
                            api_endpoints.add(node.name)

    # Compare and report missing API coverage
    # This is a heuristic - we can't perfectly match service functions to API endpoints
    # We'll report service modules that seem to have no API coverage

    for module, functions in service_functions.items():
        # Check if this service maps to a different API router
        mapped_router = service_to_api_router.get(module, module)
        api_router_file = api_path / f"{mapped_router}.py"
        if not api_router_file.exists():
            # Check if there's a similar file (e.g., singular vs plural)
            found_similar = False
            for api_file in api_path.glob("*.py"):
                if module in api_file.stem or api_file.stem in module:
                    found_similar = True
                    break

            if not found_similar and len(functions) > 0:
                func_list = ", ".join(functions[:5])
                if len(functions) > 5:
                    func_list += "..."
                report.add(
                    Violation(
                        principle="API-First Methodology",
                        severity="medium",
                        file_path=f"app/services/{module}.py",
                        line_number=1,
                        function_name=None,
                        description=f"Service module '{module}' has no corresponding API router",
                        evidence=f"Service functions: {func_list}",
                        suggested_fix=(
                            f"Create app/routers/api/v1/{module}.py with "
                            "RESTful endpoints for these operations"
                        ),
                    )
                )


# =============================================================================
# Principle 5: Authorization Pattern Verification
# =============================================================================


def check_authorization_violations(report: ComplianceReport) -> None:
    """
    Check that web routes have proper auth dependencies matching pages.py permissions.

    This verifies:
    1. Each web router has router-level auth dependencies
    2. Auth level matches the pages.py permission for routes it serves

    Permission mapping:
    - PagePermission.PUBLIC → no auth required
    - PagePermission.AUTHENTICATED → require_current_user
    - PagePermission.ADMIN → require_admin
    - PagePermission.SUPER_ADMIN → require_super_admin

    Note: Routers that use has_page_access() at route level are considered compliant
    since they implement defense-in-depth (router-level baseline + route-level checks).
    """
    routers_path = get_app_path() / "routers"
    pages_path = get_app_path() / "pages.py"

    if not routers_path.exists() or not pages_path.exists():
        return

    # Parse pages.py to extract paths and permissions
    page_permissions = _extract_page_permissions(pages_path)
    if not page_permissions:
        return

    # Define auth level hierarchy (higher number = more restrictive)
    auth_levels = {
        "public": 0,
        "require_current_user": 1,
        "require_admin": 2,
        "require_super_admin": 3,
    }

    # Map page permissions to required auth
    permission_to_auth = {
        "PUBLIC": "public",
        "AUTHENTICATED": "require_current_user",
        "ADMIN": "require_admin",
        "SUPER_ADMIN": "require_super_admin",
    }

    # First pass: collect all router prefixes to handle nested routers
    all_prefixes: set[str] = set()
    for py_file in routers_path.glob("*.py"):
        if py_file.name.startswith("__"):
            continue
        try:
            with open(py_file) as f:
                source = f.read()
            tree = ast.parse(source)
            router_info = _extract_router_info(tree, source)
            if router_info and router_info["prefix"]:
                all_prefixes.add(router_info["prefix"])
        except (SyntaxError, UnicodeDecodeError):
            continue

    # Scan web routers (exclude api/ subdirectory)
    for py_file in routers_path.glob("*.py"):
        if py_file.name.startswith("__"):
            continue

        report.files_scanned += 1

        try:
            with open(py_file) as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        # Check if router uses route-level permission checks
        # Valid patterns for defense-in-depth:
        # 1. has_page_access() calls to check permissions dynamically
        # 2. dependencies=[Depends(require_*)] on individual routes
        uses_route_level_checks = (
            "has_page_access" in source
            or "dependencies=[Depends(require_super_admin)]" in source
            or "dependencies=[Depends(require_admin)]" in source
        )

        # Extract router configuration
        router_info = _extract_router_info(tree, source)
        if not router_info:
            continue

        prefix = router_info["prefix"]
        router_auth = router_info["auth_dependency"]

        # Find more specific prefixes that handle nested routes
        more_specific_prefixes = [
            p for p in all_prefixes if p != prefix and p.startswith(prefix + "/")
        ]

        # Find the most restrictive permission required for any page under this prefix
        max_required_auth = "public"
        min_required_auth = "require_super_admin"  # Start with most restrictive
        matching_pages = []

        for page_path, permission in page_permissions.items():
            # Check if this page is under the router's prefix
            if page_path == prefix or page_path.startswith(prefix + "/"):
                # Skip pages that are handled by a more specific router
                handled_by_nested = any(
                    page_path == nested_prefix or page_path.startswith(nested_prefix + "/")
                    for nested_prefix in more_specific_prefixes
                )
                if handled_by_nested:
                    continue

                matching_pages.append((page_path, permission))
                required_auth = permission_to_auth.get(permission, "public")

                # Track max required auth (highest permission in this router's pages)
                if auth_levels.get(required_auth, 0) > auth_levels.get(max_required_auth, 0):
                    max_required_auth = required_auth

                # Track min required auth (lowest permission in this router's pages)
                if auth_levels.get(required_auth, 0) < auth_levels.get(min_required_auth, 0):
                    min_required_auth = required_auth

        if not matching_pages:
            # Router has no matching pages - might be API or special purpose
            continue

        # Check if router auth is sufficient
        if router_auth is None and max_required_auth != "public":
            # Router has no auth but serves protected pages
            report.add(
                Violation(
                    principle="Authorization",
                    severity="high",
                    file_path=str(py_file.relative_to(get_project_root())),
                    line_number=1,
                    function_name=None,
                    description=(
                        f"Router '{prefix}' has no auth dependency but serves protected pages"
                    ),
                    evidence=(
                        f"Pages requiring auth: "
                        f"{[p[0] for p in matching_pages if p[1] != 'PUBLIC'][:3]}"
                    ),
                    suggested_fix=(
                        f"Add dependencies=[Depends({max_required_auth})] to APIRouter"
                    ),
                )
            )
        elif router_auth is not None:
            router_auth_level = auth_levels.get(router_auth, 0)
            min_required_level = auth_levels.get(min_required_auth, 0)

            # Router auth should at least meet the minimum permission level
            # If router uses has_page_access(), it handles mixed permission levels at route level
            if router_auth_level < min_required_level:
                # Router auth doesn't even meet the minimum required
                report.add(
                    Violation(
                        principle="Authorization",
                        severity="high",
                        file_path=str(py_file.relative_to(get_project_root())),
                        line_number=1,
                        function_name=None,
                        description=f"Router '{prefix}' has insufficient auth level",
                        evidence=(
                            f"Router uses {router_auth} but minimum required is "
                            f"{min_required_auth}"
                        ),
                        suggested_fix=(
                            f"Change router dependency to Depends({min_required_auth})"
                        ),
                    )
                )
            elif not uses_route_level_checks:
                # Router doesn't use route-level checks and has mixed permission pages
                required_level = auth_levels.get(max_required_auth, 0)
                if router_auth_level < required_level:
                    # Router has pages requiring higher auth but no route-level checks
                    higher_perm_pages = [
                        p[0]
                        for p in matching_pages
                        if auth_levels.get(permission_to_auth.get(p[1], "public"), 0)
                        > router_auth_level
                    ]
                    if higher_perm_pages:
                        report.add(
                            Violation(
                                principle="Authorization",
                                severity="high",
                                file_path=str(py_file.relative_to(get_project_root())),
                                line_number=1,
                                function_name=None,
                                description=(
                                    f"Router '{prefix}' serves pages requiring higher auth "
                                    "without route-level checks"
                                ),
                                evidence=(
                                    f"Pages needing higher auth: {higher_perm_pages[:3]}, "
                                    f"router uses {router_auth}"
                                ),
                                suggested_fix=(
                                    "Add has_page_access() checks to routes serving these pages, "
                                    f"or change router dependency to Depends({max_required_auth})"
                                ),
                            )
                        )


def _extract_page_permissions(pages_path: Path) -> dict[str, str]:
    """Extract page paths and their permissions from pages.py."""
    try:
        with open(pages_path) as f:
            source = f.read()
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return {}

    permissions: dict[str, str] = {}

    # Find the PAGES list assignment
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "PAGES":
                    # Extract pages from the list
                    if isinstance(node.value, ast.List):
                        _extract_pages_from_list(node.value, permissions)

    return permissions


def _extract_pages_from_list(list_node: ast.List, permissions: dict[str, str]) -> None:
    """Recursively extract page paths and permissions from a list of Page() calls."""
    for element in list_node.elts:
        if isinstance(element, ast.Call):
            path = None
            permission = None
            children = None

            for keyword in element.keywords:
                if keyword.arg == "path" and isinstance(keyword.value, ast.Constant):
                    path = keyword.value.value
                elif keyword.arg == "permission" and isinstance(keyword.value, ast.Attribute):
                    permission = keyword.value.attr
                elif keyword.arg == "children" and isinstance(keyword.value, ast.List):
                    children = keyword.value

            if path and permission:
                permissions[path] = permission

            if children:
                _extract_pages_from_list(children, permissions)


def _extract_router_info(tree: ast.Module, source: str) -> dict | None:
    """Extract router prefix and auth dependencies from a router file."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "router":
                    if isinstance(node.value, ast.Call):
                        return _parse_api_router_call(node.value)
    return None


def _parse_api_router_call(call_node: ast.Call) -> dict | None:
    """Parse an APIRouter() call to extract prefix and dependencies."""
    result = {"prefix": "", "auth_dependency": None}

    for keyword in call_node.keywords:
        if keyword.arg == "prefix" and isinstance(keyword.value, ast.Constant):
            result["prefix"] = keyword.value.value

        elif keyword.arg == "dependencies" and isinstance(keyword.value, ast.List):
            # Look for Depends(require_*) in the dependencies list
            for dep in keyword.value.elts:
                if isinstance(dep, ast.Call):
                    # Check if it's Depends(require_*)
                    if isinstance(dep.func, ast.Name) and dep.func.id == "Depends":
                        if dep.args and isinstance(dep.args[0], ast.Name):
                            auth_func = dep.args[0].id
                            if auth_func in (
                                "require_current_user",
                                "require_admin",
                                "require_super_admin",
                            ):
                                result["auth_dependency"] = auth_func

    return result if result["prefix"] else None


# =============================================================================
# Main Entry Point
# =============================================================================


def run_compliance_check(
    principles: list[str] | None = None,
    output_json: bool = False,
) -> ComplianceReport:
    """
    Run compliance checks on the codebase.

    Args:
        principles: List of principles to check, or None for all.
                   Options: 'architecture', 'activity', 'tenant', 'api-first', 'authorization'
        output_json: If True, print JSON output. Otherwise, human-readable.

    Returns:
        ComplianceReport with all violations found.
    """
    report = ComplianceReport()

    all_principles = ["architecture", "activity", "tenant", "api-first", "authorization"]
    if principles is None:
        principles = all_principles

    if "architecture" in principles:
        check_architecture_violations(report)

    if "activity" in principles:
        check_activity_logging_violations(report)

    if "tenant" in principles:
        check_tenant_isolation_violations(report)

    if "api-first" in principles:
        check_api_first_violations(report)

    if "authorization" in principles:
        check_authorization_violations(report)

    return report


def format_report_text(report: ComplianceReport) -> str:
    """Format the compliance report as human-readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append("COMPLIANCE CHECK REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Files scanned: {report.files_scanned}")
    lines.append(f"Functions analyzed: {report.functions_analyzed}")
    lines.append(f"Total violations: {len(report.violations)}")
    lines.append("")

    # Group by principle
    by_principle: dict[str, list[Violation]] = {}
    for v in report.violations:
        by_principle.setdefault(v.principle, []).append(v)

    if not report.violations:
        lines.append("No violations found.")
    else:
        for principle, violations in by_principle.items():
            lines.append("-" * 70)
            lines.append(f"PRINCIPLE: {principle}")
            lines.append(f"Violations: {len(violations)}")
            lines.append("-" * 70)
            lines.append("")

            for v in violations:
                lines.append(f"  [{v.severity.upper()}] {v.file_path}:{v.line_number}")
                if v.function_name:
                    lines.append(f"  Function: {v.function_name}")
                lines.append(f"  Description: {v.description}")
                lines.append(f"  Evidence: {v.evidence}")
                lines.append(f"  Fix: {v.suggested_fix}")
                lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def main() -> int:
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description="Run compliance checks on the codebase",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--check",
        choices=["architecture", "activity", "tenant", "api-first", "authorization", "all"],
        default="all",
        help="Which principle to check (default: all)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    principles = None if args.check == "all" else [args.check]
    report = run_compliance_check(principles=principles, output_json=args.json)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report_text(report))

    # Return exit code based on high-severity violations
    high_severity = len([v for v in report.violations if v.severity == "high"])
    return 1 if high_severity > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
