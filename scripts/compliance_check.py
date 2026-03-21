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
    4. api-first      - Service operations should have corresponding API endpoints,
                        and PATCH/PUT docstrings should document all accepted fields
    5. authorization  - Web routes have proper auth dependencies matching pages.py
    6. input-length   - All str fields in Pydantic input schemas must have max_length
    7. sql-length     - All TEXT/CITEXT columns in SQL schema must have length CHECK
                        constraints
    8. rls             - RLS policies must have USING + WITH CHECK, use
                        current_setting(..., true), and exist for all
                        RLS-enabled tables
    9. migration-safety - Migrations must be backwards compatible (no DROP
                        COLUMN/TABLE, RENAME, type changes, etc.)
   10. template-links  - Template href/action attributes must match registered
                        routes (catches dead links at CI time)
   11. outbound-timeouts - Outbound HTTP/network calls must have explicit
                        timeouts to prevent indefinite hangs

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

        # Check if docstring documents delegated logging (e.g. "Logs: event_name")
        # This indicates the function delegates logging to a helper function
        docstring = ast.get_docstring(node) or ""
        has_delegated_logging = "Logs:" in docstring
        # Check if docstring explicitly opts out of audit logging (e.g. "No audit: reason")
        # Use this for writes that are UI preference state, not business actions.
        has_no_audit = "No audit:" in docstring

        # Report violations
        if self.has_requesting_user:
            if self.has_mutation and not self.has_log_event and not has_delegated_logging and not has_no_audit:
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
            elif (
                not self.has_mutation
                and not self.has_track_activity
                and not self.has_log_event
                and not has_delegated_logging
            ):
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
                                "Service function with RequestingUser missing track_activity()"
                            ),
                            evidence=(
                                f"Function {node.name} has RequestingUser but no tracking call"
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

    for py_file in services_path.rglob("*.py"):
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
    skip_files = {"__init__.py", "connection.py", "utils.py", "_core.py"}

    for py_file in database_path.rglob("*.py"):
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
        api_router_pkg = api_path / mapped_router / "__init__.py"
        if not api_router_file.exists() and not api_router_pkg.exists():
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


def check_api_doc_violations(report: ComplianceReport) -> None:
    """
    Check that API PATCH/PUT endpoint docstrings document all accepted fields.

    For each PATCH/PUT endpoint that accepts a Pydantic schema parameter,
    verify that the docstring mentions every field defined in that schema.
    """
    api_path = get_app_path() / "routers" / "api" / "v1"
    schemas_path = get_app_path() / "schemas"

    if not api_path.exists() or not schemas_path.exists():
        return

    # Collect all schema classes and their fields from app/schemas/
    schema_fields: dict[str, list[str]] = {}  # ClassName -> [field_names]

    for py_file in _iter_python_files(schemas_path):
        try:
            with open(py_file) as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                fields = []
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(
                        item.target, ast.Name
                    ):
                        # Skip class-level config or private attrs
                        if not item.target.id.startswith("_"):
                            fields.append(item.target.id)
                if fields:
                    schema_fields[node.name] = fields

    # Scan API routers for PATCH/PUT endpoints
    for py_file in _iter_python_files(api_path):
        try:
            with open(py_file) as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        report.files_scanned += 1

        # Collect imports to resolve schema names
        imported_names: dict[str, str] = {}  # local_name -> original_name
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    local = alias.asname if alias.asname else alias.name
                    imported_names[local] = alias.name

        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            # Check if this function has a PATCH or PUT decorator
            is_patch_or_put = False
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Call) and isinstance(
                    decorator.func, ast.Attribute
                ):
                    if decorator.func.attr in ("patch", "put"):
                        is_patch_or_put = True
                        break
                elif isinstance(decorator, ast.Attribute):
                    if decorator.attr in ("patch", "put"):
                        is_patch_or_put = True
                        break

            if not is_patch_or_put:
                continue

            # Find the schema parameter (non-builtin type annotation
            # that matches a known schema class)
            schema_name = None
            for arg in node.args.args:
                if arg.annotation is None:
                    continue
                ann_name = None
                if isinstance(arg.annotation, ast.Name):
                    ann_name = arg.annotation.id
                elif isinstance(arg.annotation, ast.Attribute):
                    ann_name = arg.annotation.attr

                if ann_name:
                    # Resolve to original name if aliased
                    original = imported_names.get(ann_name, ann_name)
                    if original in schema_fields:
                        schema_name = original
                        break

            if not schema_name:
                continue

            # Get the docstring
            docstring = ast.get_docstring(node) or ""

            # Check which fields are mentioned in the docstring
            fields = schema_fields[schema_name]
            missing_fields = []
            for field_name in fields:
                # Check for the field name in the docstring (case-insensitive,
                # allow underscore-to-space or underscore-to-hyphen variants)
                variants = [
                    field_name,
                    field_name.replace("_", " "),
                    field_name.replace("_", "-"),
                ]
                found = any(v.lower() in docstring.lower() for v in variants)
                if not found:
                    missing_fields.append(field_name)

            if missing_fields:
                rel_path = str(py_file.relative_to(get_project_root()))
                report.add(
                    Violation(
                        principle="API-First Methodology",
                        severity="medium",
                        file_path=rel_path,
                        line_number=node.lineno,
                        function_name=node.name,
                        description=(
                            f"PATCH/PUT endpoint docstring missing {len(missing_fields)} "
                            f"of {len(fields)} fields from {schema_name}"
                        ),
                        evidence=f"Missing: {', '.join(missing_fields)}",
                        suggested_fix=(
                            f"Update the docstring to document all fields: "
                            f"{', '.join(fields)}"
                        ),
                    )
                )


def _iter_python_files(directory: Path):
    """Yield all .py files in a directory tree."""
    for py_file in directory.rglob("*.py"):
        if py_file.name.startswith("__"):
            continue
        yield py_file


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
                    suggested_fix=(f"Add dependencies=[Depends({max_required_auth})] to APIRouter"),
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
                            f"Router uses {router_auth} but minimum required is {min_required_auth}"
                        ),
                        suggested_fix=(f"Change router dependency to Depends({min_required_auth})"),
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
# Principle 6: Input Length Validation
# =============================================================================

# Schema class name patterns that indicate input schemas (vs response schemas)
INPUT_SCHEMA_PATTERNS = re.compile(
    r"(Create|Update|Import|Request|Add|Remove|Assign|Establish|Reimport|Save|Verify|Form|Params)$"
)


def check_input_length_violations(report: ComplianceReport) -> None:
    """
    Check that all str fields in Pydantic input schemas have max_length.

    Scans app/schemas/*.py and app/routers/**/*.py for BaseModel subclasses
    whose names match input schema patterns, then checks each str or
    str | None field for max_length in Field() metadata.
    """
    app_path = get_app_path()

    # Collect Python files from schemas/ and routers/ (inline models)
    py_files: list[Path] = []
    schemas_path = app_path / "schemas"
    routers_path = app_path / "routers"
    if schemas_path.exists():
        py_files.extend(schemas_path.glob("*.py"))
    if routers_path.exists():
        py_files.extend(routers_path.rglob("*.py"))

    for py_file in py_files:
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
            if not isinstance(node, ast.ClassDef):
                continue

            # Check if this is a BaseModel subclass
            is_basemodel = any(
                (isinstance(base, ast.Name) and base.id == "BaseModel")
                or (isinstance(base, ast.Attribute) and base.attr == "BaseModel")
                for base in node.bases
            )
            if not is_basemodel:
                continue

            # Check if name matches input schema patterns
            if not INPUT_SCHEMA_PATTERNS.search(node.name):
                continue

            # Skip response schemas that have from_attributes=True
            if _has_from_attributes(node):
                continue

            # Check each field annotation for str types missing max_length
            for item in node.body:
                if not isinstance(item, ast.AnnAssign) or not isinstance(item.target, ast.Name):
                    continue

                field_name = item.target.id
                annotation = item.annotation

                if not _is_str_annotation(annotation):
                    continue

                # Check if Field() call has max_length
                if item.value and _has_max_length(item.value):
                    continue

                report.add(
                    Violation(
                        principle="Input Length Validation",
                        severity="high",
                        file_path=str(py_file.relative_to(get_project_root())),
                        line_number=item.lineno,
                        function_name=None,
                        description=(
                            f"Input schema {node.name}.{field_name} missing max_length constraint"
                        ),
                        evidence=f"Field '{field_name}' is str without max_length",
                        suggested_fix=(
                            f"Add max_length to Field(): "
                            f"{field_name}: str = Field(..., max_length=N)"
                        ),
                    )
                )


def _has_from_attributes(class_node: ast.ClassDef) -> bool:
    """Check if a class has model_config with from_attributes=True (response schema)."""
    for item in class_node.body:
        # model_config = ConfigDict(from_attributes=True)
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name) and target.id == "model_config":
                    source = ast.unparse(item.value) if hasattr(ast, "unparse") else ""
                    if "from_attributes" in source:
                        return True
    return False


def _is_str_annotation(annotation: ast.expr) -> bool:
    """Check if an annotation represents a str or str | None type."""
    if isinstance(annotation, ast.Name) and annotation.id == "str":
        return True

    # str | None (BinOp with | operator)
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _is_str_annotation(annotation.left) or _is_str_annotation(annotation.right)

    # Optional[str] or Annotated[str, ...]
    if isinstance(annotation, ast.Subscript):
        if isinstance(annotation.value, ast.Name):
            if annotation.value.id in ("Optional", "Annotated"):
                # For Annotated, we trust that the annotation itself has max_length
                if annotation.value.id == "Annotated":
                    return False
                if isinstance(annotation.slice, ast.Name) and annotation.slice.id == "str":
                    return True
                if isinstance(annotation.slice, ast.Tuple) and annotation.slice.elts:
                    first = annotation.slice.elts[0]
                    if isinstance(first, ast.Name) and first.id == "str":
                        return True
        return False

    return False


def _has_max_length(value: ast.expr) -> bool:
    """Check if a Field() call includes max_length."""
    if not isinstance(value, ast.Call):
        return False

    # Check if it's a Field() call
    func = value.func
    is_field = (isinstance(func, ast.Name) and func.id == "Field") or (
        isinstance(func, ast.Attribute) and func.attr == "Field"
    )

    if not is_field:
        return False

    # Check keyword arguments for max_length
    for kw in value.keywords:
        if kw.arg == "max_length":
            return True

    return False


# =============================================================================
# Principle 7: SQL Column Length Validation
# =============================================================================

# Tables exempt from length checks (infrastructure/system tables)
SQL_EXEMPT_TABLES = {"schema_migration_log"}

# Regex to match TEXT/CITEXT column definitions (not arrays like text[])
SQL_COL_PATTERN = re.compile(
    r"^\s+(\w+)\s+(?:public\.)?(?:text|citext)(?!\[)\b",
    re.IGNORECASE,
)

# Regex to match length/char_length CHECK constraints
SQL_LENGTH_CHECK = re.compile(
    r"(?:length|char_length)\((\w+)\)\s*<=",
    re.IGNORECASE,
)

# Regex to match enum-like CHECK constraints (col = ANY (ARRAY[...]))
SQL_ENUM_CHECK = re.compile(
    r"\b(\w+)\s*=\s*ANY\s*\(",
    re.IGNORECASE,
)


def _collect_migration_constraints(migrations_dir: Path) -> set[tuple[str, str]]:
    """Collect (table, column) pairs with length/enum constraints added in migrations.

    This allows the scanner to recognize that a column missing a CHECK in
    schema.sql has been fixed by a subsequent migration via ALTER TABLE.
    """
    covered: set[tuple[str, str]] = set()

    if not migrations_dir.exists():
        return covered

    # Match: ALTER TABLE [public.]table ADD CONSTRAINT name CHECK (...length(col)...)
    length_pattern = re.compile(
        r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
        r"ADD\s+CONSTRAINT\s+\w+\s+CHECK\s*\([^;]*?"
        r"(?:length|char_length)\((\w+)\)\s*<=",
        re.IGNORECASE | re.DOTALL,
    )
    enum_pattern = re.compile(
        r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
        r"ADD\s+CONSTRAINT\s+\w+\s+CHECK\s*\([^;]*?"
        r"\b(\w+)\s*=\s*ANY\s*\(",
        re.IGNORECASE | re.DOTALL,
    )

    for sql_file in sorted(migrations_dir.glob("*.sql")):
        with open(sql_file) as f:
            sql = f.read()

        for m in length_pattern.finditer(sql):
            covered.add((m.group(1), m.group(2)))
        for m in enum_pattern.finditer(sql):
            covered.add((m.group(1), m.group(2)))

    return covered


def check_sql_length_violations(report: ComplianceReport) -> None:
    """
    Check that TEXT/CITEXT columns in SQL schema have length CHECK constraints.

    Scans db-init/schema.sql and db-init/migrations/*.sql for:
    - CREATE TABLE with TEXT columns lacking length checks
    - ALTER TABLE ADD COLUMN with TEXT type lacking length checks

    Constraints added via ALTER TABLE ADD CONSTRAINT in migrations are
    recognized as covering columns defined in schema.sql.
    """
    project_root = get_project_root()
    migrations_dir = project_root / "db-init" / "migrations"

    # Collect constraints added by migrations (covers schema.sql gaps)
    migration_constraints = _collect_migration_constraints(migrations_dir)

    # Scan baseline schema
    schema_file = project_root / "db-init" / "schema.sql"
    if schema_file.exists():
        report.files_scanned += 1
        with open(schema_file) as f:
            sql = f.read()
        _check_sql_create_tables(sql, schema_file, report, migration_constraints)

    # Scan migrations (each must be self-contained, no cross-file resolution)
    if migrations_dir.exists():
        for sql_file in sorted(migrations_dir.glob("*.sql")):
            report.files_scanned += 1
            with open(sql_file) as f:
                sql = f.read()
            _check_sql_create_tables(sql, sql_file, report)
            _check_sql_alter_add_column(sql, sql_file, report)


def _check_sql_create_tables(
    sql: str,
    file_path: Path,
    report: ComplianceReport,
    migration_constraints: set[tuple[str, str]] | None = None,
) -> None:
    """Check CREATE TABLE blocks for TEXT columns without length constraints."""
    # Find CREATE TABLE blocks
    table_pattern = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?(\w+)\s*\((.*?)\);",
        re.DOTALL | re.IGNORECASE,
    )

    lines = sql.split("\n")

    for match in table_pattern.finditer(sql):
        table_name = match.group(1)
        table_body = match.group(2)

        if table_name in SQL_EXEMPT_TABLES:
            continue

        # Find all TEXT/CITEXT columns in this table
        text_columns: list[tuple[str, int]] = []  # (col_name, line_in_file)
        table_start_offset = sql[: match.start()].count("\n")

        for i, line in enumerate(table_body.split("\n")):
            col_match = SQL_COL_PATTERN.match(line)
            if col_match:
                col_name = col_match.group(1)
                file_line = table_start_offset + i + 1
                text_columns.append((col_name, file_line))

        if not text_columns:
            continue

        # Find all columns with length or enum CHECK constraints in this table
        checked_columns: set[str] = set()
        for length_match in SQL_LENGTH_CHECK.finditer(table_body):
            checked_columns.add(length_match.group(1))
        for enum_match in SQL_ENUM_CHECK.finditer(table_body):
            checked_columns.add(enum_match.group(1))

        # Report unchecked columns
        for col_name, line_num in text_columns:
            if col_name in checked_columns:
                continue
            # Check if a migration adds the constraint for this table.column
            if migration_constraints and (table_name, col_name) in migration_constraints:
                continue
            report.add(
                Violation(
                    principle="SQL Column Length Validation",
                    severity="medium",
                    file_path=str(file_path.relative_to(get_project_root())),
                    line_number=line_num,
                    function_name=None,
                    description=(
                        f"Table {table_name}.{col_name} (TEXT) has no length "
                        f"CHECK constraint"
                    ),
                    evidence=(
                        f"Column '{col_name}' in table '{table_name}' is TEXT "
                        f"without length() or enum CHECK"
                    ),
                    suggested_fix=(
                        f"Add: CONSTRAINT chk_{table_name}_{col_name}_length "
                        f"CHECK ((length({col_name}) <= N))"
                    ),
                )
            )


def _check_sql_alter_add_column(
    sql: str, file_path: Path, report: ComplianceReport
) -> None:
    """Check ALTER TABLE ADD COLUMN for TEXT columns without length constraints."""
    # Match: ALTER TABLE [public.]tablename ADD COLUMN [IF NOT EXISTS] colname text ...
    alter_pattern = re.compile(
        r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
        r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+"
        r"(?:public\.)?(?:text|citext)(?!\[)\b",
        re.IGNORECASE,
    )

    lines = sql.split("\n")

    # Collect all length/enum checks in the entire migration file
    file_checked: set[str] = set()
    for length_match in SQL_LENGTH_CHECK.finditer(sql):
        file_checked.add(length_match.group(1))
    for enum_match in SQL_ENUM_CHECK.finditer(sql):
        file_checked.add(enum_match.group(1))

    for match in alter_pattern.finditer(sql):
        table_name = match.group(1)
        col_name = match.group(2)
        line_num = sql[: match.start()].count("\n") + 1

        if table_name in SQL_EXEMPT_TABLES:
            continue

        if col_name not in file_checked:
            report.add(
                Violation(
                    principle="SQL Column Length Validation",
                    severity="medium",
                    file_path=str(file_path.relative_to(get_project_root())),
                    line_number=line_num,
                    function_name=None,
                    description=(
                        f"ALTER TABLE {table_name} adds TEXT column '{col_name}' "
                        f"without length CHECK"
                    ),
                    evidence=(
                        f"ADD COLUMN {col_name} TEXT without corresponding "
                        f"length constraint in migration"
                    ),
                    suggested_fix=(
                        f"Add CHECK constraint in same migration: "
                        f"ALTER TABLE {table_name} ADD CONSTRAINT "
                        f"chk_{table_name}_{col_name}_length "
                        f"CHECK ((length({col_name}) <= N))"
                    ),
                )
            )


# =============================================================================
# Principle 8: RLS Policy Consistency
# =============================================================================

# Tables with RLS enabled but intentionally no WITH CHECK clause.
# Each entry should have a comment explaining why.
RLS_NO_WITH_CHECK_EXEMPT = {
    "export_files",  # Worker inserts cross-tenant; USING has CASE for unscoped reads
}


def _collect_migration_rls_fixes(migrations_dir: Path) -> set[str]:
    """Collect table names whose RLS policies have been corrected by migrations.

    A migration is considered a fix when it contains a CREATE POLICY with both
    USING and WITH CHECK clauses and uses current_setting(..., true).
    """
    fixed: set[str] = set()

    if not migrations_dir.exists():
        return fixed

    fix_pattern = re.compile(
        r"CREATE\s+POLICY\s+\w+\s+ON\s+(?:public\.)?(\w+)\s+"
        r"(?=.*\bUSING\b)"
        r"(?=.*\bWITH\s+CHECK\b)"
        r"(?=.*current_setting\s*\([^)]*,\s*true\s*\))"
        r".*?;",
        re.DOTALL | re.IGNORECASE,
    )

    for sql_file in sorted(migrations_dir.glob("*.sql")):
        with open(sql_file) as f:
            sql = f.read()

        for m in fix_pattern.finditer(sql):
            fixed.add(m.group(1))

    return fixed


def check_rls_policy_violations(report: ComplianceReport) -> None:
    """
    Check that RLS policies are consistent and correct.

    For every table with ENABLE ROW LEVEL SECURITY, verifies:
    1. At least one CREATE POLICY exists
    2. The policy has both USING and WITH CHECK clauses (unless exempt)
    3. current_setting() uses the `true` parameter (return NULL instead of error)
    """
    schema_file = get_project_root() / "db-init" / "schema.sql"
    if not schema_file.exists():
        return

    report.files_scanned += 1

    migrations_dir = get_project_root() / "db-init" / "migrations"
    migration_rls_fixes = _collect_migration_rls_fixes(migrations_dir)

    with open(schema_file) as f:
        sql = f.read()

    lines = sql.split("\n")

    # 1. Find all tables with RLS enabled
    rls_enabled_pattern = re.compile(
        r"ALTER\s+TABLE\s+(?:public\.)?(\w+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
        re.IGNORECASE,
    )
    rls_tables: dict[str, int] = {}  # table_name -> line_number
    for match in rls_enabled_pattern.finditer(sql):
        table_name = match.group(1)
        line_num = sql[: match.start()].count("\n") + 1
        rls_tables[table_name] = line_num

    # 2. Find all CREATE POLICY statements and their properties
    # Use a multiline regex to capture the full policy block up to the semicolon
    policy_pattern = re.compile(
        r"CREATE\s+POLICY\s+(\w+)\s+ON\s+(?:public\.)?(\w+)\s*(.*?);",
        re.DOTALL | re.IGNORECASE,
    )

    policies_by_table: dict[str, list[dict[str, Any]]] = {}

    for match in policy_pattern.finditer(sql):
        policy_name = match.group(1)
        table_name = match.group(2)
        policy_body = match.group(3)
        line_num = sql[: match.start()].count("\n") + 1

        has_using = bool(re.search(r"\bUSING\b", policy_body, re.IGNORECASE))
        has_with_check = bool(re.search(r"\bWITH\s+CHECK\b", policy_body, re.IGNORECASE))
        has_true_param = bool(
            re.search(r"current_setting\s*\([^)]*,\s*true\s*\)", policy_body, re.IGNORECASE)
        )
        # Check for current_setting without the true parameter
        has_current_setting = bool(
            re.search(r"current_setting\s*\(", policy_body, re.IGNORECASE)
        )

        policies_by_table.setdefault(table_name, []).append(
            {
                "name": policy_name,
                "line": line_num,
                "has_using": has_using,
                "has_with_check": has_with_check,
                "has_true_param": has_true_param,
                "has_current_setting": has_current_setting,
            }
        )

    # 3. Check each RLS-enabled table
    for table_name, enable_line in rls_tables.items():
        table_policies = policies_by_table.get(table_name, [])

        if not table_policies:
            report.add(
                Violation(
                    principle="RLS Policy Consistency",
                    severity="high",
                    file_path="db-init/schema.sql",
                    line_number=enable_line,
                    function_name=None,
                    description=(
                        f"Table '{table_name}' has RLS enabled but no CREATE POLICY"
                    ),
                    evidence=f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY",
                    suggested_fix=(
                        f"Add a tenant isolation policy for '{table_name}'"
                    ),
                )
            )
            continue

        # Skip tables whose RLS has been corrected by a migration
        if table_name in migration_rls_fixes:
            continue

        for policy in table_policies:
            # Check for missing WITH CHECK (unless exempt)
            if (
                policy["has_using"]
                and not policy["has_with_check"]
                and table_name not in RLS_NO_WITH_CHECK_EXEMPT
            ):
                report.add(
                    Violation(
                        principle="RLS Policy Consistency",
                        severity="high",
                        file_path="db-init/schema.sql",
                        line_number=policy["line"],
                        function_name=None,
                        description=(
                            f"Policy '{policy['name']}' on '{table_name}' "
                            f"missing WITH CHECK clause"
                        ),
                        evidence=(
                            f"Policy has USING but no WITH CHECK, "
                            f"so INSERT/UPDATE bypass tenant scoping"
                        ),
                        suggested_fix=(
                            f"Add WITH CHECK clause matching the USING clause"
                        ),
                    )
                )

            # Check for current_setting without true parameter
            if policy["has_current_setting"] and not policy["has_true_param"]:
                report.add(
                    Violation(
                        principle="RLS Policy Consistency",
                        severity="high",
                        file_path="db-init/schema.sql",
                        line_number=policy["line"],
                        function_name=None,
                        description=(
                            f"Policy '{policy['name']}' on '{table_name}' uses "
                            f"current_setting() without true parameter"
                        ),
                        evidence=(
                            "current_setting('app.tenant_id'::text) raises ERROR "
                            "when unset; use current_setting('app.tenant_id'::text, true) "
                            "to return NULL instead"
                        ),
                        suggested_fix=(
                            "Change to current_setting('app.tenant_id'::text, true)"
                        ),
                    )
                )


# =============================================================================
# Principle 9: Migration Backwards Compatibility
# =============================================================================

# Operations that break a running application when applied to a live database.
# These patterns are detected via regex on migration SQL files.

# High severity: immediate breakage of running application code
_MIGRATION_HIGH_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
            r"DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?(\w+)",
            re.IGNORECASE,
        ),
        "DROP COLUMN on table '{0}' removes column '{1}' while running code may reference it",
        "Deploy code that stops referencing the column first, then drop in a later migration",
    ),
    (
        re.compile(
            r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:public\.)?(\w+)",
            re.IGNORECASE,
        ),
        "DROP TABLE removes '{0}' while running code may reference it",
        "Deploy code that stops referencing the table first, then drop in a later migration",
    ),
    (
        re.compile(
            r"\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
            r"RENAME\s+COLUMN\s+(\w+)\s+TO\s+(\w+)",
            re.IGNORECASE,
        ),
        "RENAME COLUMN on '{0}' from '{1}' to '{2}' breaks running code referencing the old name",
        "Add a new column, backfill data, deploy code using new column, then drop old column",
    ),
    (
        re.compile(
            r"\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
            r"RENAME\s+TO\s+(\w+)",
            re.IGNORECASE,
        ),
        "RENAME TABLE from '{0}' to '{1}' breaks running code referencing the old name",
        "Create a new table, migrate data, deploy code using new table, then drop old table",
    ),
    (
        re.compile(
            r"\bDROP\s+TYPE\s+(?:IF\s+EXISTS\s+)?(?:public\.)?(\w+)",
            re.IGNORECASE,
        ),
        "DROP TYPE removes '{0}' while running queries may reference it",
        "Deploy code that stops using the type first, then drop in a later migration",
    ),
]

# Medium severity: may cause lock contention, data issues, or partial breakage
_MIGRATION_MEDIUM_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(
            r"\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
            r"ALTER\s+COLUMN\s+(\w+)\s+(?:SET\s+DATA\s+)?TYPE\b",
            re.IGNORECASE,
        ),
        "ALTER COLUMN TYPE on '{0}.{1}' acquires ACCESS EXCLUSIVE lock and may break running queries",
        "Consider adding a new column with the desired type, backfilling, then swapping",
    ),
    (
        re.compile(
            r"\bDROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?(?:public\.)?(\w+)",
            re.IGNORECASE | re.DOTALL,
        ),
        "DROP INDEX '{0}' may degrade query performance for running application",
        "Ensure no queries depend on this index before dropping",
    ),
]

# Patterns to detect NOT NULL without DEFAULT on ADD COLUMN
_ADD_COLUMN_PATTERN = re.compile(
    r"\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
    r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+"
    r"([^;]+?)(?:;|\n\n)",
    re.IGNORECASE | re.DOTALL,
)

# Patterns to detect SET NOT NULL on existing column
_SET_NOT_NULL_PATTERN = re.compile(
    r"\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
    r"ALTER\s+COLUMN\s+(\w+)\s+SET\s+NOT\s+NULL",
    re.IGNORECASE,
)

# Pattern to detect CREATE INDEX without CONCURRENTLY
_CREATE_INDEX_PATTERN = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY\b)(?:IF\s+NOT\s+EXISTS\s+)?(\w+)",
    re.IGNORECASE,
)

# Pattern to detect CREATE INDEX CONCURRENTLY (safe)
_CREATE_INDEX_CONCURRENT_PATTERN = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\b",
    re.IGNORECASE,
)


# Comment directive to suppress migration safety checks for a file.
# Place "-- migration-safety: ignore" on its own line (anywhere in the file).
_MIGRATION_SAFETY_IGNORE = re.compile(
    r"^\s*--\s*migration-safety:\s*ignore\b", re.IGNORECASE | re.MULTILINE
)


def check_migration_safety_violations(report: ComplianceReport) -> None:
    """
    Check that migration files are backwards compatible with a running application.

    Scans db-init/migrations/*.sql for operations that would break a running
    instance if applied while the application is still serving traffic.

    High severity:
    - DROP COLUMN / DROP TABLE / RENAME COLUMN / RENAME TABLE / DROP TYPE
    - ADD COLUMN NOT NULL without DEFAULT

    Medium severity:
    - ALTER COLUMN TYPE (type changes acquire exclusive locks)
    - ALTER COLUMN SET NOT NULL (may fail on existing NULL data)
    - CREATE INDEX without CONCURRENTLY (blocks writes)
    - DROP INDEX (may degrade performance)

    Files containing "-- migration-safety: ignore" are skipped entirely.
    """
    migrations_dir = get_project_root() / "db-init" / "migrations"
    if not migrations_dir.exists():
        return

    for sql_file in sorted(migrations_dir.glob("*.sql")):
        report.files_scanned += 1

        with open(sql_file) as f:
            sql = f.read()

        # Allow opting out with a comment directive
        if _MIGRATION_SAFETY_IGNORE.search(sql):
            continue

        rel_path = str(sql_file.relative_to(get_project_root()))

        # Check high-severity patterns
        for pattern, desc_template, fix in _MIGRATION_HIGH_PATTERNS:
            for match in pattern.finditer(sql):
                groups = match.groups()
                line_num = sql[: match.start()].count("\n") + 1
                report.add(
                    Violation(
                        principle="Migration Safety",
                        severity="high",
                        file_path=rel_path,
                        line_number=line_num,
                        function_name=None,
                        description=desc_template.format(*groups),
                        evidence=match.group(0).strip(),
                        suggested_fix=fix,
                    )
                )

        # Check medium-severity patterns
        for pattern, desc_template, fix in _MIGRATION_MEDIUM_PATTERNS:
            for match in pattern.finditer(sql):
                groups = match.groups()
                line_num = sql[: match.start()].count("\n") + 1
                report.add(
                    Violation(
                        principle="Migration Safety",
                        severity="medium",
                        file_path=rel_path,
                        line_number=line_num,
                        function_name=None,
                        description=desc_template.format(*groups),
                        evidence=match.group(0).strip(),
                        suggested_fix=fix,
                    )
                )

        # Check ADD COLUMN NOT NULL without DEFAULT
        for match in _ADD_COLUMN_PATTERN.finditer(sql):
            table = match.group(1)
            column = match.group(2)
            col_def = match.group(3)

            has_not_null = bool(re.search(r"\bNOT\s+NULL\b", col_def, re.IGNORECASE))
            has_default = bool(re.search(r"\bDEFAULT\b", col_def, re.IGNORECASE))

            if has_not_null and not has_default:
                line_num = sql[: match.start()].count("\n") + 1
                report.add(
                    Violation(
                        principle="Migration Safety",
                        severity="high",
                        file_path=rel_path,
                        line_number=line_num,
                        function_name=None,
                        description=(
                            f"ADD COLUMN '{column}' on '{table}' is NOT NULL without DEFAULT. "
                            f"Fails on non-empty tables and breaks running inserts missing this column"
                        ),
                        evidence=match.group(0).strip(),
                        suggested_fix=(
                            "Add a DEFAULT value, or add as nullable first, "
                            "backfill, then set NOT NULL"
                        ),
                    )
                )

        # Check SET NOT NULL on existing column
        for match in _SET_NOT_NULL_PATTERN.finditer(sql):
            table = match.group(1)
            column = match.group(2)
            line_num = sql[: match.start()].count("\n") + 1
            report.add(
                Violation(
                    principle="Migration Safety",
                    severity="medium",
                    file_path=rel_path,
                    line_number=line_num,
                    function_name=None,
                    description=(
                        f"SET NOT NULL on '{table}.{column}' may fail if existing rows "
                        f"contain NULL values, and breaks running code that inserts NULLs"
                    ),
                    evidence=match.group(0).strip(),
                    suggested_fix=(
                        "Backfill NULLs first, add a NOT VALID CHECK constraint, "
                        "then validate separately"
                    ),
                )
            )

        # Check CREATE INDEX without CONCURRENTLY
        # Only flag if the file has non-concurrent indexes (skip if all are concurrent)
        if _CREATE_INDEX_PATTERN.search(sql) and not _CREATE_INDEX_CONCURRENT_PATTERN.search(sql):
            for match in _CREATE_INDEX_PATTERN.finditer(sql):
                index_name = match.group(1)
                line_num = sql[: match.start()].count("\n") + 1
                report.add(
                    Violation(
                        principle="Migration Safety",
                        severity="medium",
                        file_path=rel_path,
                        line_number=line_num,
                        function_name=None,
                        description=(
                            f"CREATE INDEX '{index_name}' without CONCURRENTLY "
                            f"acquires a write lock on the table"
                        ),
                        evidence=match.group(0).strip(),
                        suggested_fix=(
                            "Use CREATE INDEX CONCURRENTLY to avoid blocking writes. "
                            "Note: CONCURRENTLY cannot run inside a transaction, "
                            "so the migration runner must support this"
                        ),
                    )
                )


# =============================================================================
# Principle 10: Template Links
# =============================================================================


def _collect_all_routes() -> set[str]:
    """Collect all registered route path patterns from router files and pages.py.

    Returns a set of route patterns (with {param} segments replaced by regex wildcards).
    """
    root = get_project_root()
    routes: set[str] = set()

    # Source A: Router files - extract prefix + decorator paths
    router_dir = root / "app" / "routers"
    for py_file in sorted(router_dir.rglob("*.py")):
        if py_file.name.startswith("_"):
            continue

        try:
            source = py_file.read_text()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        # Find router prefix(es) in this file
        prefixes: dict[str, str] = {}  # variable name -> prefix
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(
                        node.value, ast.Call
                    ):
                        call = node.value
                        # Check if it's APIRouter(...)
                        func = call.func
                        if (isinstance(func, ast.Name) and func.id == "APIRouter") or (
                            isinstance(func, ast.Attribute) and func.attr == "APIRouter"
                        ):
                            prefix = ""
                            for kw in call.keywords:
                                if kw.arg == "prefix" and isinstance(
                                    kw.value, ast.Constant
                                ):
                                    prefix = kw.value.value
                            prefixes[target.id] = prefix

        # Extract route decorator paths
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(
                node, ast.AsyncFunctionDef
            ):
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and isinstance(
                        decorator.func, ast.Attribute
                    ):
                        method = decorator.func.attr
                        if method in ("get", "post", "put", "patch", "delete"):
                            # Get the router variable name
                            router_var = None
                            if isinstance(decorator.func.value, ast.Name):
                                router_var = decorator.func.value.id

                            # Get the route path (first positional arg)
                            route_path = ""
                            if decorator.args and isinstance(
                                decorator.args[0], ast.Constant
                            ):
                                route_path = decorator.args[0].value

                            # Combine prefix + route path
                            prefix = prefixes.get(router_var, "") if router_var else ""
                            full_path = prefix + route_path
                            if full_path:
                                routes.add(full_path)

    # Source B: Pages.py
    pages_path = root / "app" / "pages.py"
    if pages_path.exists():
        page_permissions = _extract_page_permissions(pages_path)
        for path in page_permissions:
            routes.add(path)

    # Source C: Known special paths
    routes.add("/")
    routes.add("/healthz")

    return routes


def _normalize_route_for_matching(route: str) -> str:
    """Convert a route pattern like /users/{id}/edit to a regex pattern."""
    # Replace {param} segments with regex wildcard
    pattern = re.sub(r"\{[^}]+\}", "[^/]+", route)
    # Escape other regex-special chars (but not [ ] ^ + which we use)
    # We need to be careful: escape dots, question marks, etc.
    parts = []
    i = 0
    while i < len(pattern):
        if pattern[i : i + 5] == "[^/]+":
            parts.append("[^/]+")
            i += 5
        elif pattern[i] in r"\.?*(){}|$":
            parts.append("\\" + pattern[i])
            i += 1
        else:
            parts.append(pattern[i])
            i += 1
    return "".join(parts)


def _extract_template_links(
    root: Path,
) -> list[tuple[str, int, str]]:
    """Extract href and action attribute values from all template files.

    Returns list of (relative_file_path, line_number, raw_value) tuples.
    """
    templates_dir = root / "app" / "templates"
    if not templates_dir.exists():
        return []

    links: list[tuple[str, int, str]] = []
    # Match href="..." or action="..." (double or single quotes)
    link_pattern = re.compile(r'(?:href|action)\s*=\s*"([^"]*)"')
    link_pattern_sq = re.compile(r"(?:href|action)\s*=\s*'([^']*)'")

    for html_file in sorted(templates_dir.rglob("*.html")):
        rel_path = str(html_file.relative_to(root))
        try:
            content = html_file.read_text()
        except (UnicodeDecodeError, OSError):
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in link_pattern.finditer(line):
                links.append((rel_path, line_num, match.group(1)))
            for match in link_pattern_sq.finditer(line):
                links.append((rel_path, line_num, match.group(1)))

    return links


def _should_skip_link(raw_value: str) -> bool:
    """Return True if a link value should be skipped (not checkable)."""
    if not raw_value:
        return True
    # External links
    if raw_value.startswith(("http://", "https://", "//", "mailto:")):
        return True
    # Anchors
    if raw_value == "#" or raw_value.startswith("#"):
        return True
    # Query-only
    if raw_value.startswith("?"):
        return True
    # Static, branding, and documentation assets
    if raw_value.startswith(("/static/", "/branding/", "/docs/")):
        return True
    # Entirely Jinja2 (fully dynamic path)
    if raw_value.startswith("{{"):
        return True
    # Jinja2 block tags (conditional paths)
    if "{% if" in raw_value or "{% else" in raw_value:
        return True
    return False


def _normalize_link_for_matching(raw_value: str) -> str | None:
    """Normalize a template link value for matching against routes.

    Returns a regex pattern string, or None if the link cannot be normalized.
    """
    # Strip fragment identifiers and query strings
    path = raw_value.split("#")[0]
    path = path.split("?")[0]

    # Strip trailing slash for consistency (but keep "/" as-is)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    if not path:
        return None

    # Replace {{ ... }} Jinja2 expressions with wildcard
    path = re.sub(r"\{\{[^}]*\}\}", "[^/]+", path)

    # Now escape literal parts and keep wildcards
    parts = []
    i = 0
    while i < len(path):
        if path[i : i + 5] == "[^/]+":
            parts.append("[^/]+")
            i += 5
        elif path[i] in r"\.?*(){}|$+":
            parts.append("\\" + path[i])
            i += 1
        else:
            parts.append(path[i])
            i += 1

    return "".join(parts)


def check_template_links_violations(report: ComplianceReport) -> None:
    """Check that template href/action links match registered routes."""
    root = get_project_root()

    # Collect all routes and convert to regex patterns
    raw_routes = _collect_all_routes()
    route_patterns: list[re.Pattern[str]] = []
    for route in raw_routes:
        regex_str = _normalize_route_for_matching(route)
        try:
            route_patterns.append(re.compile("^" + regex_str + "$"))
        except re.error:
            continue

    # Extract all template links
    template_links = _extract_template_links(root)
    report.files_scanned += len(
        {link[0] for link in template_links}
    )

    for file_path, line_num, raw_value in template_links:
        if _should_skip_link(raw_value):
            continue

        normalized = _normalize_link_for_matching(raw_value)
        if normalized is None:
            continue

        # Check if this link matches any route
        try:
            link_regex = re.compile("^" + normalized + "$")
        except re.error:
            continue

        matched = False
        for route_pattern in route_patterns:
            # Check both directions: link matches route, or route matches link
            # (handles cases where both have wildcards)
            if route_pattern.pattern == link_regex.pattern:
                matched = True
                break
            # Try matching the literal link against route patterns
            # For links without wildcards, match directly
            if "[^/]+" not in normalized:
                if route_pattern.match(normalized):
                    matched = True
                    break
            else:
                # Both have wildcards: compare structural patterns
                # Convert wildcards to a common placeholder and compare
                link_struct = re.sub(r"\[\^/\]\+", "<PARAM>", normalized)
                route_struct = re.sub(
                    r"\[\^/\]\+",
                    "<PARAM>",
                    route_pattern.pattern.removeprefix("^").removesuffix("$"),
                )
                if link_struct == route_struct:
                    matched = True
                    break

        if not matched:
            # Truncate evidence if too long
            evidence = raw_value
            if len(evidence) > 100:
                evidence = evidence[:97] + "..."

            report.add(
                Violation(
                    principle="Template Links",
                    severity="medium",
                    file_path=file_path,
                    line_number=line_num,
                    function_name=None,
                    description="Template link does not match any registered route",
                    evidence=f'href/action="{evidence}"',
                    suggested_fix="Check the path against app/routers/ and app/pages.py",
                )
            )


# =============================================================================
# Principle 11: Outbound Request Timeouts
# =============================================================================

# Suppress comment: place "# outbound-timeout: ok" on the call line to suppress
_OUTBOUND_TIMEOUT_SUPPRESS = "# outbound-timeout: ok"

# Direct HTTP library calls that accept a timeout= keyword argument.
# Any match without timeout= is flagged as medium severity.
_OUTBOUND_NEEDS_TIMEOUT: dict[str, str] = {
    # httpx convenience functions
    "httpx.get": "httpx.get()",
    "httpx.post": "httpx.post()",
    "httpx.put": "httpx.put()",
    "httpx.delete": "httpx.delete()",
    "httpx.patch": "httpx.patch()",
    "httpx.head": "httpx.head()",
    "httpx.options": "httpx.options()",
    "httpx.request": "httpx.request()",
    # httpx client constructors (timeout on client applies to all requests)
    "httpx.Client": "httpx.Client()",
    "httpx.AsyncClient": "httpx.AsyncClient()",
    # requests library (not currently used, but catch if added)
    "requests.get": "requests.get()",
    "requests.post": "requests.post()",
    "requests.put": "requests.put()",
    "requests.delete": "requests.delete()",
    "requests.patch": "requests.patch()",
    "requests.head": "requests.head()",
    "requests.options": "requests.options()",
    "requests.request": "requests.request()",
    "requests.Session": "requests.Session()",
    # smtplib
    "smtplib.SMTP": "smtplib.SMTP()",
    "smtplib.SMTP_SSL": "smtplib.SMTP_SSL()",
}

# Methods where timeout= should be present regardless of how the
# module is imported (catches `urlopen(...)` and `urllib.request.urlopen(...)`).
_OUTBOUND_METHODS_NEED_TIMEOUT: set[str] = {"urlopen"}

# SDK constructors/calls that make HTTP requests but don't accept a timeout=
# parameter directly. These are flagged at low severity with guidance to
# configure timeout on the underlying transport.
_SDK_NO_BUILTIN_TIMEOUT: dict[str, tuple[str, str]] = {
    "SendGridAPIClient": (
        "SendGrid client has no built-in request timeout",
        "Set timeout on underlying client: sg.client.timeout = 10",
    ),
}


def _get_dotted_call_name(node: ast.expr) -> str | None:
    """Extract the full dotted name from a Call func expression.

    For ``httpx.get(...)`` returns ``"httpx.get"``.
    For ``urllib.request.urlopen(...)`` returns ``"urllib.request.urlopen"``.
    For a bare ``urlopen(...)`` returns ``"urlopen"``.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = [node.attr]
        current: ast.expr = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def check_outbound_timeout_violations(report: ComplianceReport) -> None:
    """Check that outbound HTTP/network calls have explicit timeouts.

    Scans ``app/`` for known outbound call patterns and verifies that
    each call passes a ``timeout=`` keyword argument.  SDK clients that
    don't support timeout directly are flagged separately.

    Place ``# outbound-timeout: ok`` on the call line to suppress a finding.
    """
    app_path = get_app_path()
    if not app_path.exists():
        return

    for py_file in app_path.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue

        report.files_scanned += 1

        try:
            source = py_file.read_text()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        source_lines = source.splitlines()
        rel_path = str(py_file.relative_to(get_project_root()))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _get_dotted_call_name(node.func)
            if call_name is None:
                continue

            line_num = node.lineno

            # Check for suppression comment on the call line
            if line_num <= len(source_lines):
                if _OUTBOUND_TIMEOUT_SUPPRESS in source_lines[line_num - 1]:
                    continue

            has_timeout = any(kw.arg == "timeout" for kw in node.keywords)

            # 1. Direct HTTP library calls that accept timeout=
            if call_name in _OUTBOUND_NEEDS_TIMEOUT and not has_timeout:
                report.add(
                    Violation(
                        principle="Outbound Timeouts",
                        severity="medium",
                        file_path=rel_path,
                        line_number=line_num,
                        function_name=None,
                        description=(
                            f"{_OUTBOUND_NEEDS_TIMEOUT[call_name]} "
                            f"missing explicit timeout"
                        ),
                        evidence=f"{call_name}(...)",
                        suggested_fix=(
                            "Add timeout= parameter (e.g. timeout=10) "
                            "to prevent indefinite hangs"
                        ),
                    )
                )

            # 2. urlopen() regardless of import style
            method_name = (
                call_name.rsplit(".", 1)[-1] if "." in call_name else call_name
            )
            if (
                method_name in _OUTBOUND_METHODS_NEED_TIMEOUT
                and call_name not in _OUTBOUND_NEEDS_TIMEOUT
                and not has_timeout
            ):
                report.add(
                    Violation(
                        principle="Outbound Timeouts",
                        severity="medium",
                        file_path=rel_path,
                        line_number=line_num,
                        function_name=None,
                        description=f"{call_name}() missing explicit timeout",
                        evidence=f"{call_name}(...)",
                        suggested_fix=(
                            "Add timeout= parameter (e.g. timeout=10) "
                            "to prevent indefinite hangs"
                        ),
                    )
                )

            # 3. SDK clients without built-in timeout support
            bare_name = (
                call_name.rsplit(".", 1)[-1] if "." in call_name else call_name
            )
            if bare_name in _SDK_NO_BUILTIN_TIMEOUT:
                desc, fix = _SDK_NO_BUILTIN_TIMEOUT[bare_name]
                report.add(
                    Violation(
                        principle="Outbound Timeouts",
                        severity="low",
                        file_path=rel_path,
                        line_number=line_num,
                        function_name=None,
                        description=desc,
                        evidence=f"{call_name}(...)",
                        suggested_fix=fix,
                    )
                )


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

    all_principles = [
        "architecture",
        "activity",
        "tenant",
        "api-first",
        "authorization",
        "input-length",
        "sql-length",
        "rls",
        "migration-safety",
        "template-links",
        "outbound-timeouts",
    ]
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
        check_api_doc_violations(report)

    if "authorization" in principles:
        check_authorization_violations(report)

    if "input-length" in principles:
        check_input_length_violations(report)

    if "sql-length" in principles:
        check_sql_length_violations(report)

    if "rls" in principles:
        check_rls_policy_violations(report)

    if "migration-safety" in principles:
        check_migration_safety_violations(report)

    if "template-links" in principles:
        check_template_links_violations(report)

    if "outbound-timeouts" in principles:
        check_outbound_timeout_violations(report)

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
        choices=[
            "architecture",
            "activity",
            "tenant",
            "api-first",
            "authorization",
            "input-length",
            "sql-length",
            "rls",
            "migration-safety",
            "template-links",
            "outbound-timeouts",
            "all",
        ],
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

    # Exit 1 if medium or high violations found
    return 1 if len([v for v in report.violations if v.severity in ("high", "medium")]) else 0


if __name__ == "__main__":
    sys.exit(main())
