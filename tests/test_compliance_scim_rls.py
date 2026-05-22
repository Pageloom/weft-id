"""Tests for the SCIM RLS-widening compliance scanner.

Drives ``dev/compliance_check.check_scim_rls_widening_violations`` against
a synthetic ``app/`` tree so we can assert exactly which call sites fire
(allowed under ``app/jobs/`` and ``app/services/scim/``, flagged elsewhere).

Migration 0037 widened RLS on `scim_push_queue`, `scim_sync_log`,
`sp_scim_credentials`, and (precedent) `event_log` so background workers
can scan cross-tenant. The check guards future call sites: an UNSCOPED
read into these tables from a router or non-SCIM service silently
crosses tenants instead of failing closed.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path


def _load_compliance_module(monkeypatch, project_root: Path):
    """Load `dev/compliance_check` with `get_project_root` pointed at `project_root`."""
    real_root = Path(__file__).resolve().parent.parent
    src = real_root / "dev" / "compliance_check.py"

    spec = importlib.util.spec_from_file_location(
        "compliance_check_scim_rls_under_test",
        src,
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["compliance_check_scim_rls_under_test"] = mod
    spec.loader.exec_module(mod)

    monkeypatch.setattr(mod, "get_project_root", lambda: project_root)
    monkeypatch.setattr(mod, "get_app_path", lambda: project_root / "app")
    return mod


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip("\n"))


# ---------------------------------------------------------------------------
# Allowed sites: jobs and SCIM services may pass UNSCOPED to watched modules.
# ---------------------------------------------------------------------------


def test_jobs_calling_scim_push_queue_unscoped_is_allowed(tmp_path, monkeypatch):
    """`app/jobs/` is an explicit allowed prefix -- no violation."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "jobs" / "__init__.py", "")
    _write(
        tmp_path / "app" / "jobs" / "process_scim_push_queue.py",
        """
        import database
        from database import UNSCOPED

        def run():
            return database.scim_push_queue.list_tenants_with_ready_entries(UNSCOPED)
        """,
    )

    mod = _load_compliance_module(monkeypatch, tmp_path)
    report = mod.ComplianceReport()
    mod.check_scim_rls_widening_violations(report)

    scim_violations = [v for v in report.violations if v.principle == "SCIM RLS Widening"]
    assert scim_violations == []


def test_scim_services_calling_scim_sync_log_unscoped_is_allowed(tmp_path, monkeypatch):
    """`app/services/scim/` is an explicit allowed prefix -- no violation."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "services" / "__init__.py", "")
    _write(tmp_path / "app" / "services" / "scim" / "__init__.py", "")
    _write(
        tmp_path / "app" / "services" / "scim" / "sync_log.py",
        """
        import database
        from database import UNSCOPED

        def all_tenant_recent_failures():
            return database.scim_sync_log.list_recent_failures(UNSCOPED)
        """,
    )

    mod = _load_compliance_module(monkeypatch, tmp_path)
    report = mod.ComplianceReport()
    mod.check_scim_rls_widening_violations(report)

    scim_violations = [v for v in report.violations if v.principle == "SCIM RLS Widening"]
    assert scim_violations == []


def test_database_layer_calling_unscoped_internally_is_allowed(tmp_path, monkeypatch):
    """`app/database/` is the implementation layer -- helpers can wrap their own UNSCOPED."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "database" / "__init__.py", "")
    _write(
        tmp_path / "app" / "database" / "event_log.py",
        """
        from ._core import UNSCOPED, fetchall

        def list_all_event_types():
            return fetchall(UNSCOPED, "SELECT * FROM event_log_metadata")
        """,
    )

    mod = _load_compliance_module(monkeypatch, tmp_path)
    report = mod.ComplianceReport()
    mod.check_scim_rls_widening_violations(report)

    scim_violations = [v for v in report.violations if v.principle == "SCIM RLS Widening"]
    assert scim_violations == []


# ---------------------------------------------------------------------------
# Flagged sites: routers and non-SCIM services may NOT pass UNSCOPED.
# ---------------------------------------------------------------------------


def test_router_unscoped_call_into_scim_push_queue_is_flagged(tmp_path, monkeypatch):
    """A router-layer UNSCOPED read of `scim_push_queue` is the exact bug
    pattern the rule guards against: silently crosses tenants instead of
    failing closed.
    """
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "__init__.py", "")
    _write(
        tmp_path / "app" / "routers" / "bad_router.py",
        """
        import database
        from database import UNSCOPED

        def handler():
            # Bug: cross-tenant read of the push queue from a router.
            return database.scim_push_queue.list_ready_entries(UNSCOPED)
        """,
    )

    mod = _load_compliance_module(monkeypatch, tmp_path)
    report = mod.ComplianceReport()
    mod.check_scim_rls_widening_violations(report)

    scim_violations = [v for v in report.violations if v.principle == "SCIM RLS Widening"]
    assert len(scim_violations) == 1
    v = scim_violations[0]
    assert v.severity == "medium"
    assert v.file_path == "app/routers/bad_router.py"
    assert "scim_push_queue" in v.description


def test_non_scim_service_unscoped_call_into_event_log_is_flagged(tmp_path, monkeypatch):
    """Non-SCIM services are NOT allowed to read RLS-widened tables UNSCOPED."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "services" / "__init__.py", "")
    _write(tmp_path / "app" / "services" / "users" / "__init__.py", "")
    _write(
        tmp_path / "app" / "services" / "users" / "report.py",
        """
        import database
        from database import UNSCOPED

        def tenant_global_audit_summary():
            return database.event_log.list_all_events(UNSCOPED)
        """,
    )

    mod = _load_compliance_module(monkeypatch, tmp_path)
    report = mod.ComplianceReport()
    mod.check_scim_rls_widening_violations(report)

    scim_violations = [v for v in report.violations if v.principle == "SCIM RLS Widening"]
    assert len(scim_violations) == 1
    assert scim_violations[0].file_path == "app/services/users/report.py"
    assert "event_log" in scim_violations[0].description


def test_keyword_tenant_id_unscoped_is_detected(tmp_path, monkeypatch):
    """`tenant_id=UNSCOPED` keyword form is detected the same as positional."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "__init__.py", "")
    _write(
        tmp_path / "app" / "routers" / "kw_bad.py",
        """
        import database
        from database import UNSCOPED

        def handler():
            return database.scim_sync_log.list_recent_failures(tenant_id=UNSCOPED)
        """,
    )

    mod = _load_compliance_module(monkeypatch, tmp_path)
    report = mod.ComplianceReport()
    mod.check_scim_rls_widening_violations(report)

    scim_violations = [v for v in report.violations if v.principle == "SCIM RLS Widening"]
    assert len(scim_violations) == 1


def test_database_dot_unscoped_attribute_form_is_detected(tmp_path, monkeypatch):
    """`database.UNSCOPED` attribute access form is detected as well."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "__init__.py", "")
    _write(
        tmp_path / "app" / "routers" / "attr_bad.py",
        """
        import database

        def handler():
            return database.scim_credentials.list_all_credentials(database.UNSCOPED)
        """,
    )

    mod = _load_compliance_module(monkeypatch, tmp_path)
    report = mod.ComplianceReport()
    mod.check_scim_rls_widening_violations(report)

    scim_violations = [v for v in report.violations if v.principle == "SCIM RLS Widening"]
    assert len(scim_violations) == 1


# ---------------------------------------------------------------------------
# Out-of-scope: scoped calls or calls into other modules must not flag.
# ---------------------------------------------------------------------------


def test_tenant_scoped_calls_are_not_flagged(tmp_path, monkeypatch):
    """A normal tenant-scoped read of a watched table is the happy path."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "__init__.py", "")
    _write(
        tmp_path / "app" / "routers" / "ok.py",
        """
        import database

        def handler(tenant_id):
            return database.scim_push_queue.list_ready_entries(tenant_id)
        """,
    )

    mod = _load_compliance_module(monkeypatch, tmp_path)
    report = mod.ComplianceReport()
    mod.check_scim_rls_widening_violations(report)

    scim_violations = [v for v in report.violations if v.principle == "SCIM RLS Widening"]
    assert scim_violations == []


def test_unscoped_call_into_non_watched_module_is_not_flagged(tmp_path, monkeypatch):
    """`database.health.ping(UNSCOPED)` (or any non-watched module) is fine.

    The rule scopes only to the four RLS-widened tables. UNSCOPED calls
    into global tables like `tenants` or `bg_tasks` continue to be a
    matter of code review, not automated enforcement.
    """
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "services" / "__init__.py", "")
    _write(
        tmp_path / "app" / "services" / "health.py",
        """
        import database

        def ping():
            return database.fetchone(database.UNSCOPED, "SELECT 1")
        """,
    )

    mod = _load_compliance_module(monkeypatch, tmp_path)
    report = mod.ComplianceReport()
    mod.check_scim_rls_widening_violations(report)

    scim_violations = [v for v in report.violations if v.principle == "SCIM RLS Widening"]
    assert scim_violations == []
