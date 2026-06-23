"""Tests for the UNSCOPED-write fail-closed compliance scanner.

Drives ``dev/compliance_check.check_unscoped_write_failclosed_violations``
against a synthetic ``db-init/migrations/`` tree so we can assert exactly
which RLS policies fire.

Widened tenant-isolation policies (0037/0045/0047/0048) keep a permissive
``THEN true`` branch in USING so a pre-auth/background path can READ a row
before a tenant scope exists. That branch must NOT survive in WITH CHECK:
if it does, an UNSCOPED INSERT/UPDATE can write an arbitrary tenant_id
instead of failing closed. The check flags a policy only when the escape
hatch is present in BOTH clauses.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

# A permissive clause body fragment (the unscoped read escape hatch).
_PERMISSIVE = """
    CASE
        WHEN (NULLIF(current_setting('app.tenant_id', true), '') IS NULL) THEN true
        ELSE (tenant_id = current_setting('app.tenant_id', true)::uuid)
    END"""

# A strict clause body fragment (fails closed when app.tenant_id is unset).
_STRICT = "(tenant_id = (NULLIF(current_setting('app.tenant_id', true), ''))::uuid)"


def _load_compliance_module(monkeypatch, project_root: Path):
    """Load `dev/compliance_check` with `get_project_root` pointed at `project_root`."""
    real_root = Path(__file__).resolve().parent.parent
    src = real_root / "dev" / "compliance_check.py"

    spec = importlib.util.spec_from_file_location(
        "compliance_check_unscoped_write_under_test",
        src,
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["compliance_check_unscoped_write_under_test"] = mod
    spec.loader.exec_module(mod)

    monkeypatch.setattr(mod, "get_project_root", lambda: project_root)
    return mod


def _write_migration(root: Path, name: str, sql: str) -> None:
    path = root / "db-init" / "migrations" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(sql).lstrip("\n"))


def _run(mod):
    report = mod.ComplianceReport()
    mod.check_unscoped_write_failclosed_violations(report)
    return [v for v in report.violations if v.principle == "UNSCOPED Write Fail-Closed"]


# ---------------------------------------------------------------------------
# Flagged: the escape hatch survives in WITH CHECK.
# ---------------------------------------------------------------------------


def test_permissive_with_check_is_flagged(tmp_path, monkeypatch):
    """A policy permissive in BOTH USING and WITH CHECK is the bug pattern."""
    _write_migration(
        tmp_path,
        "0001_widen.sql",
        f"""
        CREATE POLICY widget_tenant_isolation ON widgets
            USING ({_PERMISSIVE})
            WITH CHECK ({_PERMISSIVE});
        """,
    )
    mod = _load_compliance_module(monkeypatch, tmp_path)
    violations = _run(mod)

    assert len(violations) == 1
    v = violations[0]
    assert v.severity == "high"
    assert v.file_path == "db-init/migrations/0001_widen.sql"
    assert "widgets" in v.description
    assert "widget_tenant_isolation" in v.description


def test_using_only_create_inherits_permissive_with_check(tmp_path, monkeypatch):
    """A CREATE with permissive USING and no WITH CHECK is flagged.

    Postgres copies USING into WITH CHECK when the latter is omitted, so the
    effective write clause is just as permissive.
    """
    _write_migration(
        tmp_path,
        "0001_using_only.sql",
        f"""
        CREATE POLICY widget_tenant_isolation ON widgets
            USING ({_PERMISSIVE});
        """,
    )
    mod = _load_compliance_module(monkeypatch, tmp_path)
    violations = _run(mod)

    assert len(violations) == 1
    assert violations[0].file_path == "db-init/migrations/0001_using_only.sql"


# ---------------------------------------------------------------------------
# Not flagged: WITH CHECK is strict (directly, or after a later ALTER).
# ---------------------------------------------------------------------------


def test_strict_with_check_is_not_flagged(tmp_path, monkeypatch):
    """Permissive USING + strict WITH CHECK is the correct widened shape."""
    _write_migration(
        tmp_path,
        "0001_correct.sql",
        f"""
        CREATE POLICY widget_tenant_isolation ON widgets
            USING ({_PERMISSIVE})
            WITH CHECK {_STRICT};
        """,
    )
    mod = _load_compliance_module(monkeypatch, tmp_path)
    assert _run(mod) == []


def test_later_alter_tightening_with_check_clears_violation(tmp_path, monkeypatch):
    """A later `ALTER POLICY ... WITH CHECK` (strict) overrides an earlier
    permissive CREATE -- the effective state is fail-closed, so no violation.

    This is exactly migration 0050's shape: harden WITH CHECK without
    rewriting the original widening migration.
    """
    _write_migration(
        tmp_path,
        "0001_widen.sql",
        f"""
        CREATE POLICY widget_tenant_isolation ON widgets
            USING ({_PERMISSIVE})
            WITH CHECK ({_PERMISSIVE});
        """,
    )
    _write_migration(
        tmp_path,
        "0002_failclosed.sql",
        f"""
        ALTER POLICY widget_tenant_isolation ON widgets
            WITH CHECK {_STRICT};
        """,
    )
    mod = _load_compliance_module(monkeypatch, tmp_path)
    assert _run(mod) == []


def test_fully_strict_policy_is_not_flagged(tmp_path, monkeypatch):
    """A policy with no escape hatch anywhere is never flagged."""
    _write_migration(
        tmp_path,
        "0001_strict.sql",
        f"""
        CREATE POLICY widget_tenant_isolation ON widgets
            USING {_STRICT}
            WITH CHECK {_STRICT};
        """,
    )
    mod = _load_compliance_module(monkeypatch, tmp_path)
    assert _run(mod) == []


# ---------------------------------------------------------------------------
# Exemption: event_logs intentionally allows UNSCOPED writes (redaction job).
# ---------------------------------------------------------------------------


def test_event_logs_permissive_with_check_is_exempt(tmp_path, monkeypatch):
    """event_logs is exempt: its PII-redaction job UPDATEs rows UNSCOPED."""
    _write_migration(
        tmp_path,
        "0001_event_logs.sql",
        f"""
        CREATE POLICY event_logs_tenant_isolation ON event_logs
            USING ({_PERMISSIVE})
            WITH CHECK ({_PERMISSIVE});
        """,
    )
    mod = _load_compliance_module(monkeypatch, tmp_path)
    assert _run(mod) == []


# ---------------------------------------------------------------------------
# Integration: the real repository migrations are clean.
# ---------------------------------------------------------------------------


def test_real_repository_migrations_are_clean(monkeypatch):
    """The actual db-init/migrations tree must have no fail-closed violations
    (migration 0050 hardened the six widened policies)."""
    real_root = Path(__file__).resolve().parent.parent
    mod = _load_compliance_module(monkeypatch, real_root)
    assert _run(mod) == []
