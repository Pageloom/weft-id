"""Tests for the architecture/layering compliance scanner.

Drives ``dev/compliance_check.check_architecture_violations`` against a
synthetic ``app/`` tree on disk so we can assert exactly which rules
fire (and that the allowlist suppresses them).
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

import pytest


def _load_compliance_module(monkeypatch, project_root: Path):
    """Load ``dev/compliance_check`` with ``get_project_root`` pointed at ``project_root``.

    The scanner derives the app path from ``get_project_root()``, so we
    swap that to a tmp dir that contains a fake ``app/`` tree.
    """
    real_root = Path(__file__).resolve().parent.parent
    src = real_root / "dev" / "compliance_check.py"

    spec = importlib.util.spec_from_file_location(
        "compliance_check_under_test",
        src,
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register under a unique name so importlib doesn't cache across tests.
    sys.modules["compliance_check_under_test"] = mod
    spec.loader.exec_module(mod)

    monkeypatch.setattr(mod, "get_project_root", lambda: project_root)
    monkeypatch.setattr(mod, "get_app_path", lambda: project_root / "app")
    return mod


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip("\n"))


def test_router_importing_database_is_flagged(tmp_path, monkeypatch):
    """Pre-existing rule -- preserved by the generalized scanner."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "__init__.py", "")
    _write(
        tmp_path / "app" / "routers" / "bad.py",
        """
        import database

        def handler():
            return database.users.list_users("t")
        """,
    )

    cc = _load_compliance_module(monkeypatch, tmp_path)
    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    paths = {v.file_path for v in report.violations}
    assert "app/routers/bad.py" in paths
    bad = [v for v in report.violations if v.file_path == "app/routers/bad.py"]
    assert all(v.severity == "high" for v in bad)
    assert any("Router imports directly from database" in v.description for v in bad)


def test_util_importing_database_is_flagged_high(tmp_path, monkeypatch):
    """New rule: utils are leaf code; reaching into ``database`` is high."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "utils" / "__init__.py", "")
    _write(
        tmp_path / "app" / "utils" / "bad_helper.py",
        """
        from database.users import get_user_by_id

        def helper(t, u):
            return get_user_by_id(t, u)
        """,
    )

    cc = _load_compliance_module(monkeypatch, tmp_path)
    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    matching = [v for v in report.violations if v.file_path == "app/utils/bad_helper.py"]
    assert matching, "Expected a violation for util importing database"
    assert all(v.severity == "high" for v in matching)
    assert any("leaf code" in v.description for v in matching)


def test_util_importing_services_is_flagged_medium(tmp_path, monkeypatch):
    """New rule: utils must not import services either (medium severity)."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "utils" / "__init__.py", "")
    _write(
        tmp_path / "app" / "utils" / "bad_helper.py",
        """
        from services.users import list_users

        def helper(ru):
            return list_users(ru)
        """,
    )

    cc = _load_compliance_module(monkeypatch, tmp_path)
    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    matching = [v for v in report.violations if v.file_path == "app/utils/bad_helper.py"]
    assert matching
    assert all(v.severity == "medium" for v in matching)


def test_middleware_importing_database_is_flagged(tmp_path, monkeypatch):
    """New rule: middleware must not import the database layer."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "middleware" / "__init__.py", "")
    _write(
        tmp_path / "app" / "middleware" / "bad_mw.py",
        """
        import database

        def middleware(request, call_next):
            database.users.touch(request.state.tenant_id, request.state.user_id)
            return call_next(request)
        """,
    )

    cc = _load_compliance_module(monkeypatch, tmp_path)
    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    matching = [v for v in report.violations if v.file_path == "app/middleware/bad_mw.py"]
    assert matching
    assert matching[0].severity == "high"
    assert "Middleware" in matching[0].description


def test_jobs_importing_database_is_flagged(tmp_path, monkeypatch):
    """New rule: job handlers should call services, not the database directly."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "jobs" / "__init__.py", "")
    _write(
        tmp_path / "app" / "jobs" / "bad_job.py",
        """
        import database

        def run(payload):
            database.events.cleanup_old(payload["tenant_id"])
        """,
    )

    cc = _load_compliance_module(monkeypatch, tmp_path)
    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    matching = [v for v in report.violations if v.file_path == "app/jobs/bad_job.py"]
    assert matching
    assert matching[0].severity == "high"


def test_app_prefixed_import_form_is_caught(tmp_path, monkeypatch):
    """``from app.database import x`` is the same violation as ``from database import x``."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "__init__.py", "")
    _write(
        tmp_path / "app" / "routers" / "bad.py",
        """
        from app.database.users import list_users
        """,
    )

    cc = _load_compliance_module(monkeypatch, tmp_path)
    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    matching = [v for v in report.violations if v.file_path == "app/routers/bad.py"]
    assert matching, "Expected a violation for app.database.<x> import"


def test_clean_router_is_not_flagged(tmp_path, monkeypatch):
    """Router that only imports services is fine."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "__init__.py", "")
    _write(
        tmp_path / "app" / "routers" / "good.py",
        """
        from services.users import list_users

        def handler(ru):
            return list_users(ru)
        """,
    )

    cc = _load_compliance_module(monkeypatch, tmp_path)
    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    assert not [v for v in report.violations if v.file_path == "app/routers/good.py"]


def test_allowlist_suppresses_known_violations(tmp_path, monkeypatch):
    """A file on the allowlist is skipped entirely."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "utils" / "__init__.py", "")
    _write(
        tmp_path / "app" / "utils" / "grandfathered.py",
        """
        import database
        """,
    )

    cc = _load_compliance_module(monkeypatch, tmp_path)
    monkeypatch.setattr(cc, "LAYERING_ALLOWLIST", frozenset({"app/utils/grandfathered.py"}))

    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    assert not [v for v in report.violations if v.file_path == "app/utils/grandfathered.py"]


def test_services_layer_may_import_database(tmp_path, monkeypatch):
    """Services are the one layer allowed to call into ``database``."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "services" / "__init__.py", "")
    _write(
        tmp_path / "app" / "services" / "ok.py",
        """
        import database

        def list_things(t):
            return database.things.list(t)
        """,
    )

    cc = _load_compliance_module(monkeypatch, tmp_path)
    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    assert not [v for v in report.violations if v.file_path == "app/services/ok.py"]


@pytest.mark.parametrize(
    "stmt",
    [
        "import database.users",
        "from database.users import get_user",
        "from app.database import users",
    ],
)
def test_router_violation_import_shapes(tmp_path, monkeypatch, stmt):
    """All three import shapes for ``database`` should be flagged in routers."""
    _write(tmp_path / "app" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "__init__.py", "")
    _write(tmp_path / "app" / "routers" / "bad.py", f"{stmt}\n")

    cc = _load_compliance_module(monkeypatch, tmp_path)
    report = cc.ComplianceReport()
    cc.check_architecture_violations(report)

    matching = [v for v in report.violations if v.file_path == "app/routers/bad.py"]
    assert matching, f"Expected violation for: {stmt}"
