"""Tests for the form-input-length compliance scanner.

Drives ``dev/compliance_check.check_form_input_length_violations`` against a
synthetic ``app/routers/`` tree so we can assert exactly which Form()
parameter shapes fire.

The rule: every ``str`` Form() parameter in a route handler must carry
``max_length``. Two equivalent syntaxes are covered:

- the Annotated form: ``name: Annotated[str, Form(...)]``
- the default-value form: ``name: str = Form(...)``

Unbounded form parameters allow attackers to submit multi-megabyte strings,
causing memory and CPU exhaustion (especially on password fields passed to
Argon2). Non-str parameters (``list[str]``, ``UploadFile``) are out of scope.
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
        "compliance_check_form_input_length_under_test",
        src,
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["compliance_check_form_input_length_under_test"] = mod
    spec.loader.exec_module(mod)

    monkeypatch.setattr(mod, "get_project_root", lambda: project_root)
    monkeypatch.setattr(mod, "get_app_path", lambda: project_root / "app")
    return mod


def _write_router(root: Path, name: str, code: str) -> None:
    path = root / "app" / "routers" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(code).lstrip("\n"))


def _run(mod):
    report = mod.ComplianceReport()
    mod.check_form_input_length_violations(report)
    return [v for v in report.violations if v.principle == "Form Input Length"]


# ---------------------------------------------------------------------------
# Not flagged: max_length present in either syntax.
# ---------------------------------------------------------------------------


def test_annotated_form_with_max_length_is_clean(tmp_path, monkeypatch):
    """The Annotated form is clean when max_length is present."""
    _write_router(
        tmp_path,
        "ok_annotated.py",
        """
        def create(name: Annotated[str, Form(max_length=255)]):
            pass
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_default_value_form_with_max_length_is_clean(tmp_path, monkeypatch):
    """The default-value form is clean when max_length is present."""
    _write_router(
        tmp_path,
        "ok_default.py",
        """
        def create(name: str = Form("", max_length=255)):
            pass
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_required_default_value_form_with_max_length_is_clean(tmp_path, monkeypatch):
    """`name: str = Form(...)` with max_length is clean."""
    _write_router(
        tmp_path,
        "ok_required.py",
        """
        def consent(action: str = Form(..., max_length=50)):
            pass
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_plain_string_default_is_clean(tmp_path, monkeypatch):
    """A plain `= ""` default is not a Form() parameter and is never flagged."""
    _write_router(
        tmp_path,
        "ok_plain.py",
        """
        def create(name: str = ""):
            pass
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_non_str_form_parameters_are_clean(tmp_path, monkeypatch):
    """list[str] and UploadFile Form() params are out of scope."""
    _write_router(
        tmp_path,
        "ok_non_str.py",
        """
        def bulk(group_ids: list[str] = Form(default=[])):
            pass

        def upload(file: UploadFile = Form(...)):
            pass
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


# ---------------------------------------------------------------------------
# Flagged: missing max_length in either syntax.
# ---------------------------------------------------------------------------


def test_annotated_form_without_max_length_is_flagged(tmp_path, monkeypatch):
    """The Annotated form without max_length is the original bug pattern."""
    _write_router(
        tmp_path,
        "bad_annotated.py",
        """
        def create(name: Annotated[str, Form()]):
            pass
    """,
    )
    violations = _run(_load_compliance_module(monkeypatch, tmp_path))
    assert len(violations) == 1
    assert violations[0].file_path == "app/routers/bad_annotated.py"
    assert violations[0].function_name == "create"
    assert violations[0].severity == "medium"
    assert "max_length" in violations[0].suggested_fix


def test_default_value_form_without_max_length_is_flagged(tmp_path, monkeypatch):
    """The default-value form without max_length is the newly covered gap."""
    _write_router(
        tmp_path,
        "bad_default.py",
        """
        def create(name: str = Form("")):
            pass
    """,
    )
    violations = _run(_load_compliance_module(monkeypatch, tmp_path))
    assert len(violations) == 1
    assert violations[0].file_path == "app/routers/bad_default.py"
    assert violations[0].function_name == "create"
    assert violations[0].line_number == 1
    assert "max_length" in violations[0].suggested_fix


def test_required_default_value_form_without_max_length_is_flagged(tmp_path, monkeypatch):
    """`name: str = Form(...)` without max_length is flagged too."""
    _write_router(
        tmp_path,
        "bad_required.py",
        """
        def consent(action: str = Form(...)):
            pass
    """,
    )
    assert len(_run(_load_compliance_module(monkeypatch, tmp_path))) == 1


def test_optional_union_annotation_is_flagged(tmp_path, monkeypatch):
    """`str | None = Form(...)` is still a str parameter and must be bounded."""
    _write_router(
        tmp_path,
        "bad_union.py",
        """
        def create(name: str | None = Form("")):
            pass
    """,
    )
    assert len(_run(_load_compliance_module(monkeypatch, tmp_path))) == 1


def test_each_unbounded_parameter_is_reported_separately(tmp_path, monkeypatch):
    """Every unbounded Form() parameter is its own finding, not one per file."""
    _write_router(
        tmp_path,
        "bad_many.py",
        """
        def create(name: str = Form(""), description: str = Form("")):
            pass

        def update(name: str = Form("")):
            pass
    """,
    )
    assert len(_run(_load_compliance_module(monkeypatch, tmp_path))) == 3


def test_mixed_syntaxes_are_both_flagged(tmp_path, monkeypatch):
    """Annotated and default-value forms in one function are both caught."""
    _write_router(
        tmp_path,
        "bad_mixed.py",
        """
        def create(
            name: Annotated[str, Form()],
            description: str = Form(""),
        ):
            pass
    """,
    )
    assert len(_run(_load_compliance_module(monkeypatch, tmp_path))) == 2


# ---------------------------------------------------------------------------
# Robustness.
# ---------------------------------------------------------------------------


def test_unparseable_file_is_skipped(tmp_path, monkeypatch):
    """A syntax error in one router must not abort the whole scan."""
    _write_router(tmp_path, "broken.py", "def f(:\n")
    _write_router(
        tmp_path,
        "bad.py",
        """
        def create(name: str = Form("")):
            pass
    """,
    )
    violations = _run(_load_compliance_module(monkeypatch, tmp_path))
    assert len(violations) == 1
    assert violations[0].file_path == "app/routers/bad.py"


def test_missing_routers_directory_is_a_noop(tmp_path, monkeypatch):
    """The check must not explode when app/routers/ is absent."""
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_check_is_registered_in_the_principle_list(tmp_path, monkeypatch):
    """The check must actually run under `make check`, not just exist."""
    mod = _load_compliance_module(monkeypatch, tmp_path)
    _write_router(
        tmp_path,
        "bad.py",
        """
        def create(name: str = Form("")):
            pass
    """,
    )
    report = mod.run_compliance_check(principles=["form-input-length"])
    assert [v.principle for v in report.violations] == ["Form Input Length"]
