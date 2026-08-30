"""Tests for the same-origin redirect validation compliance scanner.

Drives ``dev/compliance_check.check_redirect_validation_violations`` against a
synthetic ``app/routers/`` tree so we can assert exactly which redirect shapes
fire.

The rule is structural: inside ``app/routers/``, ``RedirectResponse`` may only
be built with a literal string target. Anything computed must go through
``safe_redirect()``, which is the single place same-origin redirect policy is
enforced. Deliberate off-origin redirects (OAuth2 ``redirect_uri``, SAML hops
to the external IdP, signed download URLs, forward-auth handshakes) must NOT be
wrapped and are waived with ``# redirect-ok: <reason>``.
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
        "compliance_check_redirect_validation_under_test",
        src,
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["compliance_check_redirect_validation_under_test"] = mod
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
    mod.check_redirect_validation_violations(report)
    return [v for v in report.violations if v.principle == "Same-Origin Redirect Validation"]


# ---------------------------------------------------------------------------
# Not flagged: the target cannot carry request data.
# ---------------------------------------------------------------------------


def test_literal_keyword_target_is_clean(tmp_path, monkeypatch):
    """A literal string target is a fixed route, not an open-redirect vector."""
    _write_router(
        tmp_path,
        "ok.py",
        """
        def index():
            return RedirectResponse(url="/dashboard", status_code=303)
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_literal_positional_target_is_clean(tmp_path, monkeypatch):
    """The url argument may be passed positionally."""
    _write_router(
        tmp_path,
        "ok_positional.py",
        """
        def index():
            return RedirectResponse("/dashboard", status_code=303)
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_safe_redirect_call_is_clean(tmp_path, monkeypatch):
    """safe_redirect() is the sanctioned wrapper and is never flagged."""
    _write_router(
        tmp_path,
        "wrapped.py",
        """
        def index(group_id):
            return safe_redirect(f"/admin/groups/{group_id}", status_code=303)
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_files_outside_routers_are_not_scanned(tmp_path, monkeypatch):
    """utils.redirects itself builds RedirectResponse and must not self-flag."""
    helper = tmp_path / "app" / "utils" / "redirects.py"
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text("def safe_redirect(t):\n    return RedirectResponse(url=t)\n")
    _write_router(tmp_path, "ok.py", "x = 1\n")
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


# ---------------------------------------------------------------------------
# Flagged: a computed target with no validation.
# ---------------------------------------------------------------------------


def test_fstring_target_is_flagged(tmp_path, monkeypatch):
    """An f-string target built from a path param is the core bug pattern."""
    _write_router(
        tmp_path,
        "bad_fstring.py",
        """
        def detail(group_id):
            return RedirectResponse(url=f"/admin/groups/{group_id}", status_code=303)
    """,
    )
    violations = _run(_load_compliance_module(monkeypatch, tmp_path))
    assert len(violations) == 1
    assert violations[0].file_path == "app/routers/bad_fstring.py"
    assert violations[0].line_number == 2
    assert violations[0].severity == "high"
    assert "safe_redirect" in violations[0].suggested_fix


def test_name_target_is_flagged(tmp_path, monkeypatch):
    """A bare variable target is opaque, so it must go through the guard."""
    _write_router(
        tmp_path,
        "bad_name.py",
        """
        def callback(request):
            target = request.session.get("next")
            return RedirectResponse(url=target, status_code=303)
    """,
    )
    assert len(_run(_load_compliance_module(monkeypatch, tmp_path))) == 1


def test_concatenated_target_is_flagged(tmp_path, monkeypatch):
    """String concatenation is just as dynamic as an f-string."""
    _write_router(
        tmp_path,
        "bad_concat.py",
        """
        def index(qs):
            return RedirectResponse(url="/admin/groups" + qs, status_code=303)
    """,
    )
    assert len(_run(_load_compliance_module(monkeypatch, tmp_path))) == 1


def test_positional_dynamic_target_is_flagged(tmp_path, monkeypatch):
    """A positional computed target is not a way around the rule."""
    _write_router(
        tmp_path,
        "bad_positional.py",
        """
        def index(target):
            return RedirectResponse(target, status_code=303)
    """,
    )
    assert len(_run(_load_compliance_module(monkeypatch, tmp_path))) == 1


def test_attribute_call_form_is_flagged(tmp_path, monkeypatch):
    """responses.RedirectResponse(...) is the same constructor."""
    _write_router(
        tmp_path,
        "bad_attr.py",
        """
        def index(target):
            return responses.RedirectResponse(url=target, status_code=303)
    """,
    )
    assert len(_run(_load_compliance_module(monkeypatch, tmp_path))) == 1


def test_each_dynamic_call_is_reported_separately(tmp_path, monkeypatch):
    """Every unguarded site is its own finding, not one per file."""
    _write_router(
        tmp_path,
        "bad_many.py",
        """
        def a(x):
            return RedirectResponse(url=x, status_code=303)

        def b(y):
            return RedirectResponse(url=f"/x/{y}", status_code=303)
    """,
    )
    assert len(_run(_load_compliance_module(monkeypatch, tmp_path))) == 2


# ---------------------------------------------------------------------------
# Waived: deliberate off-origin redirects.
# ---------------------------------------------------------------------------


def test_suppression_on_call_line_is_waived(tmp_path, monkeypatch):
    """A trailing marker matches the existing '# ssrf-ok:' convention."""
    _write_router(
        tmp_path,
        "oauth.py",
        """
        def authorize(redirect_uri):
            return RedirectResponse(url=redirect_uri)  # redirect-ok: registered redirect_uri
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_suppression_above_call_is_waived(tmp_path, monkeypatch):
    """A marker on the preceding line keeps long call lines under the limit."""
    _write_router(
        tmp_path,
        "spaces.py",
        """
        def download(info):
            # redirect-ok: signed object-storage download URL
            return RedirectResponse(url=info["url"], status_code=302)
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_suppression_inside_wrapped_call_is_waived(tmp_path, monkeypatch):
    """The marker may sit on the url= line of a multi-line call."""
    _write_router(
        tmp_path,
        "wrapped_call.py",
        """
        def authorize(redirect_uri, state):
            return RedirectResponse(
                url=f"{redirect_uri}?state={state}",  # redirect-ok: registered redirect_uri
                status_code=302,
            )
    """,
    )
    assert _run(_load_compliance_module(monkeypatch, tmp_path)) == []


def test_suppression_does_not_leak_to_the_next_call(tmp_path, monkeypatch):
    """A waiver covers its own call only, not the one that follows."""
    _write_router(
        tmp_path,
        "leak.py",
        """
        def a(redirect_uri):
            return RedirectResponse(url=redirect_uri)  # redirect-ok: registered redirect_uri

        def b(target):
            return RedirectResponse(url=target, status_code=303)
    """,
    )
    violations = _run(_load_compliance_module(monkeypatch, tmp_path))
    assert len(violations) == 1
    assert violations[0].line_number == 5


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
        def index(target):
            return RedirectResponse(url=target, status_code=303)
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
        def index(target):
            return RedirectResponse(url=target, status_code=303)
    """,
    )
    report = mod.run_compliance_check(principles=["redirect-validation"])
    assert [v.principle for v in report.violations] == ["Same-Origin Redirect Validation"]
