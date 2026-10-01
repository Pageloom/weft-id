"""Unit tests for the OIDC conformance results report (dev/oidc_conformance_report.py).

Builds synthetic suite export zips (the same ``test-log-*.json`` shape the
suite writes) and checks plan selection, classification against the
expected-results files, Markdown rendering, and the docs-page rewrite. Also
guards the checked-in docs page markers and the profile list against drift
from the runner's plans.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BASIC = "oidcc-basic-certification-test-plan"
CONFIG = "oidcc-config-certification-test-plan"
FORMPOST = "oidcc-formpost-basic-certification-test-plan"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, PROJECT_ROOT / "dev" / filename)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def report():
    return _load("oidc_conformance_report_under_test", "oidc_conformance_report.py")


def _module_log(test_name, result, *, status="FINISHED", started="2026-09-26T12:00:00Z", **variant):
    return {
        "exportedVersion": "5.2.4",
        "testInfo": {
            "testName": test_name,
            "planId": "PLAN",
            "status": status,
            "result": result,
            "started": started,
            "variant": variant or {"response_mode": "default"},
        },
        "results": [],
    }


def write_export(directory: Path, zip_name: str, logs: list[dict]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / zip_name
    with zipfile.ZipFile(path, "w") as zf:
        for i, log in enumerate(logs):
            zf.writestr(f"test-log-{log['testInfo']['testName']}-{i}.json", json.dumps(log))
            zf.writestr(f"test-log-{log['testInfo']['testName']}-{i}.sig", "sig")
    return path


WARNING_ENTRY = {
    "test-name": "oidcc-scope-profile",
    "variant": {"response_mode": "default"},
    "expected-result": "warning",
    "comment": "Profile claims WeftID has no data for are omitted",
}
SKIP_ENTRY = {
    "test-name": "oidcc-scope-address",
    "variant": "*",
    "comment": "No address scope",
}


def _run(report, modules, profile="Basic OP", plan=BASIC):
    mods = [
        report.Module(
            test_name=m["testInfo"]["testName"],
            variant=m["testInfo"]["variant"],
            status=m["testInfo"]["status"],
            result=m["testInfo"]["result"],
            started=m["testInfo"]["started"],
        )
        for m in modules
    ]
    return report.PlanRun(profile, plan, "PLAN", "5.2.4", mods)


class TestLoadLatestRuns:
    def test_newest_run_per_plan_in_profile_order(self, report, tmp_path):
        write_export(
            tmp_path,
            f"{FORMPOST}-discovery-static_client-A-26-Sep-2026.zip",
            [_module_log("oidcc-server", "PASSED", started="2026-09-26T10:00:00Z")],
        )
        write_export(
            tmp_path,
            f"{BASIC}-discovery-static_client-OLD-20-Sep-2026.zip",
            [_module_log("oidcc-server", "FAILED", started="2026-09-20T10:00:00Z")],
        )
        # Name sorts before OLD but its modules started later: start time wins.
        write_export(
            tmp_path,
            f"{BASIC}-discovery-static_client-AAA-26-Sep-2026.zip",
            [_module_log("oidcc-server", "PASSED", started="2026-09-26T10:00:00Z")],
        )
        write_export(tmp_path, "unrelated-plan-X-26-Sep-2026.zip", [_module_log("x", "FAILED")])

        runs = report.load_latest_runs(tmp_path)

        assert [r.profile for r in runs] == ["Basic OP", "Form Post OP"]
        assert runs[0].modules[0].result == "PASSED"
        assert runs[0].suite_version == "5.2.4"

    def test_formpost_zip_is_not_taken_for_basic(self, report, tmp_path):
        write_export(tmp_path, f"{FORMPOST}-x-A-1.zip", [_module_log("m", "PASSED")])
        runs = report.load_latest_runs(tmp_path)
        assert [r.profile for r in runs] == ["Form Post OP"]

    def test_missing_directory(self, report, tmp_path):
        with pytest.raises(report.ReportError, match="no export directory"):
            report.load_latest_runs(tmp_path / "absent")

    def test_no_plan_exports(self, report, tmp_path):
        tmp_path.joinpath("notes.txt").write_text("x")
        with pytest.raises(report.ReportError, match="no conformance plan exports"):
            report.load_latest_runs(tmp_path)

    def test_corrupt_zip(self, report, tmp_path):
        tmp_path.joinpath(f"{BASIC}-x-A-1.zip").write_text("not a zip")
        with pytest.raises(report.ReportError, match="not a conformance suite export"):
            report.load_latest_runs(tmp_path)

    def test_zip_without_test_logs(self, report, tmp_path):
        with zipfile.ZipFile(tmp_path / f"{BASIC}-x-A-1.zip", "w") as zf:
            zf.writestr("readme.txt", "x")
        with pytest.raises(report.ReportError, match="holds no test logs"):
            report.load_latest_runs(tmp_path)

    def test_log_without_test_info(self, report, tmp_path):
        with zipfile.ZipFile(tmp_path / f"{BASIC}-x-A-1.zip", "w") as zf:
            zf.writestr("test-log-a.json", json.dumps({"results": []}))
        with pytest.raises(report.ReportError, match="not a conformance suite export"):
            report.load_latest_runs(tmp_path)


class TestEntryMatches:
    def _module(self, report, name="oidcc-scope-profile", **variant):
        return report.Module(name, variant or {"response_mode": "default"}, "FINISHED", "X", "")

    def test_partial_variant_match(self, report):
        assert report.entry_matches(WARNING_ENTRY, self._module(report))

    def test_variant_mismatch(self, report):
        module = self._module(report, response_mode="form_post")
        assert not report.entry_matches(WARNING_ENTRY, module)

    def test_wildcard_variant_and_name_glob(self, report):
        entry = {"test-name": "oidcc-scope-*", "variant": "*"}
        assert report.entry_matches(entry, self._module(report, response_mode="form_post"))
        assert not report.entry_matches(entry, self._module(report, name="oidcc-server"))

    def test_missing_variant_matches_any(self, report):
        assert report.entry_matches({"test-name": "oidcc-scope-profile"}, self._module(report))

    def test_non_dict_variant_never_matches(self, report):
        entry = {"test-name": "oidcc-scope-profile", "variant": "response_mode=default"}
        assert not report.entry_matches(entry, self._module(report))


class TestClassify:
    def test_all_green_outcomes_are_accounted_for(self, report):
        run = _run(
            report,
            [
                _module_log("oidcc-server", "PASSED"),
                _module_log("oidcc-scope-profile", "WARNING"),
                _module_log("oidcc-scope-address", "SKIPPED"),
                _module_log("oidcc-prompt-login", "REVIEW"),
            ],
        )
        result = report.classify(run, [WARNING_ENTRY], [SKIP_ENTRY])

        assert result.green
        assert result.counts == {
            "PASSED": 1,
            "WARNING": 1,
            "REVIEW": 1,
            "SKIPPED": 1,
            "FAILED": 0,
        }
        assert result.accepted_warnings == [("oidcc-scope-profile", WARNING_ENTRY["comment"])]
        assert result.expected_skips == [("oidcc-scope-address", "No address scope")]
        assert result.review == ["oidcc-prompt-login"]
        assert result.unexpected == []

    def test_unlisted_warning_and_skip_are_unexpected_but_still_green(self, report):
        run = _run(
            report,
            [_module_log("oidcc-claims-essential", "WARNING"), _module_log("oidcc-x", "SKIPPED")],
        )
        result = report.classify(run, [WARNING_ENTRY], [SKIP_ENTRY])

        assert result.green
        assert result.unexpected == [
            "`oidcc-claims-essential` WARNING not in expected-failures",
            "`oidcc-x` SKIPPED not in expected-skips",
        ]

    def test_failure_entry_does_not_accept_a_warning(self, report):
        entry = dict(WARNING_ENTRY, **{"expected-result": "failure"})
        run = _run(report, [_module_log("oidcc-scope-profile", "WARNING")])
        result = report.classify(run, [entry], [])
        assert result.accepted_warnings == []
        assert len(result.unexpected) == 1

    @pytest.mark.parametrize(
        ("status", "result_value"),
        [("FINISHED", "FAILED"), ("INTERRUPTED", "UNKNOWN"), ("WAITING", "PASSED")],
    )
    def test_failed_or_unfinished_module_makes_profile_red(self, report, status, result_value):
        run = _run(
            report,
            [_module_log("oidcc-server", "PASSED"), _module_log("m", result_value, status=status)],
        )
        result = report.classify(run, [], [])

        assert not result.green
        assert result.counts["FAILED"] == 1
        assert result.counts["PASSED"] == 1
        assert result.unexpected == [f"`m` {status} {result_value}"]


class TestRenderMarkdown:
    def _reports(self, report):
        basic = _run(
            report,
            [
                _module_log("oidcc-server", "PASSED", started="2026-09-25T09:00:00Z"),
                _module_log("oidcc-scope-profile", "WARNING"),
                _module_log("oidcc-scope-address", "SKIPPED"),
                _module_log("oidcc-prompt-login", "REVIEW"),
            ],
        )
        formpost = _run(
            report,
            [
                _module_log(
                    "oidcc-scope-profile",
                    "WARNING",
                    started="2026-09-27T09:00:00Z",
                    response_mode="default",
                ),
                _module_log("oidcc-prompt-login", "REVIEW"),
            ],
            profile="Form Post OP",
            plan=FORMPOST,
        )
        config = _run(report, [_module_log("oidcc-discovery", "PASSED")], "Config OP", CONFIG)
        return [
            report.classify(r, [WARNING_ENTRY], [SKIP_ENTRY]) for r in (basic, config, formpost)
        ]

    def test_metadata_and_table(self, report):
        md = report.render_markdown(self._reports(report), "1.13.0 (`abc1234`)")

        assert "* **Suite version:** 5.2.4" in md
        assert "* **WeftID version:** 1.13.0 (`abc1234`)" in md
        # Newest module start across all plans.
        assert "* **Run date:** 2026-09-27" in md
        assert f"| Basic OP | `{BASIC}` | Green | 1 | 1 | 1 | 1 | 0 |" in md
        assert f"| Config OP | `{CONFIG}` | Green | 1 | 0 | 0 | 0 | 0 |" in md

    def test_lists_group_modules_across_profiles(self, report):
        md = report.render_markdown(self._reports(report), "1.0.0")

        assert (
            f"* `oidcc-scope-profile` (Basic OP, Form Post OP): {WARNING_ENTRY['comment']}"
        ) in md
        assert "* `oidcc-scope-address` (Basic OP): No address scope" in md
        assert "* `oidcc-prompt-login` (Basic OP, Form Post OP)" in md
        assert md.count("oidcc-scope-profile") == 1
        assert "Not accounted for" not in md

    def test_empty_sections_are_omitted(self, report):
        run = _run(report, [_module_log("oidcc-discovery", "PASSED")], "Config OP", CONFIG)
        md = report.render_markdown([report.classify(run, [], [])], "1.0.0")

        assert "Accepted warnings" not in md
        assert "Expected skips" not in md
        assert "Review" not in md.split("|---|")[1]

    def test_red_profile_and_unexpected_items(self, report):
        run = _run(report, [_module_log("oidcc-server", "FAILED")])
        md = report.render_markdown([report.classify(run, [], [])], "1.0.0")

        assert f"| Basic OP | `{BASIC}` | **Red** | 0 | 0 | 0 | 0 | 1 |" in md
        assert "**Not accounted for by the expected-results files:**" in md
        assert "* **Basic OP**: `oidcc-server` FINISHED FAILED" in md


class TestReplaceSection:
    PAGE = "# Title\n\nIntro\n\n{start}\n\nold table\n\n{end}\n\nOutro\n"

    def _page(self, report):
        return self.PAGE.format(start=report.START_MARKER, end=report.END_MARKER)

    def test_replaces_only_between_markers(self, report):
        updated = report.replace_section(self._page(report), "new table\n")

        assert "old table" not in updated
        assert "new table" in updated
        assert updated.startswith("# Title\n\nIntro\n\n")
        assert updated.endswith(f"{report.END_MARKER}\n\nOutro\n")

    def test_idempotent(self, report):
        once = report.replace_section(self._page(report), "table\n")
        assert report.replace_section(once, "table\n") == once

    @pytest.mark.parametrize("page", ["no markers", "<!-- conformance-results:end --> x"])
    def test_missing_markers(self, report, page):
        with pytest.raises(report.ReportError, match="markers"):
            report.replace_section(page, "x")

    def test_reversed_markers(self, report):
        page = f"{report.END_MARKER}\n{report.START_MARKER}"
        with pytest.raises(report.ReportError, match="markers"):
            report.replace_section(page, "x")


class TestWeftidVersion:
    def test_pyproject_version_and_commit(self, report, tmp_path, monkeypatch):
        tmp_path.joinpath("pyproject.toml").write_text('[tool.poetry]\nversion = "9.8.7"\n')
        monkeypatch.setattr(
            report.subprocess,
            "run",
            lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="abc1234\n"),
        )
        assert report.weftid_version(tmp_path) == "9.8.7 (`abc1234`)"

    def test_without_git(self, report, tmp_path, monkeypatch):
        tmp_path.joinpath("pyproject.toml").write_text('[tool.poetry]\nversion = "9.8.7"\n')

        def fail(*a, **k):
            raise subprocess.CalledProcessError(128, "git")

        monkeypatch.setattr(report.subprocess, "run", fail)
        assert report.weftid_version(tmp_path) == "9.8.7"

    def test_real_checkout(self, report):
        data = (PROJECT_ROOT / "pyproject.toml").read_text()
        assert report.weftid_version().split(" ")[0] in data


class TestCli:
    def _export(self, tmp_path):
        export = tmp_path / "export"
        write_export(export, f"{CONFIG}--A-1.zip", [_module_log("oidcc-discovery", "PASSED")])
        return export

    def test_prints_report(self, report, tmp_path, capsys):
        rc = report.main(["--export-dir", str(self._export(tmp_path)), "--weftid-version", "1.0"])

        assert rc == 0
        out = capsys.readouterr().out
        assert "* **WeftID version:** 1.0" in out
        assert f"| Config OP | `{CONFIG}` | Green |" in out

    def test_write_docs_updates_the_page(self, report, tmp_path):
        page = tmp_path / "page.md"
        page.write_text(f"# P\n\n{report.START_MARKER}\nold\n{report.END_MARKER}\n")

        rc = report.main(
            [
                "--export-dir",
                str(self._export(tmp_path)),
                "--weftid-version",
                "1.0",
                "--write-docs",
                str(page),
            ]
        )

        assert rc == 0
        text = page.read_text()
        assert "old" not in text
        assert f"| Config OP | `{CONFIG}` | Green |" in text

    def test_missing_export_is_an_error(self, report, tmp_path):
        with pytest.raises(report.ReportError):
            report.main(["--export-dir", str(tmp_path / "none"), "--weftid-version", "1"])


class TestCheckedInFiles:
    def test_docs_page_has_markers(self, report):
        page = report.DOCS_PAGE.read_text()
        assert page.index(report.START_MARKER) < page.index(report.END_MARKER)

    def test_profiles_match_runner_plans(self, report):
        runner = _load("oidc_conformance_for_report_test", "oidc_conformance.py")
        plan_names = [plan.split("[")[0] for plan in (*runner.PLANS, *runner.DYNAMIC_PLANS)]
        assert plan_names == [plan for _, plan in report.PROFILES]

    def test_every_expected_entry_has_a_public_comment(self, report):
        for path in (report.EXPECTED_FAILURES_PATH, report.EXPECTED_SKIPS_PATH):
            for entry in json.loads(path.read_text()):
                comment = entry["comment"]
                # Comments are published on the docs page.
                assert comment and "Iteration" not in comment, comment
