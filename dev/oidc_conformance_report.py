#!/usr/bin/env python3
"""Turn an OIDC conformance export directory into the Markdown results table.

Reads the per-plan zips that ``make oidc-conformance`` exports (one
``test-log-*.json`` per module), keeps the newest run of each plan, and
classifies every module against the checked-in expected-failures and
expected-skips files. The output is the results section of the public docs
page (``docs/conformance/oidc.md``): run metadata, one row per profile, and
the accepted warnings, expected skips and review-only modules by name.

Standard library only, so CI can run it without the Poetry environment.

Usage:
    python dev/oidc_conformance_report.py [--export-dir DIR]
    python dev/oidc_conformance_report.py --write-docs   # update the docs page

A profile is green when every module finished as PASSED, WARNING, REVIEW or
SKIPPED, or as FAILED with an expected-failures entry of result "failure"
(an accepted deviation, listed by name). The report also flags anything the
expected files do not account for; the runner's exit code is still the gate,
this is the presentation.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
import tomllib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "dev" / "oidc-conformance"
DEFAULT_EXPORT_DIR = CONFIG_DIR / "export"
EXPECTED_FAILURES_PATH = CONFIG_DIR / "expected-failures.json"
EXPECTED_SKIPS_PATH = CONFIG_DIR / "expected-skips.json"
DOCS_PAGE = PROJECT_ROOT / "docs" / "conformance" / "oidc.md"
START_MARKER = "<!-- conformance-results:start -->"
END_MARKER = "<!-- conformance-results:end -->"

# Profile name as the OpenID Foundation lists it, and the plan that tests it.
# Export zips are named "<plan>-<variant values>-<plan id>-<date>.zip".
PROFILES = (
    ("Basic OP", "oidcc-basic-certification-test-plan"),
    ("Config OP", "oidcc-config-certification-test-plan"),
    ("Form Post OP", "oidcc-formpost-basic-certification-test-plan"),
    ("RP-Initiated OP", "oidcc-rp-initiated-logout-certification-test-plan"),
    ("Front-Channel OP", "oidcc-frontchannel-rp-initiated-logout-certification-test-plan"),
    ("Back-Channel OP", "oidcc-backchannel-rp-initiated-logout-certification-test-plan"),
    ("private_key_jwt clients", "oidcc-test-plan"),
    ("Dynamic OP", "oidcc-dynamic-certification-test-plan"),
    ("3rd Party-Init OP", "oidcc-3rdparty-init-login-certification-test-plan"),
)

GREEN_RESULTS = {"PASSED", "WARNING", "REVIEW", "SKIPPED"}


class ReportError(Exception):
    """The export directory cannot be turned into a report."""


@dataclass
class Module:
    test_name: str
    variant: dict
    status: str
    result: str
    started: str


@dataclass
class PlanRun:
    profile: str
    plan: str
    plan_id: str
    suite_version: str
    modules: list[Module]

    @property
    def started(self) -> str:
        return max((m.started for m in self.modules), default="")


@dataclass
class ProfileReport:
    run: PlanRun
    counts: dict[str, int] = field(default_factory=dict)
    accepted_warnings: list[tuple[str, str]] = field(default_factory=list)
    accepted_failures: list[tuple[str, str]] = field(default_factory=list)
    expected_skips: list[tuple[str, str]] = field(default_factory=list)
    review: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)

    @property
    def green(self) -> bool:
        """Every module green, or failed with an accepted deviation."""
        return self.counts.get("FAILED", 0) == len(self.accepted_failures)

    @property
    def outcome(self) -> str:
        if not self.green:
            return "**Red**"
        accepted = len(self.accepted_failures)
        if accepted:
            return f"Green ({accepted} accepted failure{'s' if accepted > 1 else ''})"
        return "Green"


# ---------------------------------------------------------------------------
# Reading the export
# ---------------------------------------------------------------------------


def _profile_for(zip_name: str) -> tuple[str, str] | None:
    for profile, plan in PROFILES:
        if zip_name.startswith(plan + "-"):
            return profile, plan
    return None


def read_plan_zip(path: Path, profile: str, plan: str) -> PlanRun:
    modules: list[Module] = []
    plan_id = ""
    suite_version = ""
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if not (name.startswith("test-log-") and name.endswith(".json")):
                    continue
                doc = json.loads(zf.read(name))
                info = doc["testInfo"]
                plan_id = info.get("planId", plan_id)
                suite_version = doc.get("exportedVersion", suite_version)
                modules.append(
                    Module(
                        test_name=info["testName"],
                        variant=info.get("variant") or {},
                        status=info.get("status") or "UNKNOWN",
                        result=info.get("result") or "UNKNOWN",
                        started=info.get("started") or "",
                    )
                )
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError) as exc:
        raise ReportError(f"{path.name} is not a conformance suite export: {exc}") from exc
    if not modules:
        raise ReportError(f"{path.name} holds no test logs")
    modules.sort(key=lambda m: m.started)
    return PlanRun(profile, plan, plan_id, suite_version, modules)


def load_latest_runs(export_dir: Path) -> list[PlanRun]:
    """Newest run of each profile's plan, in profile order.

    The export directory accumulates a zip per plan per run, so "newest" is
    decided by the modules' start times, not by file names or mtimes.
    """
    if not export_dir.is_dir():
        raise ReportError(f"no export directory at {export_dir}")
    latest: dict[str, PlanRun] = {}
    for path in sorted(export_dir.glob("*.zip")):
        match = _profile_for(path.name)
        if match is None:
            continue
        run = read_plan_zip(path, *match)
        current = latest.get(run.profile)
        if current is None or run.started > current.started:
            latest[run.profile] = run
    if not latest:
        raise ReportError(f"no conformance plan exports in {export_dir}")
    return [latest[profile] for profile, _ in PROFILES if profile in latest]


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def entry_matches(entry: dict, module: Module) -> bool:
    """Same matching rules as run-test-plan.py: name glob, partial variant."""
    if not fnmatch.fnmatch(module.test_name, entry.get("test-name", "")):
        return False
    variant = entry.get("variant", "*")
    if variant == "*" or variant is None:
        return True
    if not isinstance(variant, dict):
        return False
    return all(module.variant.get(key) == value for key, value in variant.items())


def _comment(entries: list[dict], module: Module, expected_result: str | None) -> str | None:
    for entry in entries:
        if expected_result and entry.get("expected-result") != expected_result:
            continue
        if entry_matches(entry, module):
            return entry.get("comment", "")
    return None


def classify(run: PlanRun, failures: list[dict], skips: list[dict]) -> ProfileReport:
    report = ProfileReport(run=run)
    for result in ("PASSED", "WARNING", "REVIEW", "SKIPPED", "FAILED"):
        report.counts[result] = 0
    for module in run.modules:
        if module.status != "FINISHED" or module.result not in GREEN_RESULTS:
            report.counts["FAILED"] += 1
            comment = None
            if module.status == "FINISHED" and module.result == "FAILED":
                comment = _comment(failures, module, "failure")
            if comment is None:
                report.unexpected.append(f"`{module.test_name}` {module.status} {module.result}")
            else:
                report.accepted_failures.append((module.test_name, comment))
            continue
        report.counts[module.result] += 1
        if module.result == "WARNING":
            comment = _comment(failures, module, "warning")
            if comment is None:
                report.unexpected.append(f"`{module.test_name}` WARNING not in expected-failures")
            else:
                report.accepted_warnings.append((module.test_name, comment))
        elif module.result == "SKIPPED":
            comment = _comment(skips, module, None)
            if comment is None:
                report.unexpected.append(f"`{module.test_name}` SKIPPED not in expected-skips")
            else:
                report.expected_skips.append((module.test_name, comment))
        elif module.result == "REVIEW":
            report.review.append(module.test_name)
    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def weftid_version(project_root: Path = PROJECT_ROOT) -> str:
    """``<pyproject version> (<short commit>)``, the commit omitted outside git."""
    data = tomllib.loads((project_root / "pyproject.toml").read_text())
    version = data["tool"]["poetry"]["version"]
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except OSError, subprocess.SubprocessError:
        return version
    return f"{version} (`{sha}`)" if sha else version


def _bullets(reports: list[ProfileReport], attr: str) -> list[str]:
    """One bullet per module and reason, naming every profile it occurs in.

    Basic and Form Post run the same modules in two response modes, so the
    same accepted warning would otherwise be listed twice.
    """
    profiles: dict[tuple[str, str], list[str]] = {}
    for report in reports:
        for name, comment in getattr(report, attr):
            profiles.setdefault((name, comment), []).append(report.run.profile)
    return [
        f"* `{name}` ({', '.join(names)}): {comment}" for (name, comment), names in profiles.items()
    ]


def render_markdown(reports: list[ProfileReport], weftid: str) -> str:
    suite_versions = sorted({r.run.suite_version for r in reports if r.run.suite_version})
    run_date = max(r.run.started for r in reports)[:10]
    lines = [
        f"* **Suite version:** {', '.join(suite_versions) or 'unknown'}",
        f"* **WeftID version:** {weftid}",
        f"* **Run date:** {run_date or 'unknown'}",
        "",
        "| Profile | Test plan | Outcome | Passed | Warning | Review | Skipped | Failed |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in reports:
        c = r.counts
        lines.append(
            f"| {r.run.profile} | `{r.run.plan}` | {r.outcome} | {c['PASSED']} | "
            f"{c['WARNING']} | {c['REVIEW']} | {c['SKIPPED']} | {c['FAILED']} |"
        )

    failures = _bullets(reports, "accepted_failures")
    if failures:
        lines += ["", "**Accepted failures** (each is a deviation listed below):", ""]
        lines += failures

    warnings = _bullets(reports, "accepted_warnings")
    if warnings:
        lines += ["", "**Accepted warnings** (each is a deviation listed below):", ""]
        lines += warnings

    skips = _bullets(reports, "expected_skips")
    if skips:
        lines += ["", "**Expected skips:**", ""]
        lines += skips

    review_profiles: dict[str, list[str]] = {}
    for r in reports:
        for name in r.review:
            review_profiles.setdefault(name, []).append(r.run.profile)
    review = [f"* `{name}` ({', '.join(names)})" for name, names in review_profiles.items()]
    if review:
        lines += [
            "",
            "**Review** means the suite captured a screenshot (an error page, a second "
            "login page, or the consent page) for a person to judge, because it cannot "
            "judge page content itself:",
            "",
        ]
        lines += review

    unexpected = [f"* **{r.run.profile}**: {item}" for r in reports for item in r.unexpected]
    if unexpected:
        lines += ["", "**Not accounted for by the expected-results files:**", ""]
        lines += unexpected

    return "\n".join(lines) + "\n"


def replace_section(page: str, section: str) -> str:
    start = page.find(START_MARKER)
    end = page.find(END_MARKER)
    if start == -1 or end == -1 or end < start:
        raise ReportError(f"docs page is missing the {START_MARKER} / {END_MARKER} markers")
    head = page[: start + len(START_MARKER)]
    return f"{head}\n\n{section}\n{page[end:]}"


def build_report(export_dir: Path, weftid: str) -> str:
    failures = json.loads(EXPECTED_FAILURES_PATH.read_text())
    skips = json.loads(EXPECTED_SKIPS_PATH.read_text())
    reports = [classify(run, failures, skips) for run in load_latest_runs(export_dir)]
    return render_markdown(reports, weftid)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--export-dir", type=Path, default=DEFAULT_EXPORT_DIR)
    parser.add_argument(
        "--weftid-version", default=None, help="override (default: pyproject version + commit)"
    )
    parser.add_argument(
        "--write-docs",
        nargs="?",
        type=Path,
        const=DOCS_PAGE,
        default=None,
        metavar="PAGE",
        help=f"replace the results section of PAGE (default {DOCS_PAGE.relative_to(PROJECT_ROOT)})",
    )
    args = parser.parse_args(argv)

    section = build_report(args.export_dir, args.weftid_version or weftid_version())
    if args.write_docs is None:
        sys.stdout.write(section)
        return 0
    page = args.write_docs.read_text()
    args.write_docs.write_text(replace_section(page, section))
    print(f"Updated {args.write_docs}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
