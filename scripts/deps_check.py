#!/usr/bin/env python3
"""
Dependency security scanning script for vulnerability assessment.

This script checks project dependencies against the OSV (Open Source Vulnerabilities)
database to identify known security vulnerabilities.

Usage:
    python scripts/deps_check.py [--json] [--include-dev] [--package PACKAGE]

Options:
    --json          Output results as JSON
    --include-dev   Include dev dependencies in scan (default: production only)
    --package NAME  Scan only a specific package

Output:
    By default, outputs human-readable text. Use --json for machine-readable JSON output.
    Exit code 1 if critical/high severity vulnerabilities found, 0 otherwise.
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Vulnerability:
    """Represents a security vulnerability in a dependency."""

    package: str
    installed_version: str
    vulnerability_id: str  # CVE or GHSA ID
    severity: str  # critical, high, medium, low, unknown
    description: str
    fixed_version: str | None
    advisory_url: str | None
    aliases: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "installed_version": self.installed_version,
            "vulnerability_id": self.vulnerability_id,
            "severity": self.severity,
            "description": self.description,
            "fixed_version": self.fixed_version,
            "advisory_url": self.advisory_url,
            "aliases": self.aliases,
        }


@dataclass
class DependencyInfo:
    """Information about a single dependency."""

    name: str
    version_constraint: str
    locked_version: str | None
    is_dev: bool
    is_direct: bool  # Direct dependency vs transitive


@dataclass
class SecurityReport:
    """Dependency security scan results."""

    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    packages_scanned: int = 0
    scan_errors: list[str] = field(default_factory=list)

    def add(self, vuln: Vulnerability) -> None:
        self.vulnerabilities.append(vuln)

    def to_dict(self) -> dict[str, Any]:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for v in self.vulnerabilities:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1

        return {
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "unknown": severity_counts["unknown"],
                "packages_scanned": self.packages_scanned,
                "scan_errors": self.scan_errors,
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent


def parse_pyproject_toml() -> tuple[list[DependencyInfo], list[DependencyInfo]]:
    """
    Parse pyproject.toml to extract dependencies.

    Returns:
        Tuple of (production_deps, dev_deps)
    """
    pyproject_path = get_project_root() / "pyproject.toml"
    if not pyproject_path.exists():
        return [], []

    content = pyproject_path.read_text()

    prod_deps: list[DependencyInfo] = []
    dev_deps: list[DependencyInfo] = []

    # Simple TOML parsing for dependencies section
    # Match patterns like: package = "^1.2.3" or package = {version = "^1.2.3", ...}
    in_deps = False
    in_dev_deps = False

    for line in content.splitlines():
        line = line.strip()

        if line == "[tool.poetry.dependencies]":
            in_deps = True
            in_dev_deps = False
            continue
        elif line == "[tool.poetry.group.dev.dependencies]":
            in_deps = False
            in_dev_deps = True
            continue
        elif line.startswith("["):
            in_deps = False
            in_dev_deps = False
            continue

        if not (in_deps or in_dev_deps):
            continue

        # Skip python version constraint
        if line.startswith("python ="):
            continue

        # Parse dependency line
        match = re.match(r"^([a-zA-Z0-9_-]+)\s*=\s*(.+)$", line)
        if match:
            name = match.group(1)
            value = match.group(2).strip()

            # Extract version from simple string or dict
            version = "unknown"
            if value.startswith('"'):
                # Simple version string: package = "^1.2.3"
                version = value.strip('"')
            elif value.startswith("{"):
                # Dict format: package = {version = "^1.2.3", ...}
                version_match = re.search(r'version\s*=\s*"([^"]+)"', value)
                if version_match:
                    version = version_match.group(1)

            dep = DependencyInfo(
                name=name,
                version_constraint=version,
                locked_version=None,
                is_dev=in_dev_deps,
                is_direct=True,
            )

            if in_dev_deps:
                dev_deps.append(dep)
            else:
                prod_deps.append(dep)

    return prod_deps, dev_deps


def parse_poetry_lock() -> dict[str, str]:
    """
    Parse poetry.lock to get exact installed versions.

    Returns:
        Dict mapping package name to installed version.
    """
    lock_path = get_project_root() / "poetry.lock"
    if not lock_path.exists():
        return {}

    content = lock_path.read_text()
    versions: dict[str, str] = {}

    # Parse TOML-style lock file
    current_package = None
    for line in content.splitlines():
        line = line.strip()

        if line == "[[package]]":
            current_package = None
            continue

        if current_package is None:
            name_match = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if name_match:
                current_package = name_match.group(1)
        else:
            version_match = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if version_match:
                versions[current_package] = version_match.group(1)
                current_package = None

    return versions


def find_pip_audit() -> list[str] | None:
    """
    Find pip-audit command, trying multiple locations.

    Returns:
        Command list to run pip-audit, or None if not found.
    """
    # Try 1: Direct pip-audit in PATH
    try:
        result = subprocess.run(
            ["pip-audit", "--version"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return ["pip-audit"]
    except FileNotFoundError:
        pass

    # Try 2: Poetry venv's pip-audit
    venv_path = get_project_root() / ".venv"
    if venv_path.exists():
        venv_pip_audit = venv_path / "bin" / "pip-audit"
        if venv_pip_audit.exists():
            try:
                result = subprocess.run(
                    [str(venv_pip_audit), "--version"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    return [str(venv_pip_audit)]
            except FileNotFoundError:
                pass

    # Try 3: poetry run pip-audit
    try:
        result = subprocess.run(
            ["poetry", "run", "pip-audit", "--version"],
            capture_output=True,
            text=True,
            cwd=get_project_root(),
        )
        if result.returncode == 0:
            return ["poetry", "run", "pip-audit"]
    except FileNotFoundError:
        pass

    return None


def run_pip_audit(include_dev: bool = False) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Run pip-audit to check for vulnerabilities.

    Returns:
        Tuple of (vulnerabilities, errors)
    """
    pip_audit_cmd = find_pip_audit()
    if pip_audit_cmd is None:
        return [], ["pip-audit not found. Install with: poetry add --group dev pip-audit"]

    # Run pip-audit with JSON output
    cmd = pip_audit_cmd + [
        "--format",
        "json",
        "--progress-spinner",
        "off",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=get_project_root(),
        )

        # pip-audit returns exit code 1 if vulnerabilities found, but still outputs JSON
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                return data.get("dependencies", []), []
            except json.JSONDecodeError:
                return [], [f"Failed to parse pip-audit output: {result.stdout[:200]}"]

        if result.stderr:
            return [], [result.stderr]

        return [], []

    except subprocess.SubprocessError as e:
        return [], [f"Failed to run pip-audit: {e}"]


def query_osv_api(package: str, version: str) -> list[dict[str, Any]]:
    """
    Query the OSV API directly for vulnerabilities.

    This is a fallback if pip-audit is not available.
    """
    import urllib.error
    import urllib.request

    url = "https://api.osv.dev/v1/query"
    payload = json.dumps(
        {
            "package": {
                "name": package,
                "ecosystem": "PyPI",
            },
            "version": version,
        }
    ).encode("utf-8")

    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data.get("vulns", [])
    except (urllib.error.URLError, json.JSONDecodeError):
        return []


def map_severity(severity_data: dict[str, Any] | str | None) -> str:
    """Map OSV/pip-audit severity to our severity levels."""
    if severity_data is None:
        return "unknown"

    if isinstance(severity_data, str):
        severity_data = {"type": "UNKNOWN", "score": severity_data}

    # Handle CVSS score
    score_str = severity_data.get("score", "")
    if score_str:
        try:
            # CVSS v3 format: "CVSS:3.1/AV:N/AC:L/..."
            if isinstance(score_str, str) and "/" in score_str:
                # Extract base score if available
                pass
            else:
                score = float(score_str)
                if score >= 9.0:
                    return "critical"
                elif score >= 7.0:
                    return "high"
                elif score >= 4.0:
                    return "medium"
                elif score > 0:
                    return "low"
        except (ValueError, TypeError):
            pass

    # Map text severity
    severity_type = str(severity_data.get("type", "")).upper()
    if "CRITICAL" in severity_type:
        return "critical"
    elif "HIGH" in severity_type:
        return "high"
    elif "MEDIUM" in severity_type or "MODERATE" in severity_type:
        return "medium"
    elif "LOW" in severity_type:
        return "low"

    return "unknown"


def scan_with_pip_audit(
    report: SecurityReport,
    prod_deps: list[DependencyInfo],
    dev_deps: list[DependencyInfo],
    include_dev: bool,
) -> None:
    """Scan dependencies using pip-audit."""
    vulns, errors = run_pip_audit(include_dev)
    report.scan_errors.extend(errors)

    for vuln_data in vulns:
        if isinstance(vuln_data, dict):
            pkg_name = vuln_data.get("name", "")
            pkg_version = vuln_data.get("version", "")
            pkg_vulns = vuln_data.get("vulns", [])

            for v in pkg_vulns:
                vuln_id = v.get("id", "UNKNOWN")
                fixed = v.get("fix_versions", [])
                fixed_version = fixed[0] if fixed else None

                # Try to get description
                description = v.get("description", "")
                if not description:
                    description = f"Vulnerability {vuln_id} in {pkg_name}"

                # Get aliases (CVE IDs, etc.)
                aliases = v.get("aliases", [])

                # Determine severity
                severity = map_severity(v.get("severity"))

                report.add(
                    Vulnerability(
                        package=pkg_name,
                        installed_version=pkg_version,
                        vulnerability_id=vuln_id,
                        severity=severity,
                        description=description[:500],  # Truncate long descriptions
                        fixed_version=fixed_version,
                        advisory_url=f"https://osv.dev/vulnerability/{vuln_id}",
                        aliases=aliases,
                    )
                )


def scan_with_osv_api(
    report: SecurityReport,
    prod_deps: list[DependencyInfo],
    dev_deps: list[DependencyInfo],
    include_dev: bool,
    locked_versions: dict[str, str],
) -> None:
    """Scan dependencies using the OSV API directly."""
    deps_to_scan = list(prod_deps)
    if include_dev:
        deps_to_scan.extend(dev_deps)

    for dep in deps_to_scan:
        version = locked_versions.get(dep.name) or dep.version_constraint.lstrip("^~>=<")
        report.packages_scanned += 1

        vulns = query_osv_api(dep.name, version)

        for v in vulns:
            vuln_id = v.get("id", "UNKNOWN")

            # Get fixed version from affected ranges
            fixed_version = None
            for affected in v.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            break

            # Get severity
            severity = "unknown"
            for sev in v.get("severity", []):
                severity = map_severity(sev)
                if severity != "unknown":
                    break

            # Get aliases
            aliases = v.get("aliases", [])

            report.add(
                Vulnerability(
                    package=dep.name,
                    installed_version=version,
                    vulnerability_id=vuln_id,
                    severity=severity,
                    description=v.get("summary", v.get("details", ""))[:500],
                    fixed_version=fixed_version,
                    advisory_url=f"https://osv.dev/vulnerability/{vuln_id}",
                    aliases=aliases,
                )
            )


def run_security_scan(
    include_dev: bool = False,
    package: str | None = None,
) -> SecurityReport:
    """
    Run security scan on project dependencies.

    Args:
        include_dev: Whether to include dev dependencies
        package: Optional specific package to scan

    Returns:
        SecurityReport with all vulnerabilities found.
    """
    report = SecurityReport()

    # Parse dependencies
    prod_deps, dev_deps = parse_pyproject_toml()
    locked_versions = parse_poetry_lock()

    # Update deps with locked versions
    for dep in prod_deps + dev_deps:
        dep.locked_version = locked_versions.get(dep.name)

    # Filter to specific package if requested
    if package:
        prod_deps = [d for d in prod_deps if d.name.lower() == package.lower()]
        dev_deps = [d for d in dev_deps if d.name.lower() == package.lower()]

    report.packages_scanned = len(prod_deps) + (len(dev_deps) if include_dev else 0)

    # Try pip-audit first, fall back to OSV API
    scan_with_pip_audit(report, prod_deps, dev_deps, include_dev)

    # If pip-audit failed, use OSV API directly
    if report.scan_errors and "not installed" in report.scan_errors[0]:
        report.scan_errors = []  # Clear the pip-audit error
        scan_with_osv_api(report, prod_deps, dev_deps, include_dev, locked_versions)

    return report


def format_report_text(report: SecurityReport) -> str:
    """Format the security report as human-readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append("DEPENDENCY SECURITY SCAN REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Packages scanned: {report.packages_scanned}")
    lines.append(f"Total vulnerabilities: {len(report.vulnerabilities)}")
    lines.append("")

    if report.scan_errors:
        lines.append("SCAN ERRORS:")
        for error in report.scan_errors:
            lines.append(f"  - {error}")
        lines.append("")

    # Group by severity
    by_severity: dict[str, list[Vulnerability]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "unknown": [],
    }
    for v in report.vulnerabilities:
        by_severity[v.severity].append(v)

    # Summary
    lines.append("SEVERITY SUMMARY:")
    lines.append(f"  Critical: {len(by_severity['critical'])}")
    lines.append(f"  High:     {len(by_severity['high'])}")
    lines.append(f"  Medium:   {len(by_severity['medium'])}")
    lines.append(f"  Low:      {len(by_severity['low'])}")
    lines.append(f"  Unknown:  {len(by_severity['unknown'])}")
    lines.append("")

    if not report.vulnerabilities:
        lines.append("No vulnerabilities found.")
    else:
        for severity in ["critical", "high", "medium", "low", "unknown"]:
            vulns = by_severity[severity]
            if not vulns:
                continue

            lines.append("-" * 70)
            lines.append(f"SEVERITY: {severity.upper()}")
            lines.append(f"Count: {len(vulns)}")
            lines.append("-" * 70)
            lines.append("")

            for v in vulns:
                lines.append(f"  [{v.vulnerability_id}] {v.package} @ {v.installed_version}")
                if v.aliases:
                    lines.append(f"  Aliases: {', '.join(v.aliases)}")
                lines.append(f"  Description: {v.description[:200]}...")
                if v.fixed_version:
                    lines.append(f"  Fixed in: {v.fixed_version}")
                if v.advisory_url:
                    lines.append(f"  Advisory: {v.advisory_url}")
                lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def format_issues_md(report: SecurityReport) -> str:
    """Format vulnerabilities for ISSUES.md."""
    if not report.vulnerabilities:
        return ""

    lines = []
    for v in report.vulnerabilities:
        lines.append(f"## [DEPS] {v.package}: {v.vulnerability_id}")
        lines.append("")
        lines.append(f"**Package:** {v.package}")
        lines.append(f"**Installed Version:** {v.installed_version}")
        lines.append(f"**Fixed Version:** {v.fixed_version or 'Unknown'}")
        lines.append(f"**Severity:** {v.severity.capitalize()}")
        lines.append(f"**Advisory:** {v.advisory_url or 'N/A'}")
        if v.aliases:
            lines.append(f"**Aliases:** {', '.join(v.aliases)}")
        lines.append("")
        lines.append("**Description:**")
        lines.append(v.description)
        lines.append("")
        lines.append("**Remediation:**")
        if v.fixed_version:
            lines.append(f"- Update to version {v.fixed_version} or later")
            lines.append(f"- Run `poetry update {v.package}`")
        else:
            lines.append("- Check for updates or alternative packages")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description="Run dependency security scan on the project",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--include-dev",
        action="store_true",
        help="Include dev dependencies in scan",
    )
    parser.add_argument(
        "--package",
        type=str,
        help="Scan only a specific package",
    )
    parser.add_argument(
        "--issues-md",
        action="store_true",
        help="Output in ISSUES.md format",
    )

    args = parser.parse_args()

    report = run_security_scan(
        include_dev=args.include_dev,
        package=args.package,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    elif args.issues_md:
        output = format_issues_md(report)
        if output:
            print(output)
        else:
            print("No vulnerabilities to report.")
    else:
        print(format_report_text(report))

    # Return exit code based on critical/high severity vulnerabilities
    critical_high = len([v for v in report.vulnerabilities if v.severity in ("critical", "high")])
    return 1 if critical_high > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
