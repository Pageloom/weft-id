# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 1 | Security |
| Low | 2 | Security |

**Last security scan:** 2026-03-21 (deep: full codebase, all OWASP categories)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-21 (password templates, API/service errors, self-hosting docs)
**Last security scan:** 2026-03-21 (weftid management script PR review)

---

## [SECURITY] Imprecise Docker volume matching in weftid script

**Found in:** `weftid:491`, `weftid:286`, `weftid:527`
**Severity:** Medium
**OWASP Category:** A05:2021 - Security Misconfiguration
**Description:** The script uses `docker volume ls -q | grep dbdata` and `grep storage` to find Docker volumes. Docker Compose prefixes volume names with the project name (directory name), so `grep dbdata` can match volumes from other projects (e.g., `other-project_dbdata`).
**Attack Scenario:** On a host running multiple compose projects, rollback could delete the wrong database volume, or backup/restore could target wrong storage. Not a remote attack vector, but a dangerous operational error.
**Impact:** Data loss from deleting or overwriting the wrong Docker volume.
**Remediation:** Scope volume lookup to the current compose project. Use `docker volume ls -q --filter "name=$(basename "$(pwd)")_dbdata"` or `docker compose config --volumes` to resolve the correct volume name.

---

## [SECURITY] sed injection from version strings in weftid script

**Found in:** `weftid:368`, `weftid:499`
**Severity:** Low
**OWASP Category:** A03:2021 - Injection
**Description:** User-provided version strings are interpolated into `sed` replacement expressions without escaping. Characters like `/`, `&`, or `\` in the version string can break the sed command or corrupt `.env`. In `cmd_upgrade`, the GitHub API check provides implicit validation, but in `cmd_rollback`, `$previous` comes from `.previous_versions` which could be manually edited.
**Impact:** `.env` file corruption. Not exploitable remotely (local admin tool), but could leave the system in an inconsistent state.
**Remediation:** Add a version format check before use: `case "$target" in *[!0-9.]*) die "Version must contain only digits and dots" ;; esac`

---

## [SECURITY] Backup files written with default permissions

**Found in:** `weftid:277-298`
**Severity:** Low
**OWASP Category:** A01:2021 - Broken Access Control
**Description:** Database dumps contain password hashes, session data, audit logs, and PII. They are written to the working directory with default `umask` permissions (typically `644`, world-readable on multi-user systems).
**Impact:** On a shared host, other users could read database dumps containing sensitive data.
**Remediation:** Set `umask 077` before writing backup files so they are created with `600` permissions (owner-only).

---

