# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 0 | - |
| Low | 2 | Dead code, Architecture |

**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-07 (full codebase standard scan, no critical files remain)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-06 (users.py and groups.py split into packages)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## [REFACTOR] Dead code: Backwards-compat re-export in worker.py

**Found in:** `app/worker.py:32-40`
**Impact:** Low
**Category:** Dead code
**Description:** `register_handler()` is re-exported from `worker.py` with a comment saying "New code should import directly from jobs.registry." If nothing imports `register_handler` from `worker`, this wrapper is dead code.
**Suggested Refactoring:** Search for imports of `register_handler` from `worker`. If none exist, delete the re-export.
**Files Affected:** `app/worker.py`

---

## [REFACTOR] Architecture: Missing event log for export download

**Found in:** `app/services/exports.py:91`
**Impact:** Low
**Category:** Architecture
**Description:** The `get_download()` function calls `database.export_files.mark_downloaded()` which updates `downloaded_at` in the database but does not emit a `log_event()`. The comment says "activity already logged above" but `track_activity` tracks user presence, not audit events. All other write operations in the codebase have corresponding event logs.
**Why It Matters:** If export download tracking is important for audit compliance, this is a gap. If it is purely informational, this can be accepted.
**Suggested Refactoring:** Add a `log_event()` call with event type `export_downloaded`, or document this as an intentional exception.
**Files Affected:** `app/services/exports.py`, potentially `app/constants/event_types.py`
