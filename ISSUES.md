# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 1 | Duplication |
| Low | 2 | Dead code, Architecture |

**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-07 (full codebase standard scan, no critical files remain)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-06 (users.py and groups.py split into packages)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## [REFACTOR] Duplication: Worker periodic task boilerplate

**Found in:** `app/worker.py:106-173`
**Impact:** Medium
**Category:** Duplication
**Description:** Three identical `_maybe_run_*` / `_run_*` method pairs follow the exact same pattern: check if enough time has elapsed since last run, then call a job function wrapped in try/except with logging. This is 68 lines that could be reduced to ~20 with a generic periodic task runner.
**Why It Matters:** Each new periodic task requires copying the same boilerplate (already happened 3 times). A generic helper would make adding future periodic tasks a one-liner.
**Suggested Refactoring:** Extract a `_run_periodic(name, last_run_attr, interval_attr, func)` method.

```python
# Before: 3x copy-pasted _maybe_run_* / _run_* pairs (68 lines)

# After:
def _run_periodic(self, name: str, job_func: Callable, last_attr: str, interval_attr: str) -> None:
    now = datetime.now(UTC)
    last = getattr(self, last_attr)
    interval = getattr(self, interval_attr)
    if last is None or now - last >= interval:
        setattr(self, last_attr, now)
        logger.info("Running %s...", name)
        try:
            result = job_func()
            logger.info("%s completed: %s", name, result)
        except Exception as e:
            logger.exception("%s failed: %s", name, e)
```

**Files Affected:** `app/worker.py`

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
