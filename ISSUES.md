# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## BUG: Naive datetime usage causes 500 errors when interacting with DB timestamps

**Immediate symptom:** `/account/background-jobs` returns 500 error after an export job is created.

**Error:**
```
TypeError: can't subtract offset-naive and offset-aware datetimes
```

**Root Cause:**
The codebase uses `datetime.now()` which returns timezone-naive datetimes, but the database returns timezone-aware datetimes (psycopg3 + `TIMESTAMPTZ`). Python does not allow arithmetic between naive and aware datetimes.

Even though containers run in UTC, `datetime.now()` returns a **naive** datetime (tzinfo=None), not an **aware** UTC datetime.

**Affected locations in app/ (10 instances):**
| File | Line | Context |
|------|------|---------|
| `app/schemas/bg_tasks.py` | 55 | `datetime.now() - self.created_at` |
| `app/services/emails.py` | 237-238 | `verified_at=datetime.now()`, `created_at=datetime.now()` |
| `app/jobs/export_events.py` | 70, 84, 98 | datetime generation |
| `app/oauth2.py` | 153 | `datetime.now() + expiry_delta` |
| `app/utils/mfa.py` | 122 | `datetime.datetime.now() + timedelta()` |
| `app/worker.py` | 92 | `now = datetime.now()` |

**Affected locations in tests/ (~20 instances):**
- `tests/test_services_activity.py`, `tests/test_routers_users.py`, `tests/test_routers_settings.py`
- `tests/test_database_mfa.py`, `tests/test_routers_account.py`, `tests/test_routers_auth.py`

**Fix:**
1. Replace all `datetime.now()` with `datetime.now(timezone.utc)` (app) or `datetime.now(UTC)` (tests)
2. Add `DTZ` rules to Ruff config to prevent future naive datetime commits
3. Add backstop test that scans codebase for naive datetime.now() calls

**Severity:** High - causes runtime errors whenever code performs datetime arithmetic with DB values.

