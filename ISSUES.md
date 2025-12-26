# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## Event Logging Completely Broken in Test Environment - RLS Policy Issue

**Found in:** `app/database/event_log.py:56-73` (create_event function)

**Severity:** Critical

**Description:** ALL event logging is failing in the test environment with error "the last operation didn't produce records (command status: INSERT 0 1)". This affects every test that attempts to log events, including:
- `tests/test_database_event_log.py::test_event_logging_creates_metadata_and_event`
- `tests/test_services_users.py::test_create_user_emits_event_log`
- New integration tests for user creation event logging

**Evidence:**
- Running `poetry run pytest tests/test_services_users.py::test_create_user_emits_event_log -v` produces:
  ```
  ERROR    services.event_log:event_log.py:107 Failed to log event: the last operation didn't produce records (command status: INSERT 0 1)
  ```
- The INSERT statement executes (command status shows "1" command executed)
- But 0 rows are returned by the RETURNING clause
- No rows appear in event_logs table after the INSERT

**Impact:**
- Event logging is silently failing in the test environment
- All tests expecting event logs to be created are failing
- Event logging may also be broken in production if the root cause is not test-specific
- Audit trail is not being created, which is a compliance violation

**Root Cause:**
The error "INSERT 0 1" indicates the INSERT command succeeded but the RETURNING clause returned no rows. This is typically caused by:

1. **RLS (Row Level Security) policy issue** - Most likely cause:
   - The event_logs table has RLS enabled
   - Tests run as 'appuser' (non-superuser) to enforce RLS
   - The RLS policy may be preventing the RETURNING clause from returning the inserted row
   - The policy might allow INSERT but not SELECT on the newly inserted row

2. **Missing app.tenant_id context** - Tests may not be setting the PostgreSQL session variable `app.tenant_id` correctly before the INSERT

3. **Foreign key constraint violation being silently ignored** - The metadata_hash FK might be failing

**Suggested fix:**

**Option A: Investigate and fix RLS policy (Recommended)**
1. Check the RLS policy on event_logs table in `/root/code/loom/db-init/00011_event_log.sql`
2. Verify the policy allows both INSERT and SELECT for the same tenant
3. Add explicit test to verify app.tenant_id is set correctly in test environment
4. Ensure the RETURNING clause respects RLS policies correctly
5. Files to check:
   - `/root/code/loom/db-init/00011_event_log.sql` - RLS policy definition
   - `/root/code/loom/app/database/_core.py` - How tenant_id is set in execute/fetchone
   - `/root/code/loom/app/database/event_log.py:56-73` - create_event function

**Option B: Debug metadata foreign key constraint**
1. Check if metadata_hash exists in event_log_metadata table before INSERT
2. Verify the metadata INSERT (line 42-53) is succeeding
3. Add logging to see if FK constraint is failing silently

**Option C: Workaround for tests (Not recommended - doesn't fix production)**
1. Use UNSCOPED for event_logs INSERTs in test environment
2. This would make tests pass but wouldn't fix the underlying RLS issue

**Files Modified:**
- None yet - issue discovered during test development

**Next Steps:**
1. Investigate RLS policies on event_logs table
2. Add debugging to determine exact cause of INSERT returning 0 rows
3. Fix the root cause (likely RLS policy)
4. Verify all event logging tests pass after fix
5. Test in production-like environment to ensure fix doesn't break production

---

