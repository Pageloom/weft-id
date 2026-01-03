# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## Invalid artifact_id in delete_jobs Event Logging

**Found in:** `app/services/bg_tasks.py:173`

**Severity:** Medium

**Description:** The `delete_jobs` function logs an event with `artifact_id="bulk_delete"`, but the `event_logs.artifact_id` column is a UUID NOT NULL field. This causes the event logging to silently fail with error: `invalid input syntax for type uuid: "bulk_delete"`.

**Evidence:**
- Schema at `db-init/00011_event_log.sql:29`: `artifact_id UUID NOT NULL`
- Service code at `app/services/bg_tasks.py:173`: `artifact_id="bulk_delete"`
- Test error: `ERROR services.event_log:event_log.py:108 Failed to log event: invalid input syntax for type uuid: "bulk_delete"`

**Impact:**
- Bulk job deletions are NOT logged to the audit trail
- Violates "if there is a write, there is a log" principle
- Silent failure - no exception raised to caller

**Root Cause:** The `artifact_id` parameter accepts a string but expects a valid UUID. For bulk operations, the code incorrectly uses a descriptive string instead of a UUID.

**Suggested fix:** Use one of the job IDs as the artifact_id (e.g., the first one), or use a sentinel UUID for bulk operations. Options:

1. **Use first job ID as artifact_id** (recommended):
   ```python
   artifact_id=job_ids[0] if job_ids else None,
   ```
   Skip logging if no jobs deleted.

2. **Use sentinel UUID** for bulk operations:
   Define a `BULK_DELETE_ARTIFACT_ID` constant UUID and use it consistently.

**Files to Modify:**
- `app/services/bg_tasks.py` - Fix artifact_id parameter

---

