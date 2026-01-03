# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## Reactivation Service Missing track_activity() Calls

**Found in:** `app/services/reactivation.py`

**Severity:** Medium

**Description:** The reactivation service has three read-only functions that receive `RequestingUser` but do not call `track_activity()`. This violates the architecture principle: "Any service layer read operation updates `last_activity_at` only if 3+ hours have passed."

**Evidence:** The backstop test `test_all_service_functions_have_activity_or_logging` now catches these:
- `services.reactivation.count_pending_requests` (line 225)
- `services.reactivation.list_pending_requests` (line 189)
- `services.reactivation.list_previous_requests` (line 244)

**Impact:** Admins viewing reactivation requests won't have their activity tracked. This affects:
1. Last activity timestamp won't update for these operations
2. Automatic inactivation logic may incorrectly flag admins as inactive if these are their only activities

**Root Cause:** The reactivation service was added after the User Activity Tracking feature was implemented, and the `track_activity()` calls were not included in the initial implementation.

**Suggested fix:**
Add `track_activity(requesting_user["tenant_id"], requesting_user["id"])` at the start of each function, after the `_require_admin()` check:

```python
# In list_pending_requests, count_pending_requests, and list_previous_requests:
from services.activity import track_activity

def list_pending_requests(requesting_user: RequestingUser) -> list[ReactivationRequest]:
    _require_admin(requesting_user)
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    # ... rest of function
```

**Files to modify:**
- `app/services/reactivation.py` - Add track_activity import and calls to 3 functions

---

