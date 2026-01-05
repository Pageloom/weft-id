# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## Service Layer Bypass: Router directly calls database module

**Found in:** `app/routers/auth.py:5, 174`
**Severity:** Medium
**Principle Violated:** Service Layer Architecture
**Description:** The auth router imports and directly calls `database.users.get_admin_emails()`, bypassing the service layer.

**Evidence:**
```python
# Line 5:
import database

# Line 174:
admin_emails = database.users.get_admin_emails(tenant_id)
```

**Impact:** Bypasses service layer patterns, inconsistent architecture, harder to maintain
**Root Cause:** Likely added during reactivation feature implementation without following layered architecture
**Suggested fix:** Add `get_admin_emails()` to `app/services/users.py` and update router to use service layer

---

