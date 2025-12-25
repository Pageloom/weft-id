# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## Broken Password Set Link for Privileged Domain Users

**Found in:** `app/routers/users.py:277`
**Severity:** High
**Description:** When an admin creates a new user with a privileged domain email, the welcome email contains a broken password set link that results in a 404 error. The URL points to `/password-reset?email={email}` which does not exist.

**Evidence:**
- Line 277 constructs: `password_set_url = f"{request.base_url}password-reset?email={email}"`
- No route `/password-reset` exists in the codebase (verified via search)
- The actual password setting route is `/set-password` (defined in `app/routers/auth.py:129`)
- The correct route requires `email_id` parameter, not `email` address
- Email template at `app/utils/email.py:278-332` sends this broken link to users

**Impact:** Users created via privileged domains cannot activate their accounts because the password set link returns a 404 error.

**Root Cause:** The HTML router at `app/routers/users.py:214` was not updated when the password setting flow was implemented.

**Suggested fix:**
1. Change line 277 from `password-reset?email={email}` to `set-password?email_id={email_id}`
2. Capture the `email_id` from `add_verified_email_with_nonce()` return value on line 272
3. Ensure `add_verified_email_with_nonce()` returns the email ID (currently returns `dict | None` but may not include `id`)

---

## Missing Event Logs for User Creation via HTML Router

**Found in:** `app/routers/users.py:257`
**Severity:** High
**Description:** When users are created via the HTML interface (`POST /users/new`), no event log is created. This violates the architecture principle "if there is a write, there is a log" documented in BACKLOG_ARCHIVE.md.

**Evidence:**
- Line 257 calls: `users_service.create_user_raw(tenant_id, first_name, last_name, email, role)`
- `create_user_raw()` is a low-level utility at `app/services/users.py:181` that does NOT log events
- The proper service function `create_user()` at `app/services/users.py:455` DOES log events (line 537)
- Verified that no event with `event_type="user_created"` is logged when using the HTML router

**Impact:**
- No audit trail for user creation via HTML interface
- Violates compliance/audit requirements
- Inconsistent with API user creation which does log events

**Why the Backstop Test Didn't Catch It:**
The backstop test at `tests/test_services_activity.py:440` only scans service layer functions for event logging. It doesn't verify that routers are calling the correct service functions. The HTML router violated the architecture by calling a `*_raw()` utility instead of the proper service function.

**Root Cause:** The HTML router bypasses the service layer architecture by calling a low-level utility directly.

**Architectural Issue:**
The router needs to call `create_user()` for event logging, but `create_user()` automatically creates a VERIFIED email (line 516). The router requires different email handling:
- Privileged domains: verified email + welcome notification
- Non-privileged domains: unverified email + verification flow

This is why `create_user_raw()` was used - to avoid the automatic email creation.

**Suggested fix:**
**Option A (Quick fix):** Manually call `log_event()` from the router after `create_user_raw()`
- ❌ Violates architecture (routers shouldn't log events directly)
- ❌ Creates technical debt

**Option B (Proper fix):** Refactor `create_user()` service function
- Add optional parameter `auto_create_email: bool = True` to `create_user()`
- Wrap the email creation (line 516) in `if auto_create_email:` conditional
- Router calls `create_user(auto_create_email=False)` then handles emails separately
- ✅ Maintains architectural boundaries (event logging stays in service layer)
- ✅ Backward compatible (default parameter)
- ✅ Prevents future similar bugs

**Recommendation:** Use Option B to maintain proper architecture.

**Files involved:**
- `app/services/users.py:455` - Needs `auto_create_email` parameter
- `app/routers/users.py:214-291` - Needs to call proper service function
- `tests/test_routers_users_creation.py` (NEW) - Integration tests needed

---

## Inconsistent Role Escalation Authorization in update_user

**Found in:** `app/services/users.py:552-667` (update_user function)
**Severity:** Medium
**Description:** The `update_user` function allows regular admins to promote users to admin role, but the `create_user` function requires super_admin role to create admin users. This is an architectural inconsistency that creates a security bypass.

**Evidence:**
- `create_user()` at line 481-487 requires super_admin to create admin/super_admin users:
  ```python
  if user_data.role in ("admin", "super_admin") and requesting_user["role"] != "super_admin":
      raise ForbiddenError(...)
  ```
- `update_user()` at lines 589-602 only checks for super_admin role changes, NOT admin role changes:
  ```python
  if (new_role == "super_admin" or current_role == "super_admin") and requesting_user["role"] != "super_admin":
      raise ForbiddenError(...)
  ```
- Test `test_update_user_role_as_admin_to_admin_forbidden` demonstrates that an admin CAN promote a member to admin role via update_user

**Impact:**
- Security bypass: Regular admins can grant themselves escalated privileges by promoting members to admin, then having those new admins promote others
- Inconsistent authorization model between create and update operations
- Violates principle of least privilege

**Root Cause:** The authorization check in `update_user` only considers super_admin role changes, not admin role changes.

**Suggested fix:**
Change line 594-597 in `app/services/users.py` from:
```python
if (new_role == "super_admin" or current_role == "super_admin") and requesting_user["role"] != "super_admin":
```

To:
```python
if (new_role in ("admin", "super_admin") or current_role == "super_admin") and requesting_user["role"] != "super_admin":
```

This ensures that only super_admins can:
1. Create admin or super_admin users (already enforced in create_user)
2. Promote users to admin or super_admin roles (currently missing in update_user)
3. Demote super_admins (already enforced)

**Test coverage:** `tests/test_services_users.py::test_update_user_role_as_admin_to_admin_forbidden` (marked as xfail)

---

