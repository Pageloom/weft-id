# Issues Archive

This document contains resolved issues for historical reference.

---

## Service Read Functions Missing track_activity() Calls

**Status:** Resolved (2025-12-22)

**Found in:** `app/services/users.py`, `app/services/settings.py`, `app/services/mfa.py`, `app/services/emails.py`

**Severity:** Medium

**Description:** The backlog for User Activity Tracking states "Any service layer read operation updates `last_activity_at` only if 3+ hours have passed" and "Read operations require explicit `track_activity()` calls". However, service functions that receive `RequestingUser` and perform read operations did NOT call `track_activity()`.

**Affected functions:**
- `services/users.py`: `list_users()`, `get_user()`, `get_current_user_profile()`
- `services/settings.py`: `list_privileged_domains()`, `get_security_settings()`
- `services/mfa.py`: `get_mfa_status()`, `get_backup_codes_status()`
- `services/emails.py`: `list_user_emails()`

**Resolution:** Added `track_activity(requesting_user["tenant_id"], requesting_user["id"])` at the start of each read-only service function that receives a `RequestingUser`.

---

## Service Functions Missing Activity/Event Tracking (Backstop Test Findings)

**Status:** Resolved (2025-12-22)

**Found in:** `app/services/emails.py`, `app/services/mfa.py`

**Severity:** Low

**Description:** Two service functions with `RequestingUser` parameter were missing required tracking calls:

1. `services.emails.resend_verification()` - Read-like operation that returns email info for resending verification. Should call `track_activity()`.

2. `services.mfa.setup_totp()` - Write operation that generates and stores a new TOTP secret. Should call `log_event()`.

**Resolution:**
- Added `track_activity()` call to `resend_verification()`
- Added `log_event()` call with event_type `totp_setup_initiated` to `setup_totp()`
- Removed exemptions from backstop test `test_all_service_functions_have_activity_or_logging`

---

## Broken Password Set Link for Privileged Domain Users

**Status:** Resolved (2025-12-25)

**Found in:** `app/routers/users.py:277`

**Severity:** High

**Description:** When an admin created a new user with a privileged domain email, the welcome email contained a broken password set link that resulted in a 404 error. The URL pointed to `/password-reset?email={email}` which did not exist.

**Root Cause:** The HTML router was not updated when the password setting flow was implemented. Wrong route name (`password-reset` instead of `set-password`) and wrong parameter (`email` instead of `email_id`).

**Resolution:**
- Updated `app/routers/users.py` lines 272-280 to capture the return value from `add_verified_email_with_nonce()`
- Extract `email_id` from the returned dict
- Changed URL construction to use correct route `/set-password?email_id={email_id}`
- Added error handling for failed email creation

---

## Missing Event Logs for User Creation via HTML Router

**Status:** Resolved (2025-12-25)

**Found in:** `app/routers/users.py:257`

**Severity:** High

**Description:** When users were created via the HTML interface (`POST /users/new`), no event log was created. This violated the architecture principle "if there is a write, there is a log".

**Root Cause:** The HTML router bypassed the service layer architecture by calling `create_user_raw()` (a low-level utility) instead of the proper service function `create_user()`.

**Resolution (Option B - Proper Architecture Fix):**
- Refactored `create_user()` service function in `app/services/users.py` to add optional `auto_create_email: bool = True` parameter
- Wrapped email creation logic (lines 519-526) in `if auto_create_email:` conditional
- Updated HTML router in `app/routers/users.py` to:
  - Build `RequestingUser` dict from session user
  - Call `create_user()` with `auto_create_email=False`
  - Handle email creation separately based on domain privilege
- Event logs are now automatically created by the service layer
- Maintains proper architectural boundaries (no logs in routers)
- Updated tests to mock `create_user()` instead of `create_user_raw()`

---

## Inconsistent Role Escalation Authorization in update_user

**Status:** Resolved (2025-12-25)

**Found in:** `app/services/users.py:552-667` (update_user function)

**Severity:** Medium

**Description:** The `update_user` function allowed regular admins to promote users to admin role, but the `create_user` function required super_admin role to create admin users. This was an architectural inconsistency that created a security bypass.

**Root Cause:** The authorization check in `update_user` only considered super_admin role changes, not admin role changes.

**Resolution:**
- Changed line 595 in `app/services/users.py` from checking only `super_admin` to checking both `admin` and `super_admin`:
  - Before: `if (new_role == "super_admin" or current_role == "super_admin")`
  - After: `if (new_role in ("admin", "super_admin") or current_role == "super_admin")`
- Updated error message to reflect the change
- Removed `@pytest.mark.xfail` from `test_update_user_role_as_admin_to_admin_forbidden` in `tests/test_services_users.py`
- Ensures only super_admins can create or promote users to admin/super_admin roles

---

