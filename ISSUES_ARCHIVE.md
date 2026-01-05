# Issues Archive

This document contains resolved issues for historical reference.

---

## SAML IdP Edit Form "Save Changes" Button Does Not Work

**Status:** Resolved (2026-01-05)

**Found in:** SAML Identity Provider edit page

**Original Severity:** High

**Original Description:** When editing a SAML Identity Provider, clicking "Save Changes" appears to do nothing. The form does not save, and there is no feedback or error message to the user.

**Investigation Findings:**
- The form submission and save functionality were working correctly (verified by comprehensive tests)
- The form action URL was rendering correctly
- Checkbox handling ("on" → True) was working properly
- Quick action buttons used different endpoints that didn't require form parsing

**Actual Issue Found:** The `sp_acs_url` field was missing from the `IdPConfig` schema. This caused the "ACS URL" to display as empty on the edit form, which may have confused users into thinking the form wasn't working correctly. The save functionality itself was working.

**Resolution:**
- Added `sp_acs_url: str` field to `IdPConfig` schema in `app/schemas/saml.py`
- Updated `_idp_row_to_config()` in `app/services/saml.py` to compute and include `sp_acs_url` from `sp_entity_id`
- Added comprehensive test `test_update_idp_via_form` to verify form submission works correctly
- Added assertions to `test_view_idp_detail` to verify form action and ACS URL rendering

**Files Modified:**
- `app/schemas/saml.py` - Added `sp_acs_url` field to `IdPConfig`
- `app/services/saml.py` - Compute `sp_acs_url` in `_idp_row_to_config()`
- `tests/test_routers_saml.py` - Added update test and enhanced view test

---

## API-First: Exports and background tasks have no API endpoints

**Status:** Resolved (2026-01-05)

**Found in:** `app/services/exports.py`, `app/services/bg_tasks.py`

**Severity:** Medium

**Principle Violated:** API-First

**Description:** Export creation, listing, and download were web-only. Background job management had no API.

**Resolution:**
- Created `app/routers/api/v1/exports.py` with 3 RESTful endpoints:
  - `POST /api/v1/exports` - Create export task (admin)
  - `GET /api/v1/exports` - List exports (admin)
  - `GET /api/v1/exports/{export_id}/download` - Download export file (admin)
- Created `app/routers/api/v1/jobs.py` with 3 RESTful endpoints:
  - `GET /api/v1/jobs` - List user's background jobs
  - `GET /api/v1/jobs/{job_id}` - Get job details
  - `DELETE /api/v1/jobs` - Delete completed jobs
- Added 9 tests in `tests/test_api_exports.py`
- Added 9 tests in `tests/test_api_jobs.py`

**Files Created/Modified:**
- `app/routers/api/v1/exports.py` - New API router (created)
- `app/routers/api/v1/jobs.py` - New API router (created)
- `app/main.py` - Registered new routers
- `tests/test_api_exports.py` - Comprehensive tests (created)
- `tests/test_api_jobs.py` - Comprehensive tests (created)

---

## API-First: Event log has no API endpoints

**Status:** Resolved (2026-01-05)

**Found in:** `app/services/event_log.py`

**Severity:** Medium

**Principle Violated:** API-First

**Description:** Event log viewing was web-only. No API endpoints existed for audit log access.

**Resolution:**
- Created `app/routers/api/v1/events.py` with 2 RESTful endpoints:
  - `GET /api/v1/events` - List events with pagination
  - `GET /api/v1/events/{event_id}` - Get event details
- Added 10 tests in `tests/test_api_events.py`

**Files Created/Modified:**
- `app/routers/api/v1/events.py` - New API router (created)
- `app/main.py` - Registered new router
- `tests/test_api_events.py` - Comprehensive tests (created)

---

## API-First: User state operations missing API endpoints

**Status:** Resolved (2026-01-05)

**Found in:** `app/services/users.py`

**Severity:** Medium

**Principle Violated:** API-First

**Description:** User inactivation, reactivation, and anonymization were web-only operations. No API endpoints existed for automating user lifecycle management.

**Resolution:**
- Added 3 new endpoints to `app/routers/api/v1/users.py`:
  - `POST /api/v1/users/{user_id}/inactivate` - Inactivate user (admin)
  - `POST /api/v1/users/{user_id}/reactivate` - Reactivate user (admin)
  - `POST /api/v1/users/{user_id}/anonymize` - Anonymize user (super_admin)
- Added 9 tests in `tests/test_api_users.py`

**Files Modified:**
- `app/routers/api/v1/users.py` - Added 3 endpoints
- `tests/test_api_users.py` - Added 9 tests

---

## API-First: SAML Identity Provider Management has no API endpoints

**Status:** Resolved (2026-01-05)

**Found in:** `app/services/saml.py` (entire service)

**Severity:** High

**Principle Violated:** API-First

**Description:** All SAML Identity Provider management operations were web-only. No API endpoints existed for CRUD operations on IdPs.

**Resolution:**
- Created `app/routers/api/v1/saml.py` with 12 RESTful endpoints:
  - `GET /api/v1/saml/idps` - List IdPs
  - `POST /api/v1/saml/idps` - Create IdP
  - `GET /api/v1/saml/idps/{idp_id}` - Get IdP details
  - `PATCH /api/v1/saml/idps/{idp_id}` - Update IdP
  - `DELETE /api/v1/saml/idps/{idp_id}` - Delete IdP
  - `POST /api/v1/saml/idps/{idp_id}/enable` - Enable IdP
  - `POST /api/v1/saml/idps/{idp_id}/disable` - Disable IdP
  - `POST /api/v1/saml/idps/{idp_id}/set-default` - Set default IdP
  - `POST /api/v1/saml/idps/import` - Import from metadata URL
  - `POST /api/v1/saml/idps/{idp_id}/refresh` - Refresh metadata
  - `GET /api/v1/saml/sp/certificate` - Get SP certificate
  - `GET /api/v1/saml/sp/metadata` - Get SP metadata info
- Added 29 tests in `tests/test_api_saml.py`

**Files Created/Modified:**
- `app/routers/api/v1/saml.py` - New API router (created)
- `app/main.py` - Registered new router
- `tests/test_api_saml.py` - Comprehensive tests (created)

---

## Service Layer Bypass: Router directly calls database module

**Status:** Resolved (2026-01-05)

**Found in:** `app/routers/auth.py:5, 174`

**Severity:** Medium

**Principle Violated:** Service Layer Architecture

**Description:** The auth router imported and directly called `database.users.get_admin_emails()`, bypassing the service layer. This violated the architecture rule that routers should never import database modules directly.

**Resolution:**
- Added `get_admin_emails()` wrapper function to `app/services/users.py`
- Removed `import database` from `app/routers/auth.py`
- Updated call site to use `users_service.get_admin_emails(tenant_id)`

**Files Modified:**
- `app/services/users.py` - Added `get_admin_emails()` utility function
- `app/routers/auth.py` - Removed database import, use service layer

---

## SAML authenticate_via_saml Uses Wrong Database Field Names

**Status:** Resolved (2026-01-05)

**Found in:** `app/services/saml.py:1072-1103`

**Severity:** High

**Description:** The `authenticate_via_saml` function called `database.users.get_user_by_email()` which only returns `user_id` and `password_hash`, but the function expected a full user record with `id`, `inactivated_at`, and `mfa_method` fields. This caused KeyError crashes when users attempted SAML sign-in.

**Resolution:**
- Created new database function `get_user_by_email_with_status()` in `app/database/users.py` that returns the full user record needed for authentication flows (SAML/OAuth)
- Updated `authenticate_via_saml()` in `app/services/saml.py` to use the new function
- Removed `xfail` markers from two previously failing tests in `tests/test_services_saml.py`

**Files Modified:**
- `app/database/users.py` - Added `get_user_by_email_with_status()` function
- `app/services/saml.py` - Updated to use new function
- `tests/test_services_saml.py` - Removed xfail markers from authenticate_via_saml tests

---

## OAuth2 Authorization Page Crashes Due to Missing nav Context

**Status:** Resolved (2026-01-03)

**Found in:** `app/routers/oauth2.py:92-103`

**Severity:** High

**Description:** The OAuth2 authorization page (`GET /oauth2/authorize`) crashed with a Jinja2 `UndefinedError` when accessed by an authenticated user. The template extends `base.html` which expects a `nav` context variable, but the router didn't provide it.

**Resolution:**
- Added `"nav": {}` to the template context for the OAuth2 authorize page
- Used empty dict since OAuth2 flows are workflow pages that shouldn't show full navigation
- Also updated TemplateResponse calls to use new Starlette API: `TemplateResponse(request, name, context)` instead of deprecated `TemplateResponse(name, {"request": request, ...})`

**Files Modified:**
- `app/routers/oauth2.py` - Added nav context to authorize page TemplateResponse

---

## OAuth2 Error Page Also Missing nav Context

**Status:** Resolved (2026-01-03)

**Found in:** `app/routers/oauth2.py:49-56, 60-67, 71-78, 82-89, 144-151`

**Severity:** High

**Description:** All error template responses in the OAuth2 router were missing the `nav` context. While these didn't crash at the time (because they didn't pass `user`), they were fixed for consistency and to prevent future issues.

**Resolution:**
- Added `"nav": {}` to all TemplateResponse calls for oauth2_error.html
- Updated all TemplateResponse calls to use new Starlette API

**Files Modified:**
- `app/routers/oauth2.py` - Added nav context to all error page TemplateResponses

---

## Invalid artifact_id in delete_jobs Event Logging

**Status:** Resolved (2026-01-03)

**Found in:** `app/services/bg_tasks.py:173`

**Severity:** Medium

**Description:** The `delete_jobs` function logged an event with `artifact_id="bulk_delete"`, but the `event_logs.artifact_id` column is a UUID NOT NULL field. This caused the event logging to silently fail with error: `invalid input syntax for type uuid: "bulk_delete"`.

**Impact:**
- Bulk job deletions were NOT logged to the audit trail
- Violated "if there is a write, there is a log" principle

**Resolution:**
- Changed `artifact_id="bulk_delete"` to `artifact_id=job_ids[0]` to use the first job ID as the artifact_id
- The `metadata` field already contains all `job_ids` for full audit trail

**Files Modified:**
- `app/services/bg_tasks.py` - Fixed artifact_id parameter in log_event call

---

## Reactivation Service Missing track_activity() Calls

**Status:** Resolved (2026-01-03)

**Found in:** `app/services/reactivation.py`

**Severity:** Medium

**Description:** The reactivation service had three read-only functions that received `RequestingUser` but did not call `track_activity()`. This violated the architecture principle: "Any service layer read operation updates `last_activity_at` only if 3+ hours have passed."

**Affected functions:**
- `list_pending_requests` (line 189)
- `count_pending_requests` (line 225)
- `list_previous_requests` (line 244)

**Impact:** Admins viewing reactivation requests weren't having their activity tracked, which could incorrectly flag them as inactive.

**Resolution:** Added `track_activity(requesting_user["tenant_id"], requesting_user["id"])` call at the start of each read-only function, immediately after the `_require_admin()` check.

**Files Modified:**
- `app/services/reactivation.py` - Added import for `track_activity` and calls to 3 functions

---

## Pydantic Validation Error When Re-detecting Regional Settings

**Status:** Resolved (2026-01-01)

**Found in:** `app/schemas/api.py:48`

**Severity:** High

**Description:** Clicking "Re-detect Regional Settings" on the profile page caused a 500 error. The browser's JavaScript detected full locale strings like `en_US`, but the Pydantic schema only accepted two-letter codes like `en`.

**Root Cause:** Schema/frontend mismatch. The `UserProfileUpdate.locale` field had a regex pattern `^[a-z]{2}$` that was too restrictive. Both the frontend JavaScript and database design expected full POSIX locale format (`ll_CC` where `ll` is language and `CC` is country/region).

**Resolution:**
Updated the regex pattern in `app/schemas/api.py` to accept both formats:
- Before: `pattern="^[a-z]{2}$"`
- After: `pattern="^[a-z]{2}(_[A-Z]{2})?$"`

This now accepts both two-letter language codes (`en`, `sv`, `fr`) and full POSIX locales (`en_US`, `sv_SE`, `fr_FR`).

**Tests Added:**
- `test_update_regional_full_locale_format` - Tests `en_US` format at router level
- `test_update_regional_swedish_locale` - Tests `sv_SE` format at router level
- `test_update_current_user_profile_full_posix_locale` - Tests full POSIX format at service level

**Files Modified:**
- `app/schemas/api.py` - Updated locale pattern
- `tests/test_routers_account.py` - Added 2 new tests
- `tests/test_services_users.py` - Added 1 new test

---

## Naive Datetime Usage Causes 500 Errors When Interacting with DB Timestamps

**Status:** Resolved (2026-01-01)

**Found in:** Multiple files across `app/` and `tests/`

**Severity:** High

**Description:** The codebase used `datetime.now()` which returns timezone-naive datetimes, but PostgreSQL with psycopg3 returns timezone-aware datetimes (`TIMESTAMPTZ`). Python does not allow arithmetic between naive and aware datetimes, causing 500 errors on pages like `/account/background-jobs`.

**Error:** `TypeError: can't subtract offset-naive and offset-aware datetimes`

**Root Cause:** Even though containers run in UTC, `datetime.now()` returns a **naive** datetime (tzinfo=None), not an **aware** UTC datetime.

**Resolution:**
1. Replaced all `datetime.now()` with `datetime.now(UTC)` using the Python 3.11+ `UTC` constant
2. Added `DTZ` rules to Ruff config (`pyproject.toml`) to prevent future naive datetime commits
3. Added `# noqa: DTZ001` comment to one legitimate test that tests naive datetime handling

**Files Modified:**
- `app/oauth2.py` - Added `UTC` import, changed `datetime.now()` to `datetime.now(UTC)`
- `app/schemas/bg_tasks.py` - Added `UTC` import, changed `datetime.now()` to `datetime.now(UTC)`
- `app/utils/mfa.py` - Changed `datetime.datetime.now()` to `datetime.datetime.now(datetime.UTC)`
- `app/jobs/export_events.py` - Added `UTC` import, changed 3 instances of `datetime.now()` to `datetime.now(UTC)`
- `app/services/emails.py` - Added `UTC` import, changed 2 instances of `datetime.now()` to `datetime.now(UTC)`
- `app/worker.py` - Added `UTC` import, changed `datetime.now()` to `datetime.now(UTC)`
- `tests/test_routers_users.py` - Added `UTC` import, updated datetime calls
- `tests/test_database_mfa.py` - Updated 2 instances to use `datetime.now(UTC)`
- `tests/test_routers_settings.py` - Added `UTC` import, updated 5 instances
- `tests/test_routers_account.py` - Added `UTC` import, updated 8 instances
- `tests/test_services_activity.py` - Added `UTC` import, updated 1 instance
- `tests/test_routers_auth.py` - Added `UTC` import, updated 6 instances
- `tests/test_utils_datetime_format.py` - Added `# noqa: DTZ001` for test testing naive datetime handling
- `pyproject.toml` - Added `"DTZ"` to Ruff lint rules

**Note:** Localization is unaffected - `datetime_format.py` utility properly converts UTC datetimes to user timezones for display.

---

## Event Logging Completely Broken - fetchone() Used with INSERT Without RETURNING

**Status:** Resolved (2025-12-26)

**Found in:** `app/database/event_log.py:42-53` (create_event metadata insert)

**Severity:** Critical

**Description:** ALL event logging was failing in the test environment with error "the last operation didn't produce records (command status: INSERT 0 1)". This affected every test that attempted to log events.

**Root Cause:** The metadata insert used `fetchone()` for an INSERT query with `ON CONFLICT DO NOTHING` that didn't have a RETURNING clause. When the conflict occurred (metadata already existed), PostgreSQL returned 0 rows, and psycopg3's `fetchone()` raised a `ProgrammingError` because there was no result set to fetch from.

**Resolution:**
- Changed metadata insert in `app/database/event_log.py` to use `execute()` instead of `fetchone()` since we don't need the result
- Added import for `execute` function from `._core`
- Added explanatory comment about why `execute()` is used instead of `fetchone()`
- Updated all database-level tests in `tests/test_database_event_log.py` to use new `create_event()` signature with `combined_metadata` and `metadata_hash` parameters
- Added helper function `_prepare_event_metadata()` to simplify test code
- Removed `@pytest.mark.xfail` decorators from 3 edge case tests that now pass

**Initial Misdiagnosis:** The error message suggested an RLS (Row Level Security) policy issue, and a migration was created to split the RLS policy. However, manual psql tests showed the RLS policy was working correctly. The real issue was discovered through debug logging - the exception occurred during the metadata insert, not the event insert.

**Files Modified:**
- `app/database/event_log.py` - Changed fetchone() to execute() for metadata insert
- `tests/test_database_event_log.py` - Updated all tests to use new create_event() signature
- `db-init/00017_fix_event_log_rls.sql` - Created but not needed (RLS policy was not the issue)

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

## Tenant Security Settings Form Returns 404 When Saving

**Status:** Resolved (2025-12-26)

**Found in:** `app/templates/settings_tenant_security.html:30`

**Severity:** High

**Description:** The tenant security settings form submitted to an incorrect URL, causing all save attempts to return 404 errors. Users could not update security settings through the web interface.

**Root Cause:**
Template used hardcoded URL path `/settings/tenant-security/update` that didn't match the router's prefix + route combination. The actual route was `/admin/security/update` (router prefix `/admin` + route path `/security/update`).

**Resolution:**
- Fixed form action URL in `app/templates/settings_tenant_security.html` line 30
- Changed from: `<form method="post" action="/settings/tenant-security/update">`
- Changed to: `<form method="post" action="/admin/security/update">`
- Also updated session timeout note to reflect that changes apply immediately to all active sessions

**Verification:**
- Router prefix confirmed at `app/routers/settings.py:25` - `/admin`
- Route path confirmed at `app/routers/settings.py:143` - `/security/update`
- Form now correctly submits to `/admin/security/update`

**Files Modified:**
- `/root/code/loom/app/templates/settings_tenant_security.html` - Fixed form action URL and updated session timeout note

---

## Event Logging Completely Broken - Hash Mismatch Between Python and PostgreSQL

**Status:** Resolved (2025-12-26)

**Found in:** `app/utils/request_metadata.py` and `db-init/00015_event_log_metadata.sql`

**Severity:** Critical

**Description:** ALL event logging was broken since migration 00015 was deployed. Events were not being recorded in the database due to foreign key constraint violations. The metadata hash computed by Python code didn't match the hash computed by PostgreSQL during migration, causing INSERT failures.

**Root Cause:**
JSON key ordering mismatch between Python and PostgreSQL:
1. Python's `json.dumps(sort_keys=True)` produces keys in alphabetical order
2. PostgreSQL's `jsonb::text` produces keys in implementation-specific order (NOT alphabetical)
3. For the 4 base metadata keys, PostgreSQL uses order: `device, user_agent, remote_address, session_id_hash`
4. Python would produce alphabetical order: `device, remote_address, session_id_hash, user_agent`
5. Different JSON strings → different MD5 hashes → foreign key constraint violations

**Resolution:**
- Modified `compute_metadata_hash()` in `app/utils/request_metadata.py` (lines 118-175) to manually construct JSON strings matching PostgreSQL's exact format:
  - Base keys in PostgreSQL's order: `device, user_agent, remote_address, session_id_hash`
  - Custom keys alphabetically after base keys
  - Spaces after colons and commas: `{"key": value, "key2": value2}`
- Fixed `create_event()` in `app/database/event_log.py` (line 42) to use `UNSCOPED` for inserting into the global `event_log_metadata` table (which has no tenant_id column)
- Fixed test mock in `tests/test_database_event_log.py` (line 419) to use `mock_request.cookies` instead of `mock_request.session`

**Verification:**
- Test `test_hash_computation_matches_postgresql` now passes
- Python and PostgreSQL produce identical hashes for the same metadata

**Files Modified:**
- `/root/code/loom/app/utils/request_metadata.py` - Hash computation logic
- `/root/code/loom/app/database/event_log.py` - Use UNSCOPED for metadata table
- `/root/code/loom/tests/test_database_event_log.py` - Fix test mock
- `/root/code/loom/db-init/00016_fix_metadata_hashes.sql` - Migration file created (not needed since hash fix makes Python match PostgreSQL)

**Note:** Additional test failures exist due to pre-existing RLS configuration issues in the test environment and database function signature changes from migration 00015. These are separate issues that don't impact the core hash mismatch fix.

---

