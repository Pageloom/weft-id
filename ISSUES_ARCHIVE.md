# Issues Archive

This document contains resolved issues for historical reference.

---

## [BUG] KeyError in list_domain_bindings Service Function

**Status:** Resolved (2026-01-17)

**Found in:** `app/services/saml.py:1598`, `app/database/saml.py:562`

**Original Severity:** High

**Original Description:** The `list_domain_bindings` service function crashed with `KeyError: 'idp_id'` when called because the database query didn't select the `idp_id` column.

**Resolution:**
- Added `db.idp_id` to the SELECT clause in `app/database/saml.py:562`
- Fixed test to use correct attribute name (`bindings.items` instead of `bindings.bindings`)
- Removed `@pytest.mark.xfail` decorator from test since bug is now fixed

**Files Modified:**
- `app/database/saml.py` - Added `db.idp_id` to SELECT clause
- `tests/test_services_saml.py` - Fixed attribute access and removed xfail marker

---

## [COMPLIANCE] Missing Route Registration in pages.py

**Status:** Resolved (2026-01-17)

**Found in:** `app/routers/saml.py:374`

**Original Severity:** Medium

**Principle Violated:** Authorization Pattern Verification (Single source of truth)

**Original Description:** The `/saml/select` route rendered a page template but was not registered in `app/pages.py`, breaking the architectural principle of having a single source of truth for page permissions.

**Resolution:**
- Added `/saml/select` page registration to `app/pages.py` after the MFA section
- Configured as PUBLIC permission with show_in_nav=False, matching other authentication flow pages

**Files Modified:**
- `app/pages.py` - Added SAML select page registration

---

## [SECURITY] Failed Login Attempts Not Logged

**Status:** Resolved (2026-01-17)

**Found in:** `app/utils/auth.py:23-68`, `app/routers/auth.py:136-162`

**Original Severity:** High

**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures

**Original Description:** Failed login attempts (invalid credentials, inactive user) returned error responses but were not logged to the event log.

**Resolution:**
- Added `log_event()` calls in `app/routers/auth.py` for failed login attempts
- Logs `login_failed` event with metadata: `email_attempted`, `failure_reason`
- Handles both `invalid_credentials` (unknown user or wrong password) and `inactivated`/`pending`/`denied` user states
- When user exists but credentials are wrong, logs with their user_id for better tracking

**Files Modified:**
- `app/routers/auth.py` - Added logging for failed login attempts
- `tests/test_routers_auth.py` - Added 3 tests for login failure logging

---

## [SECURITY] Logout Events Not Logged

**Status:** Resolved (2026-01-17)

**Found in:** `app/routers/auth.py:204-208`

**Original Severity:** Medium

**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures

**Original Description:** User logout cleared the session but did not create an audit log entry.

**Resolution:**
- Added `log_event()` call in logout handler before clearing session
- Logs `user_signed_out` event with request metadata (IP, user agent)
- Only logs when user_id exists in session (handles edge case of empty sessions)

**Files Modified:**
- `app/routers/auth.py` - Added logout event logging
- `tests/test_routers_auth.py` - Added 2 tests for logout logging

---

## [SECURITY] Password Changes Not Logged

**Status:** Resolved (2026-01-17)

**Found in:** `app/services/users.py:1128`, `app/routers/auth.py:384-439`

**Original Severity:** High

**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures

**Original Description:** Password updates via `update_password()` and the `/set-password` endpoint did not emit event logs.

**Resolution:**
- Added `log_event()` call in `/set-password` POST handler after successful password update
- Logs `password_set` event with request metadata (IP, user agent)
- Provides audit trail for initial password setting

**Files Modified:**
- `app/routers/auth.py` - Added password set event logging
- `tests/test_routers_auth.py` - Added test for password set logging

---

## [SECURITY] Authorization Failures Not Logged

**Status:** Resolved (2026-01-17)

**Found in:** `app/services/mfa.py:51-58`, `app/services/saml.py:67-74`, `app/services/users.py:607-609`

**Original Severity:** Medium

**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures

**Original Description:** When `ForbiddenError` was raised (unauthorized access attempts), no audit log was created.

**Resolution:**
- Modified `_require_admin()` and `_require_super_admin()` helper functions in `mfa.py`, `saml.py`, and `users.py` to log before raising `ForbiddenError`
- Logs `authorization_denied` event with metadata: `required_role`, `actual_role`, `service`
- Added specific logging for role change authorization failures in `update_user()` with additional metadata: `action`, `target_user_id`, `current_role`, `attempted_role`

**Files Modified:**
- `app/services/mfa.py` - Added logging to `_require_admin()`
- `app/services/saml.py` - Added logging to `_require_super_admin()`
- `app/services/users.py` - Added logging to `_require_admin()`, `_require_super_admin()`, and role change check
- `tests/test_services_event_log.py` - Added 6 tests for authorization failure logging

---

## [SECURITY] Default Secret Keys in Settings

**Status:** Resolved (2026-01-17)

**Found in:** `app/settings.py:39-48`

**Original Severity:** High

**OWASP Category:** A05:2021 - Security Misconfiguration

**Original Description:** Secret keys have insecure default values that could be used if environment variables are not set, enabling session forgery and MFA/SAML encryption compromise.

**Resolution:**
1. Added `validate_production_settings()` function in `app/settings.py` that checks all secret keys against their default values when `IS_DEV=False`
2. Function raises `RuntimeError` at startup if any secret has its default value in production
3. Validation runs at module load time in `app/main.py`, preventing the application from starting with insecure configuration
4. Added `_DEFAULT_SECRETS` dict to track known insecure default values

**Files Modified:**
- `app/settings.py` - Added `_DEFAULT_SECRETS` dict and `validate_production_settings()` function
- `app/main.py` - Added call to `validate_production_settings()` at startup
- `tests/test_settings.py` - New file with 8 tests covering all validation scenarios
- `tests/conftest.py` - Added `IS_DEV=true` to test environment

---

## [SECURITY] BYPASS_OTP Feature Risk

**Status:** Resolved (2026-01-17)

**Found in:** `app/settings.py:37`, `app/utils/mfa.py:53-55`

**Original Severity:** Medium

**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Original Description:** The `BYPASS_OTP` setting allows any 6-digit code to pass MFA verification. While intended for development, accidental production enablement would cause complete MFA bypass.

**Resolution:**
1. Extended `validate_production_settings()` function to also check `BYPASS_OTP` setting
2. Function raises `RuntimeError` at startup if `BYPASS_OTP=True` and `IS_DEV=False`
3. Warning message is still logged in dev mode as a helpful reminder
4. This ensures BYPASS_OTP can never be accidentally enabled in production

**Files Modified:**
- `app/settings.py` - Extended `validate_production_settings()` to check BYPASS_OTP
- `app/main.py` - Simplified BYPASS_OTP warning (validation handles the enforcement)
- `tests/test_settings.py` - Added test for BYPASS_OTP validation

---

## [SECURITY] Session ID Not Regenerated After Authentication

**Status:** Resolved (2026-01-08)

**Found in:** `app/routers/mfa.py:123`, `app/routers/saml.py:347`

**Original Severity:** High

**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Original Description:** After successful authentication (including MFA verification), the session ID was not regenerated. Only the `user_id` was written to the existing session, enabling session fixation attacks.

**Attack Scenario:**
1. Attacker creates session and obtains session cookie
2. Attacker tricks victim into using that session (via URL or cookie injection)
3. Victim authenticates
4. Attacker now has authenticated access via the known session

**Resolution:**
1. Created `app/utils/session.py` with `regenerate_session()` function that:
   - Clears ALL existing session data (invalidates pre-auth data)
   - Creates fresh session with only authenticated user data (user_id, session_start, _max_age)
   - With Starlette's signed cookie sessions, this effectively creates a new "session ID" since the entire signed payload changes

2. Updated authentication completion points:
   - `app/routers/mfa.py` - After MFA verification, calls `regenerate_session()` instead of directly setting session values
   - `app/routers/saml.py` - After SAML authentication (non-MFA path), calls `regenerate_session()`

3. Added comprehensive tests:
   - Unit tests in `tests/test_utils_session.py` (13 tests)
   - Integration test `test_session_regenerated_after_mfa_verification` in `tests/test_mfa_e2e.py`
   - Integration test `test_saml_acs_session_regenerated_after_auth` in `tests/test_routers_saml.py`

**Key Implementation Detail:** In the MFA flow, `pending_timezone` and `pending_locale` are extracted BEFORE calling `regenerate_session()` since the clear destroys all pre-auth session data.

**Files Created:**
- `app/utils/session.py` - Session regeneration utility
- `tests/test_utils_session.py` - 13 unit tests

**Files Modified:**
- `app/routers/mfa.py` - Added import, use `regenerate_session()` after MFA verification
- `app/routers/saml.py` - Added import, use `regenerate_session()` after SAML auth
- `tests/test_mfa_e2e.py` - Added session regeneration integration test
- `tests/test_routers_saml.py` - Added session regeneration integration test

---

## [SECURITY] No Rate Limiting on Authentication Endpoints

**Status:** Resolved (2026-01-08)

**Found in:** `app/routers/auth.py:136-202`, `app/routers/mfa.py:47-90`

**Original Severity:** High

**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Original Description:** No rate limiting on login, MFA verification, or password-related endpoints. Attackers could brute force credentials without restriction.

**Attack Scenario:**
1. Brute force email/password combinations on `/login`
2. Brute force 6-digit email OTP codes (1M possibilities) on `/mfa/verify`
3. Enumerate valid email addresses via timing differences

**Resolution:**
1. Created `app/utils/ratelimit.py` implementing rate limiting using existing Memcached infrastructure:
   - `ratelimit.prevent()` - Hard limit that raises `RateLimitError` exception
   - `ratelimit.log()` - Soft limit that logs warnings and returns exceeded status
   - `ratelimit.check()` - Check current count without incrementing
   - `ratelimit.reset()` - Reset a rate limit counter
   - Supports compound keys like `login:{ip}:{email}`
   - Fails open if Memcached is unavailable (security/availability tradeoff)

2. Extended `app/utils/cache.py` with atomic Memcached operations:
   - `incr()` - Atomic counter increment
   - `add()` - Add only if key doesn't exist (race condition prevention)

3. Added `RateLimitError` exception to `app/services/exceptions.py`

4. Updated `app/utils/service_errors.py` to handle rate limiting:
   - `translate_to_http_exception()` returns HTTP 429 with `Retry-After` header
   - `render_error_page()` renders "Too Many Requests" error page

5. Added rate limiting to authentication endpoints:

| Endpoint | Pattern | Limit | Timespan |
|----------|---------|-------|----------|
| `/login/send-code` | `email_send:ip:{ip}` | 10 | 1 hour |
| `/login/send-code` | `email_send:email:{email}` | 5 | 10 min |
| `/login/verify-code` | `verify_code:ip:{ip}:email:{email}` | 5 | 5 min |
| `/login/resend-code` | `resend_code:ip:{ip}` | 5 | 10 min |
| `/login` | `login_attempts:ip:{ip}:email:{email}` | 5 (log) | 5 min |
| `/login` | `login_block:ip:{ip}:email:{email}` | 20 | 15 min |
| `/mfa/verify` | `mfa_verify:user:{user_id}` | 5 | 15 min |
| `/mfa/verify/send-email` | `mfa_email:user:{user_id}` | 3 | 5 min |

**Files Created:**
- `app/utils/ratelimit.py` - Rate limiting implementation
- `tests/test_utils_ratelimit.py` - 26 unit tests

**Files Modified:**
- `app/utils/cache.py` - Added `incr()` and `add()` methods
- `app/services/exceptions.py` - Added `RateLimitError` exception
- `app/utils/service_errors.py` - Added 429 handling
- `app/routers/auth.py` - Added rate limiting to login endpoints
- `app/routers/mfa.py` - Added rate limiting to MFA endpoints

---

## [SECURITY] Missing CSRF Token Protection on Forms

**Status:** Resolved (2026-01-08)

**Found in:** All web forms

**Original Severity:** High

**OWASP Category:** A01:2021 - Broken Access Control

**Original Description:** Web forms did not include CSRF tokens, allowing attackers to forge cross-site requests that execute state-changing operations on behalf of authenticated users.

**Attack Scenario:** Attacker hosts a malicious page that auto-submits a hidden form to `/users/new` or `/admin/security/update` while victim is logged into Loom.

**Resolution:**
1. Created `app/middleware/csrf.py` implementing the Synchronizer Token Pattern:
   - Generates cryptographically secure tokens using `secrets.token_urlsafe(32)`
   - Stores tokens in user sessions
   - Validates tokens on POST/PUT/PATCH/DELETE requests
   - Uses constant-time comparison to prevent timing attacks
2. Added middleware to `app/main.py` after session middleware
3. Added `csrf_token()` function to template context via `app/utils/template_context.py`
4. Added `make_csrf_token_func()` helper for routers not using `get_template_context()`
5. Updated all 21 templates with POST forms to include hidden CSRF token field
6. Exempt paths: API routes (use Bearer tokens), SAML ACS (receives from IdP), OAuth2 token endpoint

**Files Created:**
- `app/middleware/csrf.py` - CSRF middleware implementation
- `tests/test_middleware_csrf.py` - 12 unit tests

**Files Modified:**
- `app/main.py` - Added CSRFMiddleware
- `app/utils/template_context.py` - Added csrf_token to context
- `app/routers/auth.py` - Added csrf_token to manual contexts
- `app/routers/mfa.py` - Added csrf_token to manual contexts
- `app/routers/oauth2.py` - Added csrf_token to manual contexts
- 21 template files - Added hidden csrf_token input fields

---

## [SECURITY] Reflected XSS in Users List Search Parameter

**Status:** Resolved (2026-01-08)

**Found in:** `app/templates/users_list.html:26, 40, 52, 188`

**Original Severity:** Critical

**OWASP Category:** A03:2021 - Injection

**Original Description:** The `search` query parameter was injected directly into JavaScript code without escaping. Jinja2 autoescape protects HTML context but not JavaScript string context.

**Attack Scenario:** Attacker crafts URL like `/users/list?search=';alert(document.cookie);//` which breaks out of the JavaScript string and executes arbitrary code.

**Resolution:**
- For URL contexts (lines 26, 40, 52, 164, 235): Added `| urlencode` filter to properly escape special characters in query string values
- For JavaScript context (line 188): Changed from direct string interpolation to `encodeURIComponent({{ search | tojson }})` pattern which:
  - Uses `tojson` to safely escape the value as a JSON string (handles quotes, backslashes, etc.)
  - Uses `encodeURIComponent()` to URL-encode the value for the query string

**Files Modified:**
- `app/templates/users_list.html` - Fixed 6 instances of unescaped search parameter

---

## Activity Logging: OAuth2 client deletion not logged

**Status:** Resolved (2026-01-05)

**Found in:** `app/services/oauth2.py:303-316`

**Original Severity:** High

**Original Description:** The `delete_client` function deleted an OAuth2 client via `database.oauth2.delete_client()` but did not call `log_event()` after the mutation, violating the "if there is a write, there is a log" principle.

**Resolution:**
- Added `actor_user_id: str` parameter to `delete_client()` function
- Get client info before deletion for logging metadata
- Added `log_event()` call with event_type `oauth2_client_deleted`
- Updated router `app/routers/api/v1/oauth2_clients.py` to pass `user["id"]` to service function
- Updated 2 tests in `tests/test_services_oauth2.py` to pass new parameter

**Files Modified:**
- `app/services/oauth2.py` - Added logging to delete_client
- `app/routers/api/v1/oauth2_clients.py` - Pass actor_user_id to service
- `tests/test_services_oauth2.py` - Updated test signatures

---

## Activity Logging: OAuth2 client secret regeneration not logged

**Status:** Resolved (2026-01-05)

**Found in:** `app/services/oauth2.py:319-330`

**Original Severity:** High

**Original Description:** The `regenerate_client_secret` function regenerated the secret via `database.oauth2.regenerate_client_secret()` but did not call `log_event()` after the mutation. Secret regenerations are security-sensitive operations that should be audited.

**Resolution:**
- Added `actor_user_id: str` parameter to `regenerate_client_secret()` function
- Get client info for logging metadata
- Added `log_event()` call with event_type `oauth2_client_secret_regenerated`
- Updated router `app/routers/api/v1/oauth2_clients.py` to pass `user["id"]` to service function
- Updated 1 test in `tests/test_services_oauth2.py` to pass new parameter

**Files Modified:**
- `app/services/oauth2.py` - Added logging to regenerate_client_secret
- `app/routers/api/v1/oauth2_clients.py` - Pass actor_user_id to service
- `tests/test_services_oauth2.py` - Updated test signature

---

## Activity Logging: Public email verification not logged

**Status:** Resolved (2026-01-05)

**Found in:** `app/services/emails.py:605-631`

**Original Severity:** High

**Original Description:** The `verify_email_by_nonce` function (public endpoint flow) marked emails as verified via `database.user_emails.verify_email()` but did not call `log_event()`. The authenticated flow `verify_email()` logged events, creating an inconsistent audit trail.

**Resolution:**
- Added `log_event()` call using `email["user_id"]` as the actor (email owner performing verification)
- Added `flow: "public_link"` to metadata to distinguish from authenticated flow
- No signature change needed - user_id is available from the email record

**Files Modified:**
- `app/services/emails.py` - Added logging to verify_email_by_nonce

---

## SAML Error Page: Add SAML Response Debug Output

**Status:** Resolved (2026-01-05)

**Found in:** `app/templates/saml_error.html`

**Original Severity:** Low (DX improvement)

**Original Description:** When SAML validation failed, the error page showed a generic message. For debugging, it would be helpful to display the raw SAML response (base64 decoded) so developers can inspect what attributes were sent.

**Resolution:**
- Added helper function `_decode_saml_response_for_debug()` in `app/routers/saml.py` to safely decode base64 SAML responses
- Modified all error template responses in `saml_acs()` to pass `is_dev` and `raw_saml_xml` to the template
- Added collapsible `<details>/<summary>` section to `app/templates/saml_error.html` that only displays when `IS_DEV=true`
- Debug section shows the full SAML response XML with syntax-highlighted styling

**Files Modified:**
- `app/routers/saml.py` - Added debug helper, updated all error responses in `saml_acs()`
- `app/templates/saml_error.html` - Added collapsible debug section

---

## SAML Edit Form: No Save Confirmation Feedback

**Status:** Resolved (2026-01-05)

**Found in:** SAML Identity Provider edit page

**Original Severity:** Low (UX issue)

**Original Description:** When saving changes on the IdP edit form, there was no visual feedback that the save succeeded. Users didn't know if their changes were persisted.

**Resolution:**
- Changed redirect in `update_idp()` to redirect back to the edit form (`/admin/identity-providers/{idp_id}?success=updated`) instead of the list page
- Updated `edit_idp_form()` to capture `success` query parameter and pass it to template
- Added green success banner to `app/templates/saml_idp_form.html` matching the existing error banner styling

**Files Modified:**
- `app/routers/saml.py` - Changed redirect, added success param handling
- `app/templates/saml_idp_form.html` - Added success banner

---

## SAML IdP Simulator: Metadata Import Does Not Work Out-of-Box

**Status:** Resolved (2026-01-05)

**Found in:** SAML IdP setup flow

**Original Severity:** Medium (DX issue)

**Original Description:** Manual configuration was required for local SAML IdP setup. The "Quick Import from Metadata URL" feature couldn't be used because of Docker hostname mismatch - importing from `http://saml-idp:8080/...` resulted in SSO URLs with `saml-idp` hostname that browsers couldn't resolve.

**Resolution Approach:** Rather than complex SimpleSAMLphp configuration, added a "Paste Raw Metadata XML" option. Users can now:
1. Copy XML from browser at `localhost:8080/simplesaml/module.php/saml/idp/metadata`
2. Paste into the new "Paste Metadata XML" tab
3. The XML is parsed client-side and IdP is created

**Implementation:**
- Added `IdPMetadataImportXML` schema in `app/schemas/saml.py`
- Added `parse_idp_metadata_xml_to_schema()` and `import_idp_from_metadata_xml()` in `app/services/saml.py`
- Added HTML endpoint `POST /admin/identity-providers/import-metadata-xml` in `app/routers/saml.py`
- Added API endpoint `POST /api/v1/saml/idps/import-xml` in `app/routers/api/v1/saml.py`
- Completely rewrote `app/templates/saml_idp_form.html` with tabbed interface (URL | Paste XML)
- Removed manual form entry entirely - all IdP creation now uses XML parsing

**Tests Added:**
- 4 service tests in `tests/test_services_saml.py` for XML import
- 3 router tests in `tests/test_routers_saml.py` for HTML endpoint
- 6 API tests in `tests/test_api_saml.py` for API endpoint

**Files Modified:**
- `app/schemas/saml.py` - Added `IdPMetadataImportXML` schema
- `app/services/saml.py` - Added 2 new functions
- `app/routers/saml.py` - Added HTML import endpoint
- `app/routers/api/v1/saml.py` - Added API import endpoint
- `app/templates/saml_idp_form.html` - Complete rewrite with tabbed UI
- `tests/test_services_saml.py` - Added XML import tests
- `tests/test_routers_saml.py` - Added HTML endpoint tests
- `tests/test_api_saml.py` - Added API endpoint tests

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

## [SECURITY] OAuth2 State Parameter Not Validated (CSRF)

**Status:** Resolved (2026-01-11)

**Found in:** `app/routers/oauth2.py`

**Original Severity:** High

**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Original Description:** The OAuth2 `state` parameter was accepted and echoed back but never validated server-side. No session-based state storage or verification. This enabled OAuth2 CSRF attacks where an attacker could trick a victim into using their authorization code.

**Attack Scenario:**
1. Attacker initiates OAuth flow with their own account
2. Attacker intercepts redirect with authorization code
3. Attacker tricks victim into clicking the redirect URL
4. Victim's session gets linked to attacker's account

**Resolution:**
Implemented server-side authorization request tracking with session-based validation:

1. **GET /oauth2/authorize** now:
   - Generates a unique `auth_request_id` using `secrets.token_urlsafe(32)`
   - Stores authorization parameters in session: `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method`, `created_at`
   - Passes only `auth_request_id` to the template (not individual parameters)

2. **POST /oauth2/authorize** now:
   - Accepts only `auth_request_id` and `action` from form (not individual OAuth params)
   - Validates `auth_request_id` exists in session
   - Validates request hasn't expired (10 minute max age)
   - Retrieves stored parameters from session (prevents tampering)
   - Deletes from session after use (one-time use)
   - Uses stored parameters for authorization flow

3. **Template updated:**
   - Removed individual hidden fields for `client_id`, `redirect_uri`, `state`, etc.
   - Only includes `auth_request_id` hidden field

**Security Benefits:**
- Parameter tampering prevention - `client_id`/`redirect_uri` cannot be changed between GET and POST
- Request expiry - Stale authorization pages cannot be used after 10 minutes
- One-time use - Each authorization request can only be submitted once (replay protection)
- Defense in depth - Additional layer on top of existing CSRF token protection

**Tests Added:**
- `test_invalid_auth_request_id_rejected` - Fabricated IDs are rejected
- `test_auth_request_id_single_use` - Replay protection verification
- `test_expired_auth_request_rejected` - Expiry validation
- `test_parameters_retrieved_from_session_not_form` - Tampering prevention

**Files Modified:**
- `app/routers/oauth2.py` - Added auth_request_id generation, storage, and validation
- `app/templates/oauth2_authorize.html` - Simplified to only include auth_request_id
- `tests/test_routers_oauth2.py` - Updated existing tests, added 4 security-focused tests

---

