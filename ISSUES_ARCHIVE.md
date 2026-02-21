# Issues Archive

This document contains resolved issues for historical reference.


---

### [TEST] Integration tests for database/groups/memberships.py (28% coverage)

**Status:** Resolved (2026-02-21)
**Original Severity:** Medium

**Original Description:**
5 of 12 functions in `database/groups/memberships.py` had no integration tests. The untested functions build dynamic SQL with search tokenization, role/status filtering, and pagination. Their SQL was never executed against the real schema in tests.

**Resolution:**
Added 16 integration tests to `tests/database/test_groups.py` covering all 5 untested functions: `search_group_members` (5 tests for text search, role/status filters, sorting, pagination), `count_group_members_filtered` (3 tests for filters and count-search consistency), `search_available_users` (4 tests for member/service-account exclusion, filters, pagination), `count_available_users` (1 test for filter consistency), and `bulk_remove_group_members` (3 tests for removal, empty list, nonexistent users).

---

### [SECURITY] Certificate Cleanup Race Condition

**Status:** Resolved (2026-02-21)
**Original Severity:** Low
**OWASP Category:** A04:2021 - Insecure Design

**Original Description:**
The certificate cleanup UPDATE in `clear_previous_signing_certificate()` and `clear_previous_idp_sp_certificate()` did not re-verify that `rotation_grace_period_ends_at` had actually expired. If an admin manually rotated a certificate between the background job's SELECT and UPDATE, the cleanup would clear the newly-set previous certificate, bypassing its grace period.

**Resolution:**
Added `AND rotation_grace_period_ends_at IS NOT NULL AND rotation_grace_period_ends_at < now()` to the WHERE clause of both `clear_previous_signing_certificate()` in `app/database/sp_signing_certificates.py` and `clear_previous_idp_sp_certificate()` in `app/database/saml/idp_sp_certificates.py`. The UPDATE now only proceeds when the grace period has genuinely expired, making it safe against concurrent manual rotations.

---

### [SECURITY] SLO LogoutRequest Processed Without Validation

**Status:** Resolved (2026-02-21)
**Original Severity:** Low
**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Original Description:**
The SLO handler cleared the user's session immediately after parsing the LogoutRequest XML, before checking whether the issuer was a registered SP. Any syntactically valid LogoutRequest (even from an unregistered source) could destroy a user's session, enabling forced logout.

**Resolution:**
Moved `request.session.clear()` in `_handle_slo_request()` to after `process_sp_logout_request()` succeeds. The service function validates the issuer is a registered, enabled SP before the session is touched. Added tests confirming session is preserved when SP validation fails and when XML is malformed.

---

### [SECURITY] XML Injection in IdP Metadata Generation via String Interpolation

**Status:** Resolved (2026-02-21)
**Original Severity:** Medium
**OWASP Category:** A03:2021 - Injection

**Original Description:**
IdP and SP metadata XML was generated using f-string interpolation without XML escaping. User-configurable `attribute_mapping` values (both keys and values) were interpolated directly into XML attribute positions. A value containing `"` or `<` could break out of the XML attribute and inject arbitrary XML content.

**Resolution:**
Added `xml.sax.saxutils.escape()` with quote entity escaping for all interpolated values in both `generate_idp_metadata_xml()` (`app/utils/saml_idp.py`) and `generate_sp_metadata_xml()` (`app/utils/saml.py`). This covers attribute mapping keys/values, entity IDs, SSO URLs, SLO URLs, and ACS URLs. Added 7 tests verifying that XML special characters in attribute mappings, entity IDs, and URLs are properly escaped and round-trip correctly through XML parsing.

---

### [SECURITY] SSRF via Metadata URL Fetch

**Status:** Resolved (2026-02-21)
**Original Severity:** High
**OWASP Category:** A10:2021 - Server-Side Request Forgery (SSRF)

**Original Description:**
`fetch_sp_metadata()` and `fetch_idp_metadata()` accepted arbitrary URLs without validating scheme or target host. `urllib.request.urlopen` supports `file://`, `ftp://`, and `http://` schemes by default, and no blocklist prevented requests to internal networks (169.254.169.254, 127.0.0.1, etc.). No response size limit either.

**Resolution:** Created `app/utils/url_safety.py` with shared SSRF protection. Validates URL scheme (https only in production, http also allowed in dev), resolves hostname via `socket.getaddrinfo`, rejects private/reserved IP ranges (loopback, RFC 1918, link-local, cloud metadata, IPv6 equivalents, IPv4-mapped IPv6). Enforces a 5 MB response size limit. Both `fetch_sp_metadata` and `fetch_idp_metadata` now delegate to the shared `fetch_metadata_xml()`. Dev-mode reverse-proxy handling for `*.BASE_DOMAIN` URLs is preserved (skips IP validation since hostname is rewritten to container name, but still validates scheme).

---

### [SECURITY] RLS Policy Defect on saml_idp_sp_certificates Table

**Status:** Resolved (2026-02-21)
**Original Severity:** High
**OWASP Category:** A01:2021 - Broken Access Control

**Original Description:**
The `saml_idp_sp_certificates` table had a defective RLS policy: missing `WITH CHECK` clause (writes bypassed tenant scoping), missing `true` parameter in `current_setting()` (errors instead of NULL when unset), and missing `NULLIF()` handling for empty strings.

**Resolution:** Fixed the baseline schema policy to use the standard pattern with `NULLIF(current_setting(..., true), '')` and both `USING` and `WITH CHECK` clauses. Added migration `0004_fix_saml_idp_sp_certificates_rls.sql` to correct running databases. Updated the compliance scanner to recognize migration-based RLS fixes so future corrections are automatically detected.

---

### [SECURITY] SSO consent flow not bound to authenticated user

**Status:** Resolved (2026-02-21)
**Original Severity:** Low
**OWASP Category:** A01:2021 - Broken Access Control

**Original Description:**
The pending SSO context (`pending_sso_sp_id`, etc.) was stored in the session without recording which `user_id` initiated it. If a session were reused by a different user, they could complete another user's SSO flow. Session regeneration on login prevented this in practice.

**Resolution:** Store `pending_sso_user_id` in the session when SSO context is created (both SP-initiated and IdP-initiated). Validate it matches the current user on consent GET and POST. The MFA verification handler stamps the binding after session regeneration. The switch-account flow intentionally drops the binding so re-authentication re-binds to the new user.

---

### [SECURITY] Session cookie missing `Secure` flag in production

**Status:** Resolved (2026-02-21)
**Original Severity:** High
**OWASP Category:** A05:2021 - Security Misconfiguration

**Original Description:**
Starlette's `SessionMiddleware` defaults to `https_only=False`. The session cookie can be transmitted over plain HTTP, enabling session hijacking via network sniffing.

**Resolution:** Pass `https_only=not settings.IS_DEV` to `DynamicSessionMiddleware` in `app/main.py`. Added test verifying the Secure flag is set when `https_only=True`.

---

### [SECURITY] Inconsistent defusedxml usage allows XML bomb attacks

**Status:** Resolved (2026-02-21)
**Original Severity:** High
**OWASP Category:** A03:2021 - Injection

**Original Description:**
`app/utils/saml.py` (`extract_issuer_from_response`) and `app/services/branding.py` (SVG validation) used stdlib `xml.etree.ElementTree` instead of `defusedxml`, making them vulnerable to billion-laughs entity expansion DoS attacks.

**Resolution:** Replaced the stdlib import with `from defusedxml import ElementTree as ET` in both files. Also removed the redundant local `defusedxml` import in `saml.py` since the module-level import now covers it.

---

### [SECURITY] TLS verification disabled for internal metadata fetching

**Status:** Resolved (2026-02-21)
**Original Severity:** Medium
**OWASP Category:** A02:2021 - Cryptographic Failures

**Original Description:**
When fetching SAML metadata from URLs matching `*.BASE_DOMAIN`, TLS certificate verification was completely disabled to route through the Docker reverse-proxy, even in production.

**Resolution:** Gated the reverse-proxy routing (and associated TLS bypass) on `settings.IS_DEV`. Production metadata fetches now use full TLS verification. Applied to both `app/utils/saml.py` and `app/utils/saml_idp.py`.

---

### [SECURITY] Weak key derivation fallback for SAML private key encryption

**Status:** Resolved (2026-02-21)
**Original Severity:** Medium
**OWASP Category:** A02:2021 - Cryptographic Failures

**Original Description:**
The fallback path in `_get_encryption_key()` used raw SHA256 to derive a Fernet key, which is not a proper key derivation function (no salt, no iteration count).

**Resolution:** Replaced SHA256 with HKDF-SHA256 from `cryptography.hazmat.primitives.kdf.hkdf`, using `info=b"saml-key-encryption"` as context.

---

### [SECURITY] Trust cookie uses SameSite=Lax instead of Strict

**Status:** Resolved (2026-02-21)
**Original Severity:** Low
**OWASP Category:** A05:2021 - Security Misconfiguration

**Original Description:**
The 30-day email verification trust cookie used `samesite="lax"`, allowing it to be sent on top-level cross-site navigations.

**Resolution:** Changed trust cookie to `samesite="strict"` in `app/routers/auth/login.py`. Short-lived email verification cookies remain at Lax, which is appropriate for their use case.

---

### SQL Column Length: user_emails.email missing CHECK constraint

**Status:** Resolved (2026-02-21)
**Original Severity:** Medium

**Original Description:**
The `email` column in `user_emails` (type `citext`) had no `CHECK (length(email) <= N)` constraint. The application validates email length via Pydantic `EmailStr` with `max_length=320`, but there was no database-level backstop.

**Resolution:** Added migration `0002_add_user_emails_email_length_check.sql` with `ALTER TABLE ... ADD CONSTRAINT chk_user_emails_email_length CHECK (length(email) <= 320)`. Also fixed the compliance scanner to cross-reference migrations when checking `schema.sql`, so constraints added via ALTER TABLE ADD CONSTRAINT in migrations are recognized as covering baseline schema columns.

---

### Activity Logging: Missing track_activity() in 4 read functions

**Status:** Resolved (2026-02-21)
**Original Severity:** Medium

**Original Description:**
Four read-only service functions with `RequestingUser` parameter did not call `track_activity()` at the start. These functions were: `preview_sp_metadata_refresh`, `preview_sp_metadata_reimport`, `count_sp_group_assignments`, `get_idp_sp_certificate_for_display`.

**Resolution:** Added `track_activity(requesting_user["tenant_id"], requesting_user["id"])` after the authorization check in all four functions. Added import of `track_activity` to `app/services/saml/idp_sp_certificates.py`. User activity on SP metadata previews, group assignment counts, and IdP SP certificate views is now tracked for audit purposes.

---

### E2E: Custom Attribute Mapping in SAML Assertions Not Tested

**Status:** Resolved (2026-02-21)
**Original Severity:** Low

**Original Description:**
SPs can be configured with custom attribute mappings (custom URIs for standard attributes). No E2E test verified that configured attribute mappings actually appear in the SAML assertion consumed by the SP. Unit tests covered the mapping logic but not the full sign/deliver/parse round-trip.

**Resolution:** Added Python-level integration test in `tests/test_saml_attribute_roundtrip.py`. True E2E testing via Playwright can't inspect signed assertion content, so the test exercises the real round-trip at the code level: the IdP builds a signed assertion with custom attribute URIs, then the SP parses it with python3-saml (real signature validation) and extracts attributes via the production `_extract_mapped_attributes` function. Covers default mapping, Azure AD long URIs, partial custom mapping, and multi-valued group claims.

---

### E2E: Per-SP Certificate Rotation Not Tested End-to-End

**Status:** Resolved (2026-02-20)
**Original Severity:** Medium

**Original Description:**
Per-SP signing certificates can be rotated with a grace period, but no E2E test verified that SSO continues to work after rotation.

**Resolution:** Added `TestCertificateRotation` in `tests/e2e/test_sso_edge_cases.py`. The test performs baseline SSO, rotates the per-SP signing certificate via the IdP admin UI, syncs the new certificate to the SP's IdP certificate store, then verifies SSO completes successfully with the new certificate.

---

### E2E: Consent Denial and Error Response Not Tested

**Status:** Resolved (2026-02-20)
**Original Severity:** Medium

**Original Description:**
The consent screen allows users to cancel SSO, but no E2E test covered the cancel path.

**Resolution:** Added `TestConsentDenial` in `tests/e2e/test_sso_edge_cases.py`. The test initiates IdP-initiated SSO, clicks Cancel at the consent screen, and verifies the user is redirected to the IdP dashboard (not the SP) and remains logged in.

---

### E2E: Unauthorized User SP Access Denial Not Tested

**Status:** Resolved (2026-02-20)
**Original Severity:** Medium

**Original Description:**
Group-based access gating was tested for the positive case but no E2E test verified that a user without SP access is denied.

**Resolution:** Added `TestUnauthorizedUserAccess` in `tests/e2e/test_sso_edge_cases.py`. Added a no-access user (`no-access@acme.com`) to the extras testbed who is not in any group. The test logs in as this user, attempts IdP-initiated SSO, and verifies the "Access Denied" error page renders with group membership messaging.

---

### E2E: Switch Account During SSO Not Tested

**Status:** Resolved (2026-02-20)
**Original Severity:** Low

**Original Description:**
The consent screen has a "switch account" flow that clears the auth session while preserving the pending SSO context, but no E2E test exercised it.

**Resolution:** Added `TestSwitchAccount` in `tests/e2e/test_sso_edge_cases.py`. Added a second SSO user (`sso-user-b@acme.com`) to the extras testbed. The test logs in as user A, reaches the consent page, clicks "Use a different account", completes the full multi-step login as user B (email verify, password, MFA), verifies user B's email appears on the consent page, and confirms SSO completes successfully.

---

### ARCH-001: Router imports directly from database layer

**Status:** Resolved (2026-02-16)
**Original Severity:** High

**Original Description:**
`app/routers/dev.py:8` imported `from database.users.core import get_user_by_email`, bypassing the service layer.

**Resolution:** Replaced direct database import with `get_user_id_by_email` from `services.users`. The service utility function already wraps the same database call and returns the user ID string, which is all the dev login endpoint needs.

---

### LOG-003: Missing track_activity in branding service

**Status:** Resolved (2026-02-16)
**Original Severity:** Medium

**Original Description:**
`app/services/branding.py` function `randomize_mandala` accepts `RequestingUser` but did not call `track_activity()`.

**Resolution:** Added `track_activity(requesting_user["tenant_id"], requesting_user["id"])` at the start of `randomize_mandala()`, matching the pattern used by other read-only service functions.

---

### SEC-001: Uploaded SVG content is not sanitized

**Status:** Resolved (2026-02-14)
**Original Severity:** Medium

**Original Description:**
SVG uploads were validated for dimensions and size but not content safety. SVGs could contain `<script>` tags, event handlers, `javascript:` URLs, `<foreignObject>`, and XXE entity declarations.

**Resolution:** Added `_validate_svg_content()` to `app/services/branding.py` that parses uploaded SVGs with `xml.etree.ElementTree` and rejects dangerous content. Uses an element allowlist of safe drawing primitives, rejects event handler attributes (`on*`), `javascript:`/`data:text/html` URLs, `<script>`, `<foreignObject>`, and DOCTYPE/ENTITY declarations. Rejects rather than silently strips, so admins get clear error messages. Added 9 new tests covering each attack vector and safe content.

---

### LOG-002: Silent audit log loss from invalid actor_user_id

**Status:** Resolved (2026-02-14)
**Original Severity:** High

**Original Description:**
Two call sites passed `actor_user_id="system"` instead of `SYSTEM_ACTOR_ID` UUID constant. The `event_logs.actor_user_id` column is `UUID NOT NULL`, so the plain string failed Postgres validation and `log_event()` silently discarded the events.

**Resolution:** Imported `SYSTEM_ACTOR_ID` from `services.event_log` in both `services/service_providers/slo.py` and `jobs/inactivate_idle_users.py`, replacing the invalid `"system"` string. Updated corresponding test assertion. SLO and auto-inactivation events are now properly recorded in the audit log.

---

### API-002: Group parent management missing from API

**Status:** Resolved (2026-02-13)
**Original Severity:** Medium

**Original Description:**
The web UI exposes parent relationship management (add parent, remove parent) but the API only provides read access to parents and write access via the child direction.

**Resolution:**
Added two API endpoints `POST /api/v1/groups/{group_id}/parents` and `DELETE /api/v1/groups/{group_id}/parents/{parent_group_id}`.
Added tests for the new endpoints.

---


---

## REFACT-002: service_providers.py exceeds 1100 lines (package split candidate)

**Status:** Resolved (2026-02-13)

**Original Severity:** Medium

**Original Description:**
`app/services/service_providers.py` was 1129 lines with 26 functions handling 5 distinct concerns: SP CRUD, SSO flow lookups, IdP metadata generation, per-SP signing certificates, and group assignments. Contained duplicate code between import functions and between metadata functions.

**Resolution:**
Split into `app/services/service_providers/` package with 6 submodules: `_converters.py`, `crud.py`, `sso.py`, `metadata.py`, `signing_certs.py`, `group_assignments.py`. Extracted `_create_sp_from_parsed_metadata()` to deduplicate import functions and `_resolve_idp_certificate()` to deduplicate metadata functions. Updated mock targets in 3 service test files. All 2640 tests pass.

**Files Changed:**
- New: `app/services/service_providers/__init__.py`, `_converters.py`, `crud.py`, `sso.py`, `metadata.py`, `signing_certs.py`, `group_assignments.py`
- Deleted: `app/services/service_providers.py`
- Updated mocks: `tests/test_services_service_providers.py`, `tests/test_services_service_providers_sso.py`, `tests/test_services_sp_group_assignments.py`

---

## REFACT-001: Dropdown pagination limits silently truncate results

**Status:** Superseded (2026-02-13)

**Original Severity:** High

**Original Description:**
Two dropdown-population functions in `app/services/groups/selection.py` use hardcoded pagination limits (`page_size=100` for users, `page_size=1000` for members) that silently truncate results for larger tenants. Admins cannot assign users beyond the 100-user limit to a group via the UI dropdown.

**Resolution:**
Superseded by backlog item "Group Membership UX Redesign". Rather than patching the pagination limits, the entire group membership UX will be rebuilt with a dedicated paginated member list page, search, filtering, and a proper add-member interface that replaces the dropdown approach entirely.

**Files Changed:** None (architectural redesign planned)

---

## ARCH-001: SSO router imports database directly

**Status:** Resolved (2026-02-12)

**Original Severity:** High

**Original Description:**
The SSO router (`app/routers/saml_idp/sso.py`) imported `database` directly and called `database.service_providers.get_service_provider()` for IdP-initiated SSO, bypassing the Router -> Service -> Database architecture.

**Resolution:**
Added a thin `get_service_provider_by_id()` service function in `app/services/service_providers.py` that wraps the database call. Updated the router to call through the service layer and removed the direct database import. Updated all related tests to mock the service function instead of the database module.

**Files Changed:** `app/routers/saml_idp/sso.py`, `app/services/service_providers.py`, `tests/test_routers_saml_idp_sso.py`, `tests/test_services_service_providers_sso.py`

---

## LOG-001: Missing track_activity() in list_available_groups_for_sp

**Status:** Resolved (2026-02-12)

**Original Severity:** Medium

**Original Description:**
The read-only service function `list_available_groups_for_sp()` in `app/services/service_providers.py` did not call `track_activity()`, so admin activity for this operation was not tracked.

**Resolution:**
Added `track_activity(requesting_user["tenant_id"], requesting_user["id"])` after the authorization check. Added a test to verify the call.

**Files Changed:** `app/services/service_providers.py`, `tests/test_services_sp_group_assignments.py`

---

## SSO-001: JIT-provisioned users not added to IdP base group when IdP lacks one

**Status:** Resolved (2026-02-12)

**Original Severity:** Medium

**Original Description:**
When a user authenticates via SAML SSO and gets JIT-provisioned, `ensure_user_in_base_group()` silently skipped group assignment if no base group existed for the IdP. The base group is normally created by the service layer when an IdP is added through the admin UI (`create_idp_base_group()`), but any IdP created by direct database insertion (dev scripts, migrations, API edge cases) lacked this group. JIT-provisioned users ended up with no group memberships.

**Resolution:**
Made `ensure_user_in_base_group()` self-healing: if no base group exists for the IdP, it now auto-creates one by calling `create_idp_base_group()` before adding the user. Also updated the SSO testbed script to create base groups explicitly during setup.

**Files Changed:** `app/services/groups/idp.py`, `app/dev/sso_testbed.py`, `tests/test_services_groups.py`

---

## ISSUE-001: Email MFA code not auto-sent on IDP/SAML sign-in

**Status:** Resolved (2026-02-09)

**Original Severity:** Medium

**Original Description:**
When a user signs in via SAML/IDP and has email-based MFA enabled, no verification email is sent automatically. The user lands on `/mfa/verify` with an empty inbox and must manually click "Send code to my email." The SAML ACS handler stored pending MFA session data and redirected to `/mfa/verify` but did not call `create_email_otp()` or `send_mfa_code_email()`. The password login flow already auto-sent.

**Resolution:**
Added `create_email_otp()` and `send_mfa_code_email()` calls to the SAML ACS handler's MFA block in `authentication.py`, matching the existing password login behavior. 87 lines of new tests cover the fix.

**Files Changed:** `app/routers/saml/authentication.py`, `tests/test_routers_saml.py`

---

## ISSUE-002: Group audit events silently lost due to invalid UUID in artifact_id

**Status:** Resolved (2026-02-09)

**Original Severity:** High

**Original Description:**
11 `log_event()` calls in the groups service passed compound strings like `f"{group_id}:{user_id}"` as `artifact_id`, but `event_logs.artifact_id` is a `UUID NOT NULL` column. The compound string failed Postgres UUID validation, so the INSERT was silently rejected and the audit event was never recorded. All group membership, IdP sync, and hierarchy audit events were lost.

**Resolution:**
Replaced all 11 compound `artifact_id` values with a single UUID (the group ID or parent group ID). The second ID was already present in the `metadata` dict in every case, so no information was lost. Added `artifact_id` assertions to 7 existing tests to prevent regression.

**Files Changed:** `app/services/groups/idp.py` (7 fixes), `app/services/groups/membership.py` (2 fixes), `app/services/groups/hierarchy.py` (2 fixes), `tests/test_services_groups.py` (7 assertions added)

---

## API-FIRST: Missing API endpoint for user-IdP assignment

**Status:** Resolved (2026-02-08)

**Original Severity:** Medium

**Original Description:**
The web route `POST /users/{user_id}/update-idp` calls `saml_service.assign_user_idp()` to assign or unassign a user from an IdP. No corresponding REST API endpoint existed under `/api/v1/`.

**Resolution:**
Added `PUT /api/v1/users/{user_id}/idp` endpoint in `app/routers/api/v1/users/admin.py`. Accepts `{"saml_idp_id": "..." | null}` JSON body. Requires super_admin role. Calls the existing `saml_service.assign_user_idp()` service function. Added `saml_service` re-export to the users API package for test mocking. Added 5 unit tests covering: assign to IdP, set password-only, not found, validation error, and forbidden error.

**Files Changed:** `app/routers/api/v1/users/admin.py`, `app/routers/api/v1/users/__init__.py`, `tests/test_api_users.py`

---

## [BUG] Users assigned to an IdP are not added to its base group

**Status:** Resolved (2026-02-08)

**Original Severity:** High

**Original Description:**
Each IdP has an automatically created base group that should contain all users assigned to that IdP. No assignment path (JIT provisioning, domain binding, manual assignment) actually added users to this base group. Users only got placed in assertion sub-groups (if any) during SAML authentication.

**Resolution:**
Added `get_idp_base_group_id()` database function to look up the base group for an IdP via a join to `saml_identity_providers`. Added service helpers (`ensure_user_in_base_group`, `remove_user_from_base_group`, `ensure_users_in_base_group`, `remove_user_from_all_idp_groups`, `move_users_between_idps`) in `app/services/groups/idp.py`. Wired these helpers into all five assignment paths: JIT provisioning, SAML auth for existing users, domain binding, domain rebinding, and manual assignment. Protected `sync_user_idp_groups` from removing the base group during assertion sync (base group is managed by assignment, not assertions). Existing users are retroactively added to their base group on next SAML authentication.

**Files Changed:** `app/database/groups/idp.py`, `app/database/groups/__init__.py`, `app/services/groups/idp.py`, `app/services/groups/__init__.py`, `app/services/saml/provisioning.py`, `app/services/saml/domains.py`, `tests/test_services_groups.py`, `tests/test_services_saml.py`

---

## [REFACTOR] Duplication: Worker periodic task boilerplate

**Status:** Resolved (2026-02-07)

**Original Severity:** Medium

**Original Description:**
Three identical `_maybe_run_*` / `_run_*` method pairs in `worker.py` followed the exact same pattern (68 lines of boilerplate). Each new periodic task required copying the same code.

**Resolution:**
Extracted a `PeriodicJob` class and two generic methods (`_check_periodic_jobs`, `_run_job`) that replace all 6 boilerplate methods. Each periodic task is now a data declaration in `__init__`. Adding a new periodic task is a one-liner. Reduced from 68 lines to ~20 lines of generic code. Tests consolidated from 32 to 24 (9 duplicated timing tests became 3 generic scheduling tests).

**Files Changed:** `app/worker.py`, `tests/test_worker.py`

---

## [REFACTOR] Correctness: Super-admin count check uses wrong query

**Status:** Resolved (2026-02-07)

**Original Severity:** Medium

**Original Description:**
The last-super-admin guard in `_validation.py` used `database.users.list_users()` with `page_size=100` and counted super admins in Python. If a tenant had more than 100 users, super admins beyond page 1 would be missed, potentially allowing demotion of the last super admin.

**Resolution:**
Replaced `list_users()` + Python filtering with `database.users.count_active_super_admins(tenant_id)`, matching the correct pattern already used in `state.py`. Updated the corresponding test mock to target `services.users._validation.database` and mock `count_active_super_admins`.

**Files Changed:** `app/services/users/_validation.py`, `tests/test_services_users.py`

---

## [TEST] Parametrization Opportunities

**Status:** Resolved (2026-02-07)

**Original Severity:** Medium

**Original Description:**
Several test groups had highly similar structure that could be consolidated using `pytest.mark.parametrize` across 4 test files.

**Resolution:**
Applied `pytest.mark.parametrize` to 3 of 4 identified files:

1. `test_routers_saml_domain_binding.py`: Consolidated 4 error tests (bind/unbind x not_found/service_error) into 2 parametrized tests. Success tests kept separate (distinct assertions).
2. `test_routers_integrations.py`: Consolidated 2 validation error tests (empty_name, empty_redirect_uris) into 1 parametrized test. Service error test kept separate (requires mocker for mock setup).
3. `test_utils_saml.py`: Consolidated 3 fetch error tests (http_error, network_error, timeout) into 1 parametrized test.
4. `test_email_backends.py`: Evaluated but not parametrized. Each backend has fundamentally different mock setups (SMTP patches smtplib, Resend patches resend.Emails.send, SendGrid uses two-level client mock), making parametrization less readable than the original.

All 2174 tests pass.

---

## [REFACTOR] Critical File Size: services/users.py and services/groups.py

**Status:** Resolved (2026-02-06)

**Original Severity:** High (Claude Traversability)

**Original Description:**
Two service files exceeded the critical threshold of 1000 lines:
- `app/services/users.py` (1334 lines, ~40 functions)
- `app/services/groups.py` (1295 lines, ~35 functions)

**Resolution:**
Both files split into focused package modules following the established `app/services/saml/` pattern:

**`app/services/groups/` package (8 modules):**
- `_converters.py` - Row-to-schema conversion helpers
- `_helpers.py` - IdP group validation guards
- `utilities.py` - Internal utility functions (get_user_group_ids)
- `crud.py` - Group CRUD operations (list, get, create, update, delete)
- `membership.py` - Member management (list, add, remove)
- `hierarchy.py` - DAG operations (parents, children, add/remove relationships)
- `selection.py` - UI dropdown helpers (available users, parents, children)
- `idp.py` - IdP sync operations (create, sync, invalidate)

**`app/services/users/` package (7 modules):**
- `_converters.py` - Row-to-schema conversion helpers
- `_validation.py` - Role change validation
- `utilities.py` - Low-level utility functions (email checks, password updates, etc.)
- `profile.py` - Self-service profile management (get/update)
- `crud.py` - User CRUD operations (list, get, create, update, delete)
- `state.py` - Lifecycle state operations (inactivate, reactivate, anonymize)

**Test Updates:**
Mock paths updated in 4 test files:
- `tests/test_services_groups.py` (55 tests)
- `tests/test_services_users.py` (48 tests)
- `tests/test_services_event_log.py` (5 tests)
- `tests/test_services_activity.py` (3 tests)

**Verification:** All 2174 tests pass.

---

## [TEST] Underutilized Pytest Parametrization

**Status:** Resolved (2026-02-06)

**Original Severity:** Medium

**Original Description:**
Only `test_templates_dark_mode.py` effectively used `@pytest.mark.parametrize`. Many test files had repeated test structures that could be consolidated, particularly section redirect tests and role-based access tests.

**Resolution:**
Applied parametrization to `tests/test_routers_admin.py` section redirect tests:

- Consolidated 8 individual test functions into 3 parametrized tests
- `test_section_index_redirects_to_first_child` (3 cases: /admin/, /admin/audit/, /admin/todo/)
- `test_section_index_fallback_to_dashboard` (3 cases)
- `test_section_index_works_without_trailing_slash` (2 cases: /admin/audit, /admin/todo)

This establishes the parametrization pattern for the codebase. Other files (test_routers_users.py, test_api_users.py, test_services_users.py) have potential opportunities but with more complex patterns (different function signatures, varying assertions).

**Verification:** All 2174 tests pass.

---

## [TEST] Missing Test Docstrings: test_services_saml.py

**Status:** Already Resolved (confirmed 2026-02-06)

**Original Severity:** Medium

**Original Description:**
73 tests in `tests/test_services_saml.py` were reported to lack docstrings explaining what they test and why.

**Resolution:**
Upon investigation, all 163 tests in the file already have docstrings. The examples mentioned in the original issue (lines 197, 455, 569, 625) all contain descriptive docstrings. The issue was either resolved previously or was logged incorrectly.

**Verification:** AST parsing confirmed 163 tests with docstrings, 0 without.

---

## [REFACTOR] File Structure: Large Router Files (All 4 Routers)

**Status:** Resolved (2026-02-06)

**Original Severity:** High (Claude Traversability)

**Original Description:**
Four router modules exceeded 500 lines:
- `app/routers/saml.py` (1241 lines)
- `app/routers/auth.py` (987 lines)
- `app/routers/users.py` (747 lines)
- `app/routers/api/v1/users.py` (1025 lines)

**Resolution:**
All four routers split into focused package modules:

- **saml.py** → `app/routers/saml/` (9 modules): authentication.py, logout.py, selection.py, admin/providers.py, admin/debug.py, admin/domains.py, _helpers.py
- **auth.py** → `app/routers/auth/` (6 modules): login.py, logout.py, onboarding.py, reactivation.py, dashboard.py, _helpers.py
- **api/v1/users.py** → `app/routers/api/v1/users/` (4 modules): profile.py, emails.py, mfa.py, admin.py
- **users.py** → `app/routers/users/` (5 modules): listing.py, creation.py, detail.py, emails.py, lifecycle.py

**Verification:** All 2174 tests pass. Test mock paths updated to target specific sub-modules.

---

## [REFACTOR] File Structure: Split app/routers/api/v1/users.py

**Status:** Resolved (2026-02-06)

**Original Severity:** High

**Original Description:**
`app/routers/api/v1/users.py` was 1025 lines with 29 endpoints across multiple functional areas (profile, emails, MFA, admin CRUD, state management). Too large for efficient Claude traversability.

**Resolution:**
Split into `app/routers/api/v1/users/` package with 4 focused modules:
- `profile.py` (82 lines) - /roles, /me GET/PATCH (3 endpoints)
- `emails.py` (376 lines) - /me/emails/*, /{user_id}/emails/* (10 endpoints)
- `mfa.py` (246 lines) - /me/mfa/*, /{user_id}/mfa/reset (9 endpoints)
- `admin.py` (279 lines) - User CRUD + state management (8 endpoints)

Sub-modules access services via package import (`import routers.api.v1.users as _pkg`) to maintain test mock compatibility. The `__init__.py` re-exports services and email utilities for backwards compatibility with existing tests (no test changes required).

**Files Modified:**
- `app/routers/api/v1/users.py` - Deleted
- `app/routers/api/v1/users/__init__.py` - Created (combined router + re-exports)
- `app/routers/api/v1/users/profile.py` - Created
- `app/routers/api/v1/users/emails.py` - Created
- `app/routers/api/v1/users/mfa.py` - Created
- `app/routers/api/v1/users/admin.py` - Created

**Verification:** All 2174 tests pass with no test file changes.

---

## [TEST] Nested Patch Pyramids: test_utils_storage.py

**Status:** Resolved (2026-02-06)

**Original Severity:** Medium

**Original Description:**
67 instances of nested `with patch()` context managers in `tests/test_utils_storage.py`, with SpacesStorageBackend tests having 5-6 levels of nesting for settings patches.

**Resolution:**
Converted all nested `with patch()` to flat `mocker.patch()` calls. Extracted a `spaces_env` fixture that sets up the common boto3 mock and all Spaces settings patches, returning the mock client and boto3 module for per-test configuration. Local storage tests converted to single `mocker.patch()` calls. Backend selection tests flattened similarly.

**Files Modified:**
- `tests/test_utils_storage.py` - 67 nested patches eliminated, `spaces_env` fixture added

---

## [REFACTOR] Long Functions in Service Layer

**Status:** Resolved (2026-02-06)

**Original Severity:** Medium

**Original Description:**
Three service functions exceeded 100 lines:
- `update_user()` in `app/services/users.py` (~131 lines)
- `process_saml_response()` in `app/services/saml/auth.py` (~129 lines)
- `sync_user_idp_groups()` in `app/services/groups.py` (~119 lines)

**Resolution:**
Extracted focused helper functions to reduce each function's length without changing behavior:

1. **`app/services/users.py`**: Extracted `_validate_role_change()` (role escalation checks, last super_admin guard, authorization event logging) and `_fetch_user_detail()` (user lookup with emails and service status). `update_user()` dropped to ~50 lines, `get_user()` also simplified by reusing `_fetch_user_detail()`.

2. **`app/services/saml/auth.py`**: Extracted `_prepare_saml_auth()` (IdP config, SP cert, key decryption, settings construction, auth object creation) and `_extract_mapped_attributes()` (attribute extraction and mapping via IdP config). Eliminated duplication across `build_authn_request()`, `process_saml_response()`, and `process_saml_test_response()`.

3. **`app/services/groups.py`**: Extracted `_apply_membership_additions()` and `_apply_membership_removals()` (bulk add/remove with per-group event logging). `sync_user_idp_groups()` dropped to ~25 lines.

**Files Modified:**
- `app/services/users.py` - Extracted 2 helpers, simplified `update_user()` and `get_user()`
- `app/services/saml/auth.py` - Extracted 2 helpers, simplified 3 functions
- `app/services/groups.py` - Extracted 2 helpers, simplified `sync_user_idp_groups()`

**Verification:** All 2174 tests pass with no test file changes.

---

## [TEST] Duplicated Auth Override Pattern

**Status:** Resolved (2026-02-06)

**Original Severity:** High

**Original Description:**
The same 3-line auth dependency override pattern was duplicated 200+ times across 12+ router and API test files. Three files had local helpers, but these were file-local and still duplicated across files. A change to the auth dependency structure would require updating hundreds of locations.

**Resolution:**
Added two shared fixtures to `tests/conftest.py` and converted all test files to use them:

1. `override_auth(user, level="user")` for frontend router tests, with hierarchical level support (user < admin < super_admin)
2. `override_api_auth(user, level="admin")` for API tests

Converted 12 test files, removed redundant local helpers (`_setup_admin_overrides`, `_setup_member_overrides`, local `override_auth`), and removed all manual `app.dependency_overrides.clear()` calls (autouse fixture handles cleanup).

**Files Modified:**
- `tests/conftest.py` (added 2 fixtures)
- `tests/test_routers_account.py`, `test_routers_admin.py`, `test_routers_settings.py`, `test_routers_groups.py`, `test_routers_integrations.py`, `test_routers_users.py`, `test_routers_saml.py`, `test_routers_saml_crud_errors.py`, `test_routers_saml_domain_binding.py`, `test_routers_oauth2.py`, `test_api_users.py`, `test_api_groups.py`

**Net result:** 882 insertions, 2,278 deletions across 15 files. All 2,174 tests pass.

---

## [TEST] Nested Patch Pyramids: test_routers_auth.py

**Status:** Resolved (2026-02-06)

**Original Severity:** High

**Original Description:**
This file contained **104 instances** of nested `with patch()` context managers, typically 2-3 levels deep, with the deepest nesting reaching 8 levels in password-setting tests. Auth tests are critical path tests that need to be easy to read and modify.

**Resolution:**
Converted all nested `with patch()` context managers to flat `mocker.patch()` calls using pytest-mock fixture. The refactoring:

1. Added module path constants at the top of the file for cleaner patch targets:
   ```python
   AUTH_LOGIN = "routers.auth.login"
   AUTH_LOGOUT = "routers.auth.logout"
   AUTH_ONBOARDING = "routers.auth.onboarding"
   AUTH_DASHBOARD = "routers.auth.dashboard"
   AUTH_HELPERS = "routers.auth._helpers"
   DEPS_AUTH = "dependencies.auth"
   SERVICES_EMAILS = "services.emails"
   SERVICES_USERS = "services.users"
   UTILS_TEMPLATE = "utils.template_context"
   UTILS_PASSWORD = "utils.password"
   ```

2. Added `override_tenant()` helper to reduce auth dependency override boilerplate

3. Converted all nested patterns to flat `mocker.patch()` calls

4. Removed unused `from unittest.mock import patch` import

5. Removed manual `app.dependency_overrides.clear()` calls (handled by autouse fixture in conftest.py)

**Files Modified:**
- `tests/test_routers_auth.py` (104 patch calls converted to flat mocker.patch() calls)

**Verification:** All 54 tests in the file pass. Full suite (2174 tests) passes.

---

## [TEST] Nested Patch Pyramids: test_routers_users.py

**Status:** Resolved (2026-02-02)

**Original Severity:** High

**Original Description:**
This file contained **218 instances** of nested `with patch()` context managers, including pyramids up to 5 levels deep. This was the worst offender in the test suite.

**Resolution:**
Converted all 218 nested `with patch()` context managers to flat `mocker.patch()` calls using pytest-mock fixture. The refactoring:

1. Added module path constants at the top of the file for cleaner patch targets:
   ```python
   USERS_MODULE = "routers.users"
   SERVICES_USERS = "services.users"
   SERVICES_EMAILS = "services.emails"
   SERVICES_SETTINGS = "services.settings"
   SERVICES_ACTIVITY = "services.activity"
   DATABASE_SETTINGS = "database.settings"
   DATABASE_USERS = "database.users"
   ```

2. Converted nested patterns to flat patterns:
   ```python
   # Before (nested):
   with patch("services.settings.is_privileged_domain") as mock_privileged:
       with patch("services.users.create_user") as mock_create:
           mock_privileged.return_value = True
           # ... test code indented 8+ spaces

   # After (flat):
   def test_create_new_user_with_privileged_domain(test_admin_user, mocker):
       mock_privileged = mocker.patch(f"{SERVICES_SETTINGS}.is_privileged_domain")
       mock_create = mocker.patch(f"{SERVICES_USERS}.create_user")

       mock_privileged.return_value = True
       # ... test code at normal indentation
   ```

3. Added `mocker` parameter to all test functions that required mocking
4. Removed unused `from unittest.mock import patch` import

**Files Modified:**
- `tests/test_routers_users.py` (218 patch calls converted to flat mocker.patch() calls)

**Verification:** All 112 tests in the file pass.

---

## [REFACTOR] File Structure: Large Database Layer Files

**Status:** Resolved (2026-02-02)

**Original Severity:** High (Claude Traversability)

**Original Description:**
Four database modules exceeded 500 lines, making them harder for Claude to efficiently work with:
- `app/database/saml.py` (1112 lines)
- `app/database/users.py` (1003 lines)
- `app/database/groups.py` (936 lines)
- `app/database/oauth2.py` (842 lines)

**Resolution:**
Split each monolithic database module into focused sub-modules following the pattern established by `app/services/saml/`:

| Original File | New Directory | Sub-modules |
|--------------|---------------|-------------|
| `saml.py` | `saml/` | `certificates.py`, `providers.py`, `domains.py`, `security.py`, `debug.py` |
| `users.py` | `users/` | `core.py`, `profile.py`, `activity.py`, `lifecycle.py`, `listing.py`, `authentication.py`, `saml_assignment.py`, `_utils.py` |
| `groups.py` | `groups/` | `core.py`, `listing.py`, `memberships.py`, `relationships.py`, `lineage.py`, `selection.py`, `idp.py` |
| `oauth2.py` | `oauth2/` | `clients.py`, `authorization.py`, `tokens.py` |

Each directory includes an `__init__.py` that re-exports all public functions for backwards compatibility. Existing code using `from database import saml` or `import database.users` continues to work unchanged.

**Files Modified:**
- Created 4 new directories under `app/database/`
- Created 24 new sub-module files
- Deleted 4 original monolithic files

**Verification:** All 2174 tests pass.

---

## [REFACTOR] Dead Code: Unused Converter Functions

**Status:** Resolved (2026-02-01)

**Original Severity:** Medium

**Original Description:** Four converter functions in `app/routers/api/v1/users.py` were defined but never called: `_user_to_profile()`, `_user_to_summary()`, `_user_to_detail()`, and `_email_to_info()`. These existed because the services layer now returns Pydantic schemas directly, making router-level conversion unnecessary.

**Resolution:**
- Deleted all four unused converter functions (~65 lines)
- Removed unused `UserSummary` import

**Files Modified:**
- `app/routers/api/v1/users.py` - Removed dead code

**Verification:** All 2174 tests pass. Linting and type checking clean.

---

## [DEPS] user-agents: Unmaintained Package Replaced with ua-parser

**Status:** Resolved (2026-01-31)

**Original Severity:** Low

**Original Description:** The `user-agents` package (v2.2.0) had not received updates since 2020 (>4 years). While still functional, it may not correctly parse modern user agent strings and could have undiscovered vulnerabilities.

**Resolution:**
- Replaced `user-agents` package with actively maintained `ua-parser` package
- Rewrote `parse_device_from_user_agent()` function in `app/utils/request_metadata.py` with heuristic-based device type detection (since ua-parser has a different API without `is_mobile`, `is_tablet`, etc.)
- Updated mypy configuration in `pyproject.toml` to use `ua_parser.*` instead of `user_agents.*`

**Files Modified:**
- `pyproject.toml` - Swapped dependencies and updated mypy config
- `app/utils/request_metadata.py` - Updated import and rewrote device parsing function

**Verification:** All 22 request metadata tests pass. Device detection for mobile, tablet, desktop, and bot user agents works correctly.

---

## [TECH-DEBT] CSRF Protection Backstop Test Added

**Status:** Resolved (2026-01-31)

**Original Severity:** Low

**Original Description:** No static analysis test existed to verify all non-GET frontend routes have CSRF protection. This created risk of future regressions where a developer adds a POST/PUT/DELETE route without CSRF protection.

**Resolution:**
- Created `tests/test_csrf_route_coverage.py` with static analysis tests
- Tests parse frontend router files using AST to identify all non-GET routes
- Verifies CSRFMiddleware is registered in `app/main.py`
- Verifies all CSRF exempt paths are documented with justification
- Verifies no frontend routes accidentally use exempt path prefixes
- Documents intentionally exempt routes (SAML ACS, OAuth2 token endpoint)

**Files Created:**
- `tests/test_csrf_route_coverage.py` - New test file with 5 tests

**Verification:** All 5 CSRF route coverage tests pass.

---

## [SECURITY] OpenAPI/Swagger Debug Endpoints Exposed in Production

**Status:** Resolved (2026-01-25)

**Found in:** `app/main.py:47-48`

**Original Severity:** Medium (downgraded from original assessment due to open source context)

**OWASP Category:** A05:2021 - Security Misconfiguration

**Original Description:** The `/docs` (Swagger UI), `/redoc` (ReDoc UI), and `/openapi.json` endpoints were accessible without authentication in production. This exposed the complete API structure, endpoint paths, and parameter schemas to unauthenticated users.

**Risk:** Information disclosure that aids attackers in mapping the API surface. However, since the codebase is open source (MIT licensed), the API structure is already publicly visible in the code. The main risk is exposing instance-specific details like server URLs, enabled/disabled features, and version information.

**Resolution:**
- Added `ENABLE_OPENAPI_DOCS` environment variable to `app/settings.py` (defaults to `False`)
- Modified FastAPI app initialization in `app/main.py` to conditionally set `openapi_url`, `docs_url`, and `redoc_url` to `None` when disabled
- When set to `None`, FastAPI completely disables these endpoints (404 response)
- Updated `.env`, `.env.dev.example` to set `ENABLE_OPENAPI_DOCS=true` for development convenience
- Updated `.env.onprem.example` to set `ENABLE_OPENAPI_DOCS=false` with production guidance
- Added `tests/test_openapi_endpoints.py` with comprehensive test coverage
- Updated test configuration in `tests/conftest.py` to enable OpenAPI docs for tests

**Implementation Approach:** Environment variable toggle (simple, no database changes, follows existing patterns like `BYPASS_OTP`)

**Why This Approach:** Given the open source context, a simple environment variable provides sufficient control without over-engineering. Production operators can enable docs if needed for debugging, while keeping them disabled by default for professional appearance and defense in depth.

**Files Modified:**
- `app/settings.py` - Added `ENABLE_OPENAPI_DOCS` variable
- `app/main.py` - Conditional OpenAPI URL configuration
- `.env` - Added `ENABLE_OPENAPI_DOCS=true`
- `.env.dev.example` - Added `ENABLE_OPENAPI_DOCS=true`
- `.env.onprem.example` - Added `ENABLE_OPENAPI_DOCS=false` with documentation
- `tests/conftest.py` - Added `ENABLE_OPENAPI_DOCS=true` to test environment
- `tests/test_openapi_endpoints.py` - New test file

**Verification:** All 1832 tests pass. Type checking passes. Code formatted and linted.

---

## [CLEANUP] RequestingUser.request_metadata field is superfluous

**Status:** Resolved (2026-01-25)

**Found in:** `app/services/types.py`, `app/dependencies.py`, multiple service files

**Original Severity:** Low (Technical Debt)

**Original Description:** The `request_metadata` field in `RequestingUser` (defined in `app/services/types.py`) and the explicit passing pattern `request_metadata=requesting_user.get("request_metadata")` in `log_event()` calls were superfluous. Event request context (IP address, user agent, device, session) is handled automatically by `RequestContextMiddleware` which sets a contextvar for ALL web requests, and `log_event()` auto-reads from the contextvar if `request_metadata` not explicitly passed.

**Resolution:**
- Removed `request_metadata: NotRequired[dict[str, Any] | None]` field from `RequestingUser` TypedDict in `app/services/types.py`
- Removed unused `Any` and `NotRequired` imports from `app/services/types.py`
- Removed the if-block that populated `request_metadata` in `build_requesting_user()` in `app/dependencies.py`
- Removed unused `request_metadata` import from `app/dependencies.py`
- Removed all 37 occurrences of `request_metadata=requesting_user.get("request_metadata")` and `request_metadata=user.get("request_metadata")` from service files:
  - `app/services/users.py` (10 occurrences)
  - `app/services/saml.py` (15 occurrences)
  - `app/services/settings.py` (3 occurrences)
  - `app/services/emails.py` (3 occurrences)
  - `app/services/bg_tasks.py` (2 occurrences)
  - `app/services/reactivation.py` (3 occurrences)
  - `app/services/mfa.py` (1 occurrence)
- Updated `test_event_logging_creates_metadata_and_event` in `tests/test_database_event_log.py` to use `set_request_context()` to simulate middleware behavior
- Removed unused `build_requesting_user` import from test file

**Impact:**
- Removed ~40 lines of boilerplate code
- No functional changes - event logging behavior remains identical
- Request metadata continues to be auto-populated via `RequestContextMiddleware` contextvar mechanism
- Background jobs continue to use `system_context()` context manager

**Files Modified:**
- `app/services/types.py`
- `app/dependencies.py`
- `app/services/users.py`
- `app/services/saml.py`
- `app/services/settings.py`
- `app/services/emails.py`
- `app/services/bg_tasks.py`
- `app/services/reactivation.py`
- `app/services/mfa.py`
- `tests/test_database_event_log.py`

**Verification:** All 1829 tests pass. Type checking and linting pass.

---

## [BUG] SAML Router Route Ordering Bug - Phase 4 Endpoints Partially Unreachable

**Status:** Resolved (2026-01-19)

**Found in:** `app/routers/saml.py`

**Original Severity:** High

**Original Description:** FastAPI route ordering bug prevented two SAML Phase 4 endpoints from being reached. The parameterized route `/admin/identity-providers/{idp_id}` was defined before the literal routes `/admin/identity-providers/rotate-certificate` and `/admin/identity-providers/debug`, causing FastAPI to match "rotate-certificate" and "debug" as `idp_id` values.

**Resolution:**
- Moved `rotate_certificate` and `saml_debug_list` routes before the `{idp_id}` parameterized route (FastAPI matches routes in definition order)
- Added explanatory comment about route ordering requirements
- Updated section header for debug detail route to explain the split location
- Fixed test `test_debug_list_shows_entries` to mock with dicts instead of schema objects (matching real service behavior)
- Removed `@pytest.mark.xfail` decorators from 4 tests

**Files Modified:**
- `app/routers/saml.py` - Reordered route definitions
- `tests/test_routers_saml.py` - Removed xfail markers, fixed mock data format

**Verification:** All 53 SAML router tests pass.

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

## [SECURITY] Missing Security Headers

**Status:** Resolved (2026-01-17)

**Found in:** `app/main.py` (no security header middleware)

**Original Severity:** Medium

**OWASP Category:** A05:2021 - Security Misconfiguration

**Original Description:** Standard HTTP security headers were not configured (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy), increasing attack surface for XSS, clickjacking, and other client-side attacks.

**Resolution:**
- Created new `SecurityHeadersMiddleware` in `app/middleware/security_headers.py`
- Configured CSP to allow self-hosted resources, Tailwind inline styles, and QR code server for TOTP
- Added X-Frame-Options (DENY), X-Content-Type-Options (nosniff), HSTS (HTTPS only), and Referrer-Policy
- Registered middleware in `app/main.py` after CSRF middleware
- HSTS only applied on HTTPS connections (not in development)

**Files Modified:**
- `app/middleware/security_headers.py` (NEW) - Security headers middleware implementation
- `app/main.py` - Registered security headers middleware
- `tests/test_middleware_security_headers.py` (NEW) - Comprehensive test coverage (13 tests)

---

## [SECURITY] Raw Exceptions Exposed in OAuth2 Clients API

**Status:** Resolved (2026-01-17)

**Found in:** `app/routers/api/v1/oauth2_clients.py:87-88, 124-125`

**Original Severity:** Medium

**OWASP Category:** A02:2021 - Cryptographic Failures (Information Disclosure)

**Original Description:** Generic exceptions were caught and converted directly to HTTP response details using `str(e)`, potentially exposing SQL errors, database structure, or internal logic to attackers.

**Resolution:**
- Updated service layer to raise `ValidationError` instead of `ValueError` with descriptive error codes
- Updated router layer to catch `ServiceError` and use `translate_to_http_exception()` pattern
- Error responses now return safe, user-friendly messages without exposing internals

**Files Modified:**
- `app/services/oauth2.py` - Changed ValueError to ValidationError with error codes
- `app/routers/api/v1/oauth2_clients.py` - Added proper ServiceError handling pattern
- `tests/test_api_oauth2_clients.py` - Added 3 tests verifying safe error handling

---

## [SECURITY] Reflected XSS in SAML relay_state Parameter

**Status:** Resolved (2026-01-17)

**Found in:** `app/templates/saml_idp_select.html:24`, `app/routers/saml.py:389-391`

**Original Severity:** Medium

**OWASP Category:** A03:2021 - Injection

**Original Description:** The `relay_state` parameter was reflected into URLs without proper URL encoding, allowing XSS injection through malicious payloads like `javascript:alert('XSS')`.

**Resolution:**
- Added `| urlencode` filter to template rendering of relay_state
- Added `quote(relay_state, safe='')` in router redirect URL construction
- Both template and router now properly URL-encode relay_state parameter

**Files Modified:**
- `app/templates/saml_idp_select.html` - Added `| urlencode` filter
- `app/routers/saml.py` - Import quote() and use for relay_state encoding
- `tests/test_routers_saml.py` - Added 4 comprehensive XSS prevention tests

---

## [SECURITY] SQL f-string Patterns (Defense in Depth)

**Status:** Resolved (2026-01-17)

**Found in:** `app/database/_core.py:107, 123`, `app/database/users.py:300-324`, `app/database/saml.py:290-317`

**Original Severity:** Medium (Mitigated)

**OWASP Category:** A03:2021 - Injection

**Original Description:** Several database functions used f-strings to construct SQL queries. While currently mitigated by input validation, this pattern was fragile and lacked clear security documentation.

**Resolution:**
- Added comprehensive inline security comments explaining WHY f-strings are necessary (PostgreSQL limitations)
- Documented HOW safety is guaranteed (UUID validation, collation DB validation, field whitelists)
- Added warnings for future developers about maintaining validation
- No code changes needed as existing validation patterns are sufficient

**Files Modified:**
- `app/database/_core.py` - Enhanced security comments for SET LOCAL pattern (2 locations)
- `app/database/users.py` - Added comprehensive security documentation for dynamic ORDER BY
- `app/database/saml.py` - Added security documentation for dynamic SET clause construction

---

## [BUG] OAuth Tokens Not Revoked When User Disconnected from IdP

**Status:** Resolved (2026-01-19)

**Found in:** `app/services/saml.py:2129`

**Original Severity:** High

**Original Description:** When a user was disconnected from a SAML IdP (saml_idp_id set to NULL), they were correctly inactivated but their OAuth access tokens remained valid. This allowed continued API access after account lockout.

**Root Cause:** The `assign_user_idp()` function in saml.py bypassed the service layer when inactivating users. It called `database.users.inactivate_user()` directly instead of going through `services.users.inactivate_user()` which would also revoke tokens.

**Resolution:**
- Added `database.oauth2.revoke_all_user_tokens(tenant_id, user_id)` call after inactivating the user
- Removed `@pytest.mark.xfail` decorator from test
- Test now verifies OAuth tokens are properly revoked when users are disconnected from IdPs

**Files Modified:**
- `app/services/saml.py` - Added token revocation call after user inactivation
- `tests/test_services_saml.py` - Removed xfail marker and updated docstring

---


## [SECURITY] CSP unsafe-inline Weakens XSS Protection

**Status:** Resolved (2026-01-31)

**Found in:** `app/middleware/security_headers.py`

**Original Severity:** Low

**OWASP Category:** A05:2021 - Security Misconfiguration

**Original Description:** The Content Security Policy included `'unsafe-inline'` for both `script-src` and `style-src` directives, weakening XSS protection by allowing inline scripts and styles to execute.

**Resolution:**
Implemented per-request CSP nonces:
- Created `app/utils/csp_nonce.py` with `generate_csp_nonce()` and `get_csp_nonce()` functions
- Updated `app/utils/template_context.py` to include `csp_nonce` in template context
- Modified `app/middleware/security_headers.py` to build dynamic CSP with nonces
- Added `csp_nonce` to all direct-context routes in `auth.py`, `oauth2.py`, `saml.py`
- Added `nonce="{{ csp_nonce }}"` to all 17 inline `<script>` tags across 15 templates
- Created `tests/test_csp_nonce.py` with backstop test to prevent regressions

**Key Design Decision:** No database persistence needed. Nonces are stateless and per-request, stored in `request.state`, used in both CSP header and template scripts within the same response.

**Files Modified:**
- `app/utils/csp_nonce.py` (new)
- `app/utils/template_context.py`
- `app/middleware/security_headers.py`
- `app/routers/auth.py`, `app/routers/oauth2.py`, `app/routers/saml.py`
- 15 template files with inline scripts
- `tests/test_csp_nonce.py` (new)
- `tests/test_middleware_security_headers.py` (updated expectations)

**Verification:** All 1983 tests pass. Type checking passes.

---

## [TD-001] Inline JavaScript Event Handlers Blocked by CSP

**Status:** Resolved (2026-01-31)

**Original Severity:** High

**Category:** Security / UX

**Original Description:** Many templates used inline JavaScript event handlers (e.g., `onclick="window.location='...'"`, `onclick="showModal()"`). These were blocked by the Content Security Policy which uses nonces for script execution. Only `<script nonce="...">` blocks execute; inline event attributes were silently ignored. This caused buttons, modals, and clickable elements to fail silently.

**Resolution:**
Migrated all 50+ inline event handlers across 14 templates to use CSP-compliant event listeners attached from nonce-protected script blocks.

**Patterns Applied:**
1. **Modal/Function Calls**: `onclick="showModal()"` → `id="show-modal-btn"` + `addEventListener('click', showModal)`
2. **Confirm Dialogs**: `onclick="return confirm('...')"` → `class="confirm-btn" data-confirm="..."` + delegated listener
3. **Copy to Clipboard**: `onclick="copyToClipboard('id')"` → `class="copy-btn" data-target="id"` + delegated listener
4. **Select/Navigation**: `onchange="window.location='?'+this.value"` → `id` + `addEventListener('change', ...)`
5. **Clickable Rows**: `onclick="window.location='...'"` → `class="clickable-row" data-href="..."` + delegated listener
6. **Disabled Pagination**: `onclick="return false;"` → `href="#"` when disabled + `aria-disabled="true"`

**Templates Fixed:**
- Phase 1: `integrations_b2b_detail.html`, `integrations_b2b.html`, `integrations_apps.html`, `integrations_app_detail.html`
- Phase 2: `saml_idp_list.html`, `saml_idp_form.html`, `saml_debug_detail.html`, `saml_test_result.html`
- Phase 3: `user_detail.html`, `settings_privileged_domains.html`, `admin_reactivation_requests.html`
- Phase 4: `admin_events.html`, `users_list.html`
- Phase 5: `mfa_backup_codes.html`

**Prevention Test Added:**
Added `TestInlineEventHandlerBackstop` class to `tests/test_csp_nonce.py` with regex-based static analysis to prevent future inline event handler regressions. The test scans all templates for `onclick=`, `onchange=`, `onsubmit=`, etc. and fails if any are found.

**Verification:** All 1977 tests pass. Backstop test confirms 0 inline handlers remaining.

---

## [DEPS] python-multipart: CVE-2026-24486 - Path Traversal

**Status:** Resolved (2026-02-01)

**Original Severity:** High (CVSS: 8.6)

**Package:** python-multipart 0.0.18

**Description:** A path traversal vulnerability exists when using non-default configuration options UPLOAD_DIR and UPLOAD_KEEP_FILENAME=True. An attacker can write uploaded files to arbitrary locations on the filesystem by crafting a malicious filename that begins with `/`.

**Exploitability in This Project:** Low. This project does not use UPLOAD_DIR or UPLOAD_KEEP_FILENAME configurations. The multipart parsing is only used for form data (CSRF tokens), not file uploads.

**Resolution:** Updated python-multipart from 0.0.18 to 0.0.22 via `poetry add "python-multipart@^0.0.22"`.

**Files Modified:**
- `pyproject.toml` - Updated version constraint
- `poetry.lock` - Updated lockfile

**Verification:** All 2151 tests pass.

---

## [TECH-DEBT] Service Layer Architecture: Groups Router Bypasses Service Layer

**Status:** Resolved (2026-02-01)

**Original Severity:** High

**Principle Violated:** Service Layer Architecture

**Original Description:** The groups router directly imported and used the `database` module, bypassing the service layer. This violated the layered architecture principle where routers should only call service functions.

Lines affected:
- Line 5: `import database`
- Lines 157-166: Direct database calls for dropdown data

**Impact:**
- Bypassed activity tracking (reads not tracked via `track_activity()`)
- Bypassed authorization checks that would be enforced in service layer
- Broke architectural consistency and maintainability

**Resolution:**
1. Added new schemas in `app/schemas/groups.py`:
   - `AvailableUserOption` - User option for dropdown selections
   - `AvailableGroupOption` - Group option for dropdown selections

2. Added new service functions in `app/services/groups.py`:
   - `list_available_users_for_group()` - Returns users not already group members
   - `list_available_parents()` - Returns groups valid as parents
   - `list_available_children()` - Returns groups valid as children

   All functions include proper authorization (`_require_admin()`), activity tracking (`track_activity()`), and group existence validation.

3. Updated `app/routers/groups.py`:
   - Removed `import database`
   - Updated `group_detail()` to call new service functions

4. Updated tests in `tests/test_routers_groups.py`:
   - Changed mocks from database functions to service functions

5. Added 7 unit tests in `tests/test_services_groups.py`:
   - `test_list_available_users_for_group_success`
   - `test_list_available_users_for_group_not_found`
   - `test_list_available_users_for_group_forbidden`
   - `test_list_available_parents_success`
   - `test_list_available_parents_not_found`
   - `test_list_available_children_success`
   - `test_list_available_children_not_found`

**Files Modified:**
- `app/schemas/groups.py` - Added dropdown option schemas
- `app/services/groups.py` - Added 3 service functions
- `app/routers/groups.py` - Removed database import, use service layer
- `tests/test_routers_groups.py` - Updated mocks
- `tests/test_services_groups.py` - Added 7 tests

**Verification:** All 2151 tests pass. Compliance check shows 0 violations.

---

## [REFACTOR] God Module - saml.py (2,658 lines, 45 functions)

**Status:** Resolved (2026-02-01)

**Original Severity:** High

**Category:** Code Quality / Tech Debt

**Original Description:** The `app/services/saml.py` file had grown to 2,658 lines with 45+ functions, making it difficult to navigate, test, and maintain. This monolithic structure violated the Single Responsibility Principle and created a high cognitive load for developers.

**Resolution:**
Split the monolithic file into 10 focused sub-modules under `app/services/saml/`:

| Module | Responsibility | ~Lines |
|--------|---------------|--------|
| `_converters.py` | Row-to-schema conversion helpers | ~50 |
| `_helpers.py` | SAML attribute extraction helpers | ~50 |
| `auth.py` | SAML AuthnRequest/Response processing | ~450 |
| `certificates.py` | SP certificate management | ~200 |
| `debug.py` | Debug entry storage | ~100 |
| `domains.py` | Domain binding operations | ~500 |
| `logout.py` | Single Logout (SLO) flows | ~200 |
| `metadata.py` | Metadata import and refresh | ~325 |
| `providers.py` | IdP CRUD operations | ~400 |
| `provisioning.py` | JIT provisioning and SAML auth completion | ~240 |
| `routing.py` | Authentication routing logic | ~100 |
| `__init__.py` | Re-exports for backwards compatibility | ~175 |

**Key Design Decisions:**
- **Backwards Compatibility:** The `__init__.py` re-exports all public functions, so existing code using `from services import saml as saml_service` continues to work unchanged
- **Private Helpers:** Shared utilities prefixed with underscore (`_converters.py`, `_helpers.py`) are also re-exported with underscore prefix for backwards compatibility
- **Import Timing:** The `OneLogin_Saml2_Auth` class is imported inside functions (not at module level) to support test monkeypatching patterns

**Files Created:**
- `app/services/saml/__init__.py`
- `app/services/saml/_converters.py`
- `app/services/saml/_helpers.py`
- `app/services/saml/auth.py`
- `app/services/saml/certificates.py`
- `app/services/saml/debug.py`
- `app/services/saml/domains.py`
- `app/services/saml/logout.py`
- `app/services/saml/metadata.py`
- `app/services/saml/providers.py`
- `app/services/saml/provisioning.py`
- `app/services/saml/routing.py`

**Files Deleted:**
- `app/services/saml.py` (original 2,658 line file)

**Verification:** All 2167 tests pass. Ruff check and mypy pass with no issues.

---

## [DEPS] ecdsa: CVE-2024-23342 - Minerva Timing Attack (Transitive)

**Status:** Resolved (2026-02-02)

**Original Severity:** High (CVSS: 7.4)

**Package:** ecdsa 0.19.1 (transitive via sendgrid 6.12.4)

**Advisory:** https://github.com/advisories/GHSA-wj6h-64fc-37mp

**Original Description:**
The python-ecdsa library was vulnerable to the Minerva timing attack on P-256 curve operations. The maintainers stated they had no plans to fix it because implementing side-channel-free code in pure Python is impossible. This was a transitive dependency of the sendgrid package.

**Exploitability in This Project:**
Low. The ecdsa package was only used internally by sendgrid for token signing. Exploitation would have required measuring timing of hundreds of signing operations.

**Resolution:**
Updated sendgrid from 6.12.4 to 6.12.5. The new version replaced the ecdsa dependency with pyca/cryptography (PR #1114), eliminating the vulnerability entirely.

```bash
poetry update sendgrid
```

**Files Modified:**
- `pyproject.toml` - Updated via poetry
- `poetry.lock` - Updated lockfile

**Verification:** `poetry run python -m pip_audit` shows no known vulnerabilities.

---

## [TEST] Nested Patch Pyramids: Remaining Files

**Status:** Resolved (2026-02-06)

**Original Severity:** Low-Medium

**Category:** Test Code / Maintainability

**Original Description:**
The following files had deeply nested `with patch()` blocks (2-6 levels deep):
- `tests/test_routers_admin.py` (11 tests with nested patches)
- `tests/test_utils_email.py` (2 tests with 3-6 level nesting)
- `tests/test_email_backends.py` (3 tests with 2-4 level nesting)

Note: `tests/test_api_users.py`, `tests/test_services_users.py`, and `tests/test_api_groups.py` were found to already use flat patterns (comma-separated context managers or single-level patches).

**Resolution:**
Converted all deeply nested `with patch():` blocks to flat `mocker.patch()` calls using the pytest-mock fixture.

**Pattern Applied:**
```python
# Before (nested):
with patch("a") as mock_a:
    with patch("b") as mock_b:
        with patch("c") as mock_c:
            # test code

# After (flat):
mock_a = mocker.patch("a")
mock_b = mocker.patch("b")
mock_c = mocker.patch("c")
# test code
```

**Files Modified:**
- `tests/test_routers_admin.py` - Flattened 11 tests
- `tests/test_utils_email.py` - Flattened 2 tests
- `tests/test_email_backends.py` - Flattened 3 tests

**Verification:** All 66 tests across the 3 modified files pass. Ruff check passes.

---

## [REFACTOR] Duplication: Authorization Helpers Repeated Across Services

**Status:** Resolved (2026-02-01)

**Original Severity:** High

**Category:** Duplication

**Original Description:** The `_require_admin()` helper function was duplicated 9 times across service modules with 3 inconsistent variants. Similarly, `_require_super_admin()` was duplicated 3 times with 2 variants. This created bug risk (changes required in 12 places) and inconsistency (some logged failures, some didn't).

**Resolution:**
- Created `app/services/auth.py` with centralized `require_admin()` and `require_super_admin()` functions
- Functions support optional logging via `log_failure` parameter
- Updated 8 service files to use centralized functions
- `event_log.py` kept local copy to avoid circular import
- Reduced duplication from 12 function definitions to 3

**Files Modified:**
- `app/services/auth.py` (new)
- 8 service files (settings.py, bg_tasks.py, groups.py, emails.py, users.py, exports.py, reactivation.py, mfa.py, saml.py)

---

## [REFACTOR] Architecture: Event Logging in Routers

**Status:** Resolved (2026-02-06) - Accepted as Architectural Exception

**Original Severity:** Low

**Category:** Coupling / Consistency

**Original Description:**
5 direct `log_event()` calls existed in routers:
- `auth/login.py` - login_failed (invalid credentials)
- `auth/login.py` - login_failed (inactivated user)
- `auth/logout.py` - user_signed_out
- `auth/onboarding.py` - password_set
- `mfa.py:132` - user_signed_in

Per the architectural pattern ("all writes go through service layer"), event logging should occur in services, not routers.

**Resolution:**
Accepted as an architectural exception for authentication flows. Authentication events (login_failed, user_signed_out, password_set, user_signed_in) are fundamentally tied to session management which occurs at the router level. These are not business logic mutations but security-relevant authentication state changes.

Added documentation comments to each affected file explaining the exception:
- `app/routers/auth/login.py`
- `app/routers/auth/logout.py`
- `app/routers/auth/onboarding.py`
- `app/routers/mfa.py`

Creating a thin auth service wrapper would add unnecessary indirection without architectural benefit.

---

## [TEST] Magic Indices in Assertions

**Status:** Resolved (2026-02-06)

**Original Severity:** Low

**Category:** Test Code / Readability

**Original Description:**
Tests used positional indices to access mock call arguments without clarifying what each index represents (e.g., `call_args[0][2]` instead of named destructuring).

**Resolution:**
Refactored ~50 instances across test files to use clearer patterns:
- Destructuring: `task_id, error_message = call_args[0]`
- Named extraction: `template_name = mock_tmpl.call_args[0][0]`
- Inline comments where destructuring wasn't practical

**Files Modified:**
- `tests/test_worker.py`
- `tests/test_routers_integrations.py`
- `tests/test_routers_users.py`
- `tests/test_routers_account.py`
- `tests/test_services_activity.py`
- `tests/test_email_backends.py`
- `tests/test_utils_storage.py`
- `tests/test_routers_saml_security.py`
- `tests/test_jobs_export_events.py`
- `tests/test_api_reactivation.py`
- `tests/test_routers_groups.py`
- `tests/test_utils_service_errors.py`
- `tests/test_routers_auth_rate_limiting.py`

**Verification:** All 2174 tests pass.

---

## [DEPS] pip: CVE-2026-1703

**Status:** Resolved (2026-02-06) - Accepted as Low Risk

**Original Severity:** Unrated (path traversal)

**Package:** pip 25.3
**Fixed Version:** pip 26.0

**Original Description:**
Limited path traversal vulnerability when pip installs a maliciously crafted wheel archive. Files may be extracted outside the installation directory, though traversal is limited to prefixes of the installation directory.

**Resolution:**
Accepted as low risk for the following reasons:
1. pip is a development tool, not a runtime dependency
2. Exploitation requires installing a maliciously crafted wheel
3. This project uses poetry lock files with pinned versions from PyPI
4. Risk only arises if a compromised package was published to PyPI with the exact name and version specified in dependencies

**Remediation for developers:** Run `pip install --upgrade pip` in local environments when pip 26.0+ becomes available.

---

## [REFACTOR] Dead code: Backwards-compat re-export in worker.py

**Status:** Resolved (2026-02-07)

**Original Severity:** Low

**Original Description:**
`register_handler()` was re-exported from `worker.py` for backwards compatibility, but no production code imported it from `worker`. The only consumer was its own test.

**Resolution:**
Removed the re-export function from `app/worker.py` and its corresponding test from `tests/test_worker.py`. No production imports existed.

**Files Changed:** `app/worker.py`, `tests/test_worker.py`

---

## [REFACTOR] Architecture: Missing event log for export download

**Status:** Resolved (2026-02-07)

**Original Severity:** Low

**Original Description:**
`get_download()` called `database.export_files.mark_downloaded()` (a DB write) without a corresponding `log_event()` call, violating the "if there is a write, there is a log" principle.

**Resolution:**
Added `export_downloaded` event type and a `log_event()` call after `mark_downloaded()` in `get_download()`. Added test coverage for the new event log.

**Files Changed:** `app/services/exports.py`, `app/constants/event_types.py`, `app/constants/event_types.lock`, `tests/test_services_exports.py`

---

## [SECURITY] SQL Injection via String Interpolation in Bulk Group Insert

**Status:** Resolved (2026-02-08)

**Found in:** `app/database/groups/idp.py:147`

**Original Severity:** High

**Principle Violated:** Tenant Isolation (parameterized query safety)

**Original Description:**
`bulk_add_user_to_groups()` built SQL VALUES via f-string interpolation instead of parameterized queries. The `group_ids`, `tenant_id_value`, and `user_id` values were inserted directly into the SQL string. While all current callers passed database-generated UUIDs (low immediate risk), the pattern was unsafe and would become dangerous if any future caller passed user-controlled input.

**Resolution:**
Replaced the f-string bulk insert with a parameterized loop. Each group ID is inserted via a parameterized `INSERT ... ON CONFLICT DO NOTHING` within the same transaction. The loop is appropriate because group counts are always small (< 20), and it preserves accurate rowcount tracking.

**Files Modified:**
- `app/database/groups/idp.py` - Replaced f-string SQL with parameterized loop

---

## ISSUE-003: Router directly imports database in SAML IdP SSO consent

**Status:** Resolved (2026-02-12)

**Original Severity:** High

**Principle Violated:** Service Layer Architecture

**Original Description:**
The `consent_page()` route handler in `app/routers/saml_idp/sso.py` imported `database` directly (as a local import) to fetch user info and primary email for the consent screen. Routers must never import database modules directly.

**Resolution:**
Added `get_user_consent_info()` service function to `app/services/service_providers.py` that fetches user display info (email, first_name, last_name). The router now calls this service function instead of importing the database layer.

**Files Modified:**
- `app/services/service_providers.py` - Added `get_user_consent_info()`
- `app/routers/saml_idp/sso.py` - Replaced `import database` with service call
- `tests/test_routers_saml_idp_sso.py` - Updated mock targets
- `tests/test_services_service_providers_sso.py` - Added unit tests for new function

---

## ISSUE-004: sso_consent_denied event silently dropped due to empty artifact_id

**Status:** Resolved (2026-02-12)

**Original Severity:** High

**Principle Violated:** Activity Logging

**Original Description:**
The `log_event()` call for `sso_consent_denied` in `consent_respond()` passed `artifact_id=""` (empty string). The `event_logs.artifact_id` column is `UUID NOT NULL`, so the empty string failed PostgreSQL UUID validation and the INSERT was silently rejected. SSO consent denials were never recorded in the audit log.

**Resolution:**
Store the SP's UUID (`sp.id`) in the session as `pending_sso_sp_id` alongside the existing entity_id. Use that UUID as `artifact_id` in the consent denied event. Added `pending_sso_sp_id` to `PENDING_SSO_KEYS` and the session cleanup list.

**Files Modified:**
- `app/routers/saml_idp/sso.py` - Store SP UUID in session, use as artifact_id
- `app/routers/saml_idp/_helpers.py` - Added key to `PENDING_SSO_KEYS`
- `tests/test_routers_saml_idp_sso.py` - Added SP ID to mock sessions, verified artifact_id

---
