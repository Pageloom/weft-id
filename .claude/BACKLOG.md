# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Custom User Fields

**Status:** Grooming

**Summary:** Admin-defined custom fields on user profiles. Supported types: one-line text, multiline text, single-select, multi-select, currency, time, duration, date, datetime.

**Effort:** XL
**Value:** High

---

## Create `/accessibility` Skill

**User Story:**
As a developer,
I want an `/accessibility` skill that audits the frontend for WCAG 2.1 AA compliance,
So that accessibility issues are identified and tracked systematically like security and compliance violations.

**Acceptance Criteria:**

- [ ] New skill file at `.claude/skills/accessibility/` following the pattern of existing skills
- [ ] Skill audits Jinja2 templates for WCAG 2.1 AA violations (missing alt text, insufficient contrast cues, missing form labels, ARIA misuse, keyboard navigation gaps, missing lang attributes, missing focus indicators)
- [ ] Skill logs findings to `ISSUES.md` in the same format as `/security` and `/compliance`
- [ ] Skill references a checklist in `.claude/references/wcag-patterns.md`
- [ ] Skill can be invoked with `/accessibility` from Claude Code

**Effort:** M
**Value:** Medium

---

## Dyslexic-Friendly Font User Preference

**User Story:**
As a user with dyslexia,
I want to enable a dyslexic-friendly font in my account settings,
So that the interface is more readable for me without affecting other users.

**Acceptance Criteria:**

- [ ] A font preference field is added to the user profile (boolean, default false)
- [ ] Database migration adds the column to the `users` table
- [ ] User can toggle the preference in their profile/settings page
- [ ] When enabled, the selected dyslexic-friendly font (e.g. OpenDyslexic or Atkinson Hyperlegible) is applied via a CSS class on the `<html>` or `<body>` element
- [ ] Font is served from static assets (not an external CDN) for privacy and reliability
- [ ] Preference persists across sessions (stored server-side)
- [ ] **No audit log** for this write (follows the `save_graph_layout()` pattern: it is UI preference state, not a business action). The service function docstring must note this explicitly.
- [ ] `track_activity()` is called (instead of `log_event()`) so the user's `last_activity_at` is still updated
- [ ] API endpoint exposes the preference for programmatic access

**Effort:** M
**Value:** Medium

---

## Admin Notification on Auto-Inactivation

**User Story:**
As an admin,
I want to receive an email summary when the system auto-inactivates users due to inactivity,
So that I'm aware of account changes happening automatically and can intervene if needed.

**Context:**

The daily inactivation job (`inactivate_idle_users`) currently runs silently. When it
inactivates users, the only record is in the audit log. Admins may not check the audit
log daily. A summary email after each run that actually inactivated someone keeps admins
informed without requiring them to monitor logs.

**Acceptance Criteria:**

- [ ] After the daily inactivation job completes, if any users were inactivated, send an email to all admins and super admins in the tenant
- [ ] Email subject: "WeftID: N user(s) inactivated due to inactivity"
- [ ] Email body includes: count, list of affected users (name, email, last activity date), the tenant's configured threshold
- [ ] No email sent if zero users were inactivated (avoid noise)
- [ ] Uses the shared email layout with tenant branding
- [ ] Email function added to `app/utils/email.py` following existing patterns

**Effort:** S
**Value:** Medium
**Version impact:** Patch (enhancement to existing feature)

---

## Passkey Authentication & Tenant Auth Policy

**User Story:**
As a super admin,
I want to require strong authentication (TOTP or passkey) for my tenant's users,
So that accounts are protected beyond email-based verification.

As a user,
I want to sign in with a passkey (biometric prompt) instead of typing passwords and codes,
So that authentication is faster and phishing-resistant.

**Context:**

WeftID currently supports password + email OTP as the baseline, with optional TOTP upgrade.
There is no tenant-level control over which authentication methods are required. The
`require_platform_mfa` flag on SAML IdPs exists in the schema and admin UI but is not
enforced in the SSO flow (bug). This feature introduces passkeys (WebAuthn/FIDO2) as a
passwordless primary auth method and gives super admins control over minimum auth strength.

**Tenant Auth Policy Model:**

Super admins configure the minimum authentication strength for their tenant:

* **Baseline** (default): Password + email OTP. Current behavior, no change.
* **Enhanced**: Super admin declares email OTP insufficient. Users must set up TOTP
  and/or passkey (admin controls which methods are allowed):
  * TOTP and passkey (user chooses one or both)
  * TOTP only
  * Passkey only

**Passkey Login Flow:**

1. User visits login page
2. Clicks "Sign in with passkey"
3. Browser/OS prompts biometric (Face ID, fingerprint, Windows Hello)
4. On success: fully authenticated. No password, no email code, no MFA step
5. Proceeds to dashboard (or SSO consent if SP-initiated)

**Passkey Registration:**

* Users register passkeys in account settings (opt-in regardless of tenant policy)
* Multiple passkeys supported (each named by the user, e.g. "MacBook", "iPhone")
* Registration generates backup codes (same pattern as TOTP)
* WebAuthn discoverable credentials (resident keys) with user verification required

**Coexistence (TOTP + Passkey):**

A user can have both TOTP and passkey registered. Login defaults to passkey when
available. A "Can't use passkey? Use one-time code" link falls back to password +
TOTP/email flow.

**Enforcement Flow (Enhanced Policy):**

When super admin enables enhanced auth and a user has not yet set up a qualifying method:

1. User signs in with email two-step (baseline) as normal
2. After successful baseline auth, redirected to setup page
3. User must register a passkey or set up TOTP (depending on allowed methods)
4. Cannot access dashboard, cannot complete SP-initiated IdP SSO until setup is done
5. Follows the same redirect-and-block pattern as forced password reset

**Recovery:**

* Backup codes: generated at passkey registration (like TOTP). Can be used when passkey
  device is unavailable.
* Admin recovery: admin can reset a user back to baseline auth (email OTP), clearing
  their enhanced auth requirement. User would need to set up again if tenant policy
  still requires enhanced auth.

**Platform MFA for IdP-Authenticated Users:**

The existing `require_platform_mfa` flag on SAML identity providers must be enforced.
When enabled, after successful SAML authentication, the user must complete their
configured two-step verification method before proceeding:

* If user has passkey: passkey prompt
* If user has TOTP: TOTP code entry
* Baseline: email OTP

**Admin Management:**

* Tenant security settings page: auth policy configuration (baseline/enhanced, allowed methods)
* User detail view: shows registered passkeys (name, created date, last used)
* Admin can revoke individual passkeys
* Admin can reset user to baseline auth
* User list: filterable by auth method (email, TOTP, passkey)

**Acceptance Criteria:**

*Tenant auth policy:*
- [ ] New tenant security setting: `required_auth_strength` (`baseline` | `enhanced`)
- [ ] New tenant security setting: `allowed_enhanced_methods` (controls which methods are available when enhanced)
- [ ] Super admin UI to configure auth policy on tenant security settings page
- [ ] Default: baseline (no change to existing behavior)
- [ ] API endpoints for reading/updating tenant auth policy

*Passkey registration:*
- [ ] `webauthn_credentials` table (user_id, tenant_id, credential_id, public_key, sign_count, name, created_at, last_used_at, etc.)
- [ ] Migration for new tables and tenant settings columns
- [ ] Account settings page: register new passkey (WebAuthn registration ceremony)
- [ ] Support multiple passkeys per user, each with a user-provided name
- [ ] Backup codes generated at passkey registration (same pattern as TOTP)
- [ ] Account settings: list registered passkeys with name, created date, last used
- [ ] Account settings: delete individual passkeys
- [ ] API endpoints for passkey registration, listing, and deletion

*Passkey authentication:*
- [ ] Login page: "Sign in with passkey" option (WebAuthn authentication ceremony)
- [ ] Successful passkey auth: fully authenticated, skip password and MFA
- [ ] Passkey bound to tenant subdomain (RP ID = tenant domain for isolation)
- [ ] User verification required (biometric/PIN, not just presence)
- [ ] Sign count tracked and validated to detect cloned credentials
- [ ] `user_signed_in` event logged with `method: "passkey"` in metadata

*Coexistence and fallback:*
- [ ] Users with both TOTP and passkey: login defaults to passkey
- [ ] "Can't use passkey? Use one-time code" falls back to password + TOTP/email flow
- [ ] Backup codes usable as fallback for passkey-only users

*Enforcement:*
- [ ] When enhanced auth required and user lacks qualifying method: redirect to setup after baseline login
- [ ] Setup page presents allowed methods (TOTP, passkey, or both)
- [ ] User cannot access dashboard until setup is complete
- [ ] User cannot complete SP-initiated SSO consent until setup is complete
- [ ] Follows forced-password-reset redirect-and-block pattern

*Recovery:*
- [ ] Admin can reset user to baseline auth (clears enhanced auth setup)
- [ ] Reset logs `user_auth_reset_to_baseline` event
- [ ] User re-enters enforcement flow on next login if tenant still requires enhanced

*Platform MFA enforcement (bug fix):*
- [ ] Enforce `require_platform_mfa` flag on SAML IdPs in the SSO flow
- [ ] After SAML auth, if flag set, require user's configured two-step method
- [ ] Supports passkey, TOTP, and email OTP based on user's method

*Admin tooling:*
- [ ] Tenant security settings: auth policy UI (baseline/enhanced, method selection)
- [ ] User detail: registered passkeys section (name, dates, revoke action)
- [ ] User list: filter by auth method
- [ ] Admin action: reset user to baseline auth

*Audit:*
- [ ] `passkey_registered`, `passkey_deleted`, `passkey_auth_success`, `passkey_auth_failure` event types
- [ ] `tenant_auth_policy_updated` event type
- [ ] `user_auth_reset_to_baseline` event type
- [ ] `platform_mfa_enforced` event type (for IdP users)
- [ ] `track_activity()` for read operations

**Effort:** XL
**Value:** High
**Version impact:** Minor (new feature, new tables, additive settings with defaults. Platform MFA enforcement is a bug fix bundled in.)

---

## HMAC-Based Export Data Verification

**User Story:**
As an admin sharing an audit export with a compliance auditor,
I want to prove that the data was generated by WeftID and has not been tampered with,
So that the auditor can trust the export as authentic evidence.

**Context:**

The verification target is the data content, not the XLSX file bytes. Excel files
change when opened, re-saved, or reformatted (column widths, fonts, etc.), so
HMACing the file itself would produce false negatives. Instead, HMAC the raw row
data in a canonical form before it enters openpyxl.

At verification time, the admin provides the file password and the XLSX. WeftID
extracts the cell values, serializes them in the same canonical form, and compares
the HMAC. This is format-independent: the data could even have been copied into
another spreadsheet and verification would still work.

The canonical form must be deterministic: fixed column order, consistent date
formatting, stable JSON key ordering for metadata, and a defined null representation.

**Acceptance Criteria:**

- [ ] Before building the workbook, serialize all export rows into a canonical form (e.g. newline-delimited JSON with sorted keys, fixed column order, ISO timestamps)
- [ ] Compute HMAC-SHA256 of the canonical bytes using a tenant-scoped HKDF-derived key
- [ ] Store the HMAC in the `export_files` record (new column, database migration)
- [ ] Add verification endpoint: `POST /api/v1/exports/{export_id}/verify` accepts file upload + password, decrypts, extracts cell values, re-serializes to canonical form, compares HMAC
- [ ] Admin UI: verification option on the background jobs page (upload file to check)
- [ ] Response clearly states "Data is authentic, generated by WeftID on [date]" or "Data does not match the original export"

**Effort:** S
**Value:** Low
**Version impact:** Patch (new endpoint, no breaking changes)

---

## Enforce Clean Unit/Integration Test Boundary

**User Story:**
As a developer,
I want tests to either fully mock the database or fully use it,
So that unit tests never leak queries to PostgreSQL, producing noisy error logs and hiding incomplete mocking.

**Problem:**
`tests/services/` and `tests/routers/` mix unit and integration patterns. Tests mock specific DB calls they care about but let side-effects (`track_activity`, `log_event`, `is_verbose_logging_active`) leak to the real database. This produced ~115 PG error log entries per test run. Temporary guards in conftest files reduce this to ~6, but the root cause is architectural.

**Acceptance Criteria:**
- [ ] Service and router conftest auto-mocks the database connection pool by default (nothing reaches PG)
- [ ] Tests that need real DB access opt in with `@pytest.mark.integration` (restores real pool)
- [ ] `tests/database/` remains unchanged (all integration by default, no marker needed)
- [ ] `tests/utils/` and `tests/jobs/` remain unchanged (already clean unit tests)
- [ ] Remove the UUID-validation guard fixtures from `tests/services/conftest.py` and `tests/routers/conftest.py` (no longer needed)
- [ ] Zero PG error log entries from unit tests (only expected constraint errors from database integration tests)
- [ ] All existing tests pass without modification (integration tests get the marker, unit tests work as-is)

**Effort:** M
**Value:** Medium (developer experience, test reliability, CI log clarity)
**Version impact:** None (test infrastructure only)
