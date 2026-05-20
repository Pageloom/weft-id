# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Docs: capture SCIM admin guide screenshots

**Status:** Backlog

**Summary:** `docs/admin-guide/service-providers/scim.md` ships with `TODO: screenshot - ...` placeholders at six locations (amber plaintext token box, credential list mid-rotation, sync activity panel mixed states, Slack provisioning page, GitHub Enterprise SCIM page, Atlassian directory provisioning, GitLab SAML SSO page). Capture the WeftID screenshots first (amber box, credential list, sync panel) since they can be staged against the dev testbed. Vendor screenshots require live tenants and can land later as access becomes available. Remove the `TODO:` lines once each image lands.

**Effort:** S
**Value:** Medium (lifts the docs above placeholder quality for outbound SCIM)

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

---

## Outbound SCIM (WeftID → Downstream Service Providers)

**User Story:**
As a tenant admin,
I want WeftID to expose a SCIM 2.0 endpoint per registered Service Provider,
So that downstream SaaS apps (Slack, Zoom, GitHub, Atlassian, etc.) can receive user and group changes in real time and deprovision access when a user is removed from WeftID.

**Context:**

Pure SAML cannot solve the "deprovisioned user retains downstream SaaS access" gap, because SAML only acts at login. SCIM closes the loop by letting WeftID push lifecycle and group-membership changes to each SP between logins.

This is the first piece of the "federation-native directory" positioning: it makes WeftID a directory *for* downstream apps, not just an SSO broker.

**Design Notes:**

- Endpoint shape: `/scim/v2/<sp-slug>/...`, served by a new `app/routers/scim/` package and `app/services/scim/` service layer.
- Auth: bearer token per SP, stored in a new SCIM-token table, with rotation (token versioning + overlap window).
- Scope of exposed users: **only users with SP access via existing group grants**, not the entire tenant directory. Adding/removing a user from a granting group must enqueue a SCIM push job to the SP (use the existing `app/jobs/` worker).
- DAG groups: default to projecting **effective (flattened) membership** via `group_lineage`; configurable per-SP to expose direct membership only when needed.
- SCIM 2.0 core: Users + Groups resources, Enterprise User extension. Skip bulk operations and exotic PATCH filter paths.
- Compatibility target: real-world SP implementations (Slack, Zoom, GitHub, Atlassian, Google Workspace's SCIM-out side) over RFC purity. Their quirks define "works."

**Acceptance Criteria:**

- [ ] Migration adds `scim_tokens` table (tenant-scoped, SP-scoped, supports rotation with overlap)
- [ ] `app/routers/scim/` package with endpoints under `/scim/v2/<sp-slug>/`:
  - [ ] `GET /Users`, `GET /Users/{id}`, `POST /Users`, `PUT /Users/{id}`, `PATCH /Users/{id}`, `DELETE /Users/{id}`
  - [ ] `GET /Groups`, `GET /Groups/{id}`, `POST /Groups`, `PUT /Groups/{id}`, `PATCH /Groups/{id}`, `DELETE /Groups/{id}`
  - [ ] `GET /ServiceProviderConfig`, `GET /ResourceTypes`, `GET /Schemas`
- [ ] `app/services/scim/` enforces SP scoping: only users granted access to the SP are visible
- [ ] Bearer-token auth middleware validates SCIM tokens, scopes the request to one SP
- [ ] DAG groups projected as flattened effective membership by default; per-SP setting for direct-only
- [ ] Change events on grants, group memberships, and user lifecycle enqueue SCIM push jobs
- [ ] Push jobs are idempotent and retry with backoff on transient failures
- [ ] Admin UI: SCIM token management per SP (create, rotate, revoke; secret shown once)
- [ ] API endpoints mirror admin UI per the API-first rule
- [ ] Audit events: `scim_token_created`, `scim_token_rotated`, `scim_token_revoked`, `scim_user_pushed`, `scim_group_pushed`, `scim_push_failed`
- [ ] Test coverage includes real-world request shapes from Slack, Okta SCIM client, and Entra SCIM client (recorded fixtures)
- [ ] Documentation page in `docs/admin-guide/` covering SCIM setup per SP

**Effort:** M (2–3 weeks focused work)
**Value:** High (single largest unlock for moving WeftID from "SSO broker" to "directory"; closes the deprovisioning gap that pure SAML cannot)
**Version impact:** Minor (new endpoints, new table, new auth surface, additive only)

**Dependencies:** None. Builds entirely on existing SP, user, group, and group-grant models.

---

## Inbound SCIM (Okta and Entra → WeftID)

**User Story:**
As a tenant admin whose company uses Okta or Entra as the source of truth,
I want my IdP to push user and group changes into WeftID via SCIM,
So that WeftID reflects directory state without waiting for users to log in, and downstream apps (via outbound SCIM) get changes promptly.

**Context:**

Today, WeftID only learns about a user when they log in (JIT). This means a deprovisioned upstream user is not removed from WeftID until their next (failed) login, and an admin cannot grant SP access to a user who has not yet logged in.

Inbound SCIM makes WeftID a true **reflection directory** rather than a JIT cache. Combined with outbound SCIM, this is the end-to-end "federation-native directory" story.

Explicitly scoped to **Okta and Entra** for the initial release. Those are the two SCIM 2.0 client implementations enterprises actually run, and their quirks define what "works" means more than the RFC does.

**Design Notes:**

- Endpoint shape: `/scim/v2/inbound/<idp-connection-id>/...`, bearer token per IdP connection.
- Reuses existing `group_type='idp'` (read-only externally-synced groups).
- Reuses existing user lifecycle states. SCIM DELETE maps to **soft-delete / deactivate** (never hard-delete; preserves MFA enrollment, audit history, granted access on reactivation).
- Conflict resolution: **SCIM-wins-always** for the initial release. Do not build a per-attribute mastering rules engine. Layer that on later only if a customer asks. Correct for the federation use case and ships faster.
- Idempotent merge on `externalId` or email: a user created by JIT login *before* SCIM provisioning catches up must be merged into the SCIM-managed user, not duplicated.
- Compatibility realities: Okta SCIM and Entra SCIM both claim 2.0 compliance and both have known quirks (Entra's batched PATCH semantics, Okta's group `members[]` add/remove patterns, both differ on `meta.resourceType` casing). Tests must use recorded request fixtures from real tenants.

**Acceptance Criteria:**

- [ ] Migration adds `scim_inbound_tokens` table tied to IdP connections
- [ ] `app/routers/scim/inbound/` package with endpoints under `/scim/v2/inbound/<idp-connection-id>/`:
  - [ ] Full Users CRUD (GET, POST, PUT, PATCH, DELETE)
  - [ ] Full Groups CRUD (GET, POST, PUT, PATCH, DELETE)
  - [ ] `GET /ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`
- [ ] Bearer-token auth middleware validates inbound SCIM tokens and scopes to one IdP connection
- [ ] Users created via inbound SCIM are merged with any pre-existing JIT user on `externalId` or canonical email match (no duplicates)
- [ ] DELETE soft-deletes (deactivates) the user, preserving MFA enrollment and audit history
- [ ] Groups created via inbound SCIM use `group_type='idp'` (read-only in WeftID)
- [ ] Group membership changes from SCIM update memberships and trigger any downstream outbound SCIM pushes
- [ ] **SCIM-wins-always:** any user/group attribute write from SCIM overrides local edits without conflict prompts
- [ ] Test fixtures cover real-world Okta and Entra request shapes (recorded from sandbox tenants)
- [ ] Admin UI: inbound SCIM token management per IdP connection
- [ ] Documentation page in `docs/admin-guide/` covering inbound SCIM setup for Okta and Entra (step-by-step screenshots)
- [ ] Audit events: `scim_inbound_token_created`, `scim_inbound_token_rotated`, `scim_inbound_token_revoked`, `scim_user_received`, `scim_group_received`, `scim_user_deactivated`, `scim_membership_synced`

**Effort:** M
**Value:** High (closes the JIT-only gap; required to be credible as a directory product; combined with outbound SCIM, completes the directory story)
**Version impact:** Minor (new endpoints, new table, no breaking changes to existing flows)

**Dependencies:**
- Independent of Outbound SCIM (can ship in either order), but the SCIM router/auth scaffolding from Outbound is reusable, so doing Inbound second is cheaper.
- Shares conflict-resolution plumbing and `group_type='idp'` integration with Google Workspace sync; whichever ships second of the two reuses the merge/soft-delete code.

---

## Google Workspace Directory Sync

**User Story:**
As a tenant admin whose company uses Google Workspace,
I want WeftID to sync users and groups from my Workspace customer domain,
So that my directory reflection works the same way it does for Okta and Entra customers, even though Google does not push SCIM.

**Context:**

Google Workspace does **not** implement SCIM 2.0. Directory provisioning uses the Google Admin SDK Directory API instead. This is a separate connector from inbound SCIM, not a variant of it.

The destination data model and conflict semantics are identical to inbound SCIM (creates `group_type='idp'` groups, soft-deletes on removal, Google-wins-always), so most of the merge/lifecycle code is shared.

Pull-based rather than push-based, because Workspace does not push directory events. Implemented as a scheduled job in `app/jobs/`.

**Design Notes:**

- Auth: OAuth2 service account with domain-wide delegation, or admin-consented OAuth2 app. Service account is the standard pattern for non-interactive directory sync.
- Sync surface: users (active, suspended, deleted) and groups (with members) from a Workspace customer domain.
- Pull cadence: scheduled job, configurable interval per tenant (default e.g. 15 minutes), plus an on-demand "sync now" admin action.
- Incremental sync where Google's API supports it (`syncToken` / change-list APIs), full sync otherwise. Full sync as a fallback when sync state is lost or first run.
- Reuses the inbound-SCIM merge/conflict/soft-delete code paths (idempotent merge on Google's `id` or canonical email; soft-delete on removal; Google-wins-always for attribute conflicts).
- Connector identity stored alongside other IdP connections so the admin UI is unified.

**Acceptance Criteria:**

- [ ] Migration adds `google_workspace_connections` table (tenant-scoped, holds service account credentials encrypted, customer domain, sync state, sync interval)
- [ ] Admin UI: connect Google Workspace (upload/paste service account key, specify customer domain, configure sync interval)
- [ ] Admin UI: "sync now" button, last sync time, last sync status, error surface
- [ ] Scheduled job in `app/jobs/` runs at the configured interval per connection
- [ ] On-demand sync enqueues a one-off job
- [ ] Incremental sync uses Google's change-list API where available; falls back to full sync
- [ ] Users created via Google sync are merged with any pre-existing JIT user on `externalId` (Google `id`) or canonical email match
- [ ] Removed users are soft-deleted (deactivated), preserving MFA enrollment and audit history
- [ ] Groups synced from Google use `group_type='idp'` (read-only in WeftID)
- [ ] **Google-wins-always** for attribute conflicts
- [ ] Service account key is encrypted at rest using existing HKDF-derived key infrastructure
- [ ] Audit events: `google_workspace_connection_created`, `google_workspace_connection_updated`, `google_workspace_connection_deleted`, `google_workspace_sync_started`, `google_workspace_sync_completed`, `google_workspace_sync_failed`, `google_workspace_user_synced`, `google_workspace_user_deactivated`, `google_workspace_group_synced`
- [ ] Documentation page in `docs/admin-guide/` covering Google Workspace setup (service account creation in Google Cloud, domain-wide delegation, scope grants, connection in WeftID)
- [ ] Test coverage with mocked Google Admin SDK responses (no live API calls in tests)

**Effort:** M
**Value:** High (Google Workspace is the third major enterprise IdP; without it, the reflection-directory story has a gap that prospects will probe)
**Version impact:** Minor (new connector, new table, new job, new scopes; no breaking changes)

**Dependencies:**
- Reuses the merge/soft-delete/conflict-resolution plumbing from **Inbound SCIM**. Whichever of the two ships second is cheaper. Recommended order: Inbound SCIM first (it establishes the reflection-directory data flow and is more familiar territory), then Google Workspace as the second connector.
- Independent of **Outbound SCIM**, but most valuable when combined with it (sync in from Google → push out to downstream apps).

---

## Outbound SCIM: Additional Vendor Quirks and Connector Types

**User Story:**
As a tenant admin,
I want WeftID's outbound SCIM to support more downstream applications out of the box,
So that I can connect WeftID to the SaaS my organization uses without falling back to the spec-correct generic profile (which may not work for vendors that diverge from SCIM 2.0).

**Context:**

The initial Outbound SCIM release shipped with quirk modules for **Slack, GitHub, Atlassian, and GitLab**, plus a spec-correct generic profile. Real-world SaaS diverges from SCIM 2.0 in vendor-specific ways, so each new high-profile vendor benefits from a small quirk module that adjusts payload shape, PATCH semantics, error interpretation, or authentication.

Two related extensions also belong here: connector types that don't fit the "generic SCIM 2.0 client with quirks" mold (1Password Business uses a self-hosted bridge; Box wraps SCIM in OAuth2 client-credentials auth).

**Design Notes:**

- Each new vendor is a small file under `app/services/scim/quirks/<vendor>.py` plus recorded fixtures under `tests/fixtures/scim/<vendor>/`. The vendor's name extends the `service_providers.scim_kind` CHECK constraint and appears in the SP detail page's "Application type" dropdown.
- Alternate connector types (bridge model, alternate auth) are larger work: a new transport layer alongside the generic HTTP-bearer client. Likely a `scim_transport VARCHAR(50)` column or a separate `sp_scim_connector_kind` table, with `http_bearer` as the default.
- Priority within this backlog item should be driven by customer demand. The list below is "next-most-likely-to-be-asked-for," not a commitment to ship all of them.

**Candidate vendor quirks (incremental, ship as customer demand surfaces):**

- **Zoom**: `userName` must be the email address, even when `emails[]` carries it separately
- **Notion**: PUT-only for users (no PATCH); architecturally distinct enough that the quirk module needs to translate PATCH ops into full-resource PUTs
- **Linear**: custom role attributes via schema extension
- **PagerDuty**: split between team membership and schedule membership (both modelled as "groups" in WeftID; quirk decides which)
- **Datadog**: tenant-specific URL pattern (region in the base URL)
- **Vercel**: project-membership model differs from flat groups
- **Figma**: distinguishes editor vs viewer seats in non-standard ways
- **AWS IAM Identity Center**: email as the immutable identifier; strict
- **Snowflake**: custom role mapping via attribute extensions
- **CircleCI**: org structure differs from spec's flat groups
- **HashiCorp Cloud Platform**: mostly compliant; minor differences
- **Sentry**: SCIM on Business+; mostly compliant
- **Cloudflare Zero Trust**: mostly compliant

**Candidate alternate connector types (each is a larger, distinct piece of work):**

- **1Password Business** -- self-hosted SCIM bridge. Admins deploy a 1Password-provided bridge container in their own infra; WeftID pushes to the bridge, not directly to 1Password's cloud. Requires a new connector kind and likely a different config UX (bridge URL + bridge auth, not 1Password cloud credentials).
- **Box** -- OAuth2 client-credentials in front of SCIM. Bearer token is short-lived and refreshed; WeftID needs a token-management layer (acquire, cache, refresh) rather than the static-bearer model used by everyone else.

**Acceptance Criteria (per increment -- each vendor or connector type is its own sub-deliverable):**

- [ ] Per vendor quirk: new `app/services/scim/quirks/<vendor>.py` module with the appropriate transforms and error interpretation
- [ ] Per vendor quirk: recorded request/response fixtures in `tests/fixtures/scim/<vendor>/`
- [ ] Per vendor quirk: `scim_kind` CHECK constraint extended via migration; dropdown updated
- [ ] Per vendor quirk: documentation walkthrough added under `docs/admin-guide/` with screenshots of the vendor's bearer-token acquisition flow
- [ ] Per alternate connector type: new transport layer in `app/services/scim/transports/` with its own auth model
- [ ] Per alternate connector type: UI accommodates the new config shape (bridge URL, OAuth2 client ID/secret, etc.)
- [ ] Per alternate connector type: integration tests against a recorded or sandbox instance

**Effort:** Variable. Single vendor quirk = XS (one file + fixtures + docs page). Alternate connector type = M (new transport + UI + auth refresh logic).
**Value:** Per-vendor: scales with how many prospects ask for that vendor. Bridge/OAuth2 connectors: unlock specific high-value prospects who use those products.
**Version impact:** Each vendor quirk is a patch release (additive). Each alternate connector type is a minor release (new auth surface, new config columns).

**Dependencies:** Requires **Outbound SCIM (WeftID → Downstream Service Providers)** to be shipped first. This backlog item is the follow-on wave.

---
