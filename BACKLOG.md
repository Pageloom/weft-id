# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## ~~Email Address Management: Admin-Only Controls~~ (Complete)

---

## ~~Bulk User Attribute Update via Spreadsheet~~ (Complete)

---

## ~~Resend Invitation Email~~ (Complete)

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

## Admin: Super Admin Debug Impersonation

**User Story:**
As a super admin
I want to view what a specific user's application access looks like from their perspective
So that I can debug access and attribute issues without creating a real session as that user

**Context:**

This is a debug-only, read-only capability. The super admin sees the user's effective access
and the identity attributes that would be asserted for them, without performing a real
authentication to any SP. This is the "what would happen if they logged in?" companion to
the User-App Access Query item, which answers "does this user have access?".

**Acceptance Criteria:**

- [ ] Super admin only (not admin role)
- [ ] Accessible from the user detail page and/or the User-App Access view
- [ ] Shows the user's effective group memberships and the SPs accessible via those groups
- [ ] For a selected user + SP combination, shows a preview of the identity attributes
      (name, email, groups, any custom attribute mappings) that would be asserted
- [ ] Clearly labeled as a debug preview. No actual SP session or authentication occurs.
- [ ] Event logged in audit trail (`super_admin_debug_impersonation`) with actor, target user, and SP

**Effort:** M
**Value:** Low

---

## ~~Contextual Documentation Links~~ (Complete)

---

## ~~Consolidate Tenant Name and Site Title~~ (Complete)

---

## ~~Branded Email Headers~~ (Complete)

---

## ~~Standardize Product Name to "WeftID"~~ (Complete)

---

## ~~Password Strength Policy~~ (Complete)

---

## ~~Password Change and Admin-Forced Reset~~ (Complete)

---

## ~~Password Lifecycle Hardening~~ (Complete)

---

## ~~Forgot Password (Self-Service Reset)~~ (Complete)

---

## ~~Stateless Time-Windowed Token Generation~~ (Complete)

---

## ~~Drop Unused `site_title` Column from `tenant_branding`~~ (Complete)

---

## ~~Remove Legacy One-Time Token Storage~~ (Complete)

---

## ~~Remove Bulk Update Spreadsheet Feature~~ (Complete)

---

## ~~Enhanced User List Filtering and Bulk Selection~~ (Complete)

---

## ~~Bulk Add Secondary Emails (Browser-Native)~~ (Complete)

---

## Primary Email Change: SP Assertion Impact Warnings

**User Story:**
As an admin promoting a user's secondary email to primary,
I want to see which downstream SPs will be affected by the email change,
So that I understand the federation impact before confirming a potentially breaking change.

**Context:**

The existing single-user promote-to-primary flow (`/users/{id}/emails/{email_id}/promote`)
already warns about IdP routing changes via `check_routing_change()`. However, it does not
warn about the impact on SAML assertions to downstream SPs.

When a user's primary email changes, SPs configured with `emailAddress` or `unspecified`
NameID format will receive a different NameID in the next assertion. This can cause the SP
to create a duplicate JIT user or reject the assertion entirely. SPs using `persistent` or
`transient` NameID formats are unaffected (they use stable or random identifiers).

This item adds a reusable `compute_email_change_impact()` service function that computes
the full downstream impact for a given user + new email, and surfaces it in the single-user
promote confirmation dialog. The bulk change primary email feature will reuse this function
for its dry-run report.

**Acceptance Criteria:**

- [ ] New service function `compute_email_change_impact(tenant_id, user_id, new_email)` returns:
  * List of accessible SPs with their NameID format and impact level ("will change" vs "not affected")
  * IdP routing change (current IdP vs new domain's IdP, if different). Reuses existing `check_routing_change()`.
  * Count summaries (N SPs affected, N not affected)
- [ ] Single-user promote confirmation dialog shows SP assertion impact alongside the existing IdP routing warning
- [ ] SPs using `persistent`/`transient` shown as "Not affected"
- [ ] SPs using `emailAddress`/`unspecified` shown as "NameID will change" with SP name
- [ ] If no SPs are affected, the warning section is omitted (no noise)
- [ ] API: promote endpoint response includes impact data when called with `?preview=true` (or similar)

**Effort:** S
**Value:** High
**Version impact:** Patch (enhancement to existing feature)

---

## Bulk Change Primary Email (Browser-Native)

**User Story:**
As an admin,
I want to select users and promote one of their secondary emails to primary in the browser with
a clear preview of downstream consequences,
So that I can complete domain migrations confidently, understanding the impact on SP assertions
and IdP routing before committing.

**Context:**

Changing a user's primary email is a high-impact operation. The primary email is the default
NameID in SAML assertions for SPs using `emailAddress` or `unspecified` format. Changing it
means downstream SPs may see a "new" user (especially if they do JIT provisioning), or reject
the assertion entirely if they validate the NameID against their user store.

Additionally, the new email's domain may be bound to a different IdP (or no IdP at all), which
affects how the user authenticates going forward. The user's current `saml_idp_id` is not
automatically changed by an email promotion, but the admin may want to change it as part of
the migration.

This feature adds a **two-phase flow**: first a dry-run impact report, then a confirmed
execution. Both phases are deferred to the worker as background jobs, with the UI polling
for completion. For large tenants the impact computation may need to query SP access and
NameID formats for hundreds of user-SP pairs, which can exceed API request timeouts.

The page uses a `beforeunload` guard (same pattern as the group graph edit-layout mode) to
warn the admin if they try to navigate away mid-flow, since the selections and dry-run
results would be lost.

**Flow:**

1. Filter users with secondary emails, select them, click "Change Primary Email (N)"
2. Action page shows each user with their primary and secondary emails. Admin picks which
   secondary to promote per user (or leaves as "No change").
3. On "Preview Changes", a dry-run background job is enqueued. UI polls for completion,
   showing a progress indicator. No data is modified.
4. When the dry-run completes, the report renders inline: per-user impact (affected SPs,
   NameID format risk level, IdP routing changes) with per-user IdP disposition selectors.
5. Admin reviews, adjusts per-user IdP choices, and clicks "Apply Changes".
6. Execution background job is enqueued. UI polls for completion. Results rendered inline
   when done.

**Dry-run report (per user):**

For each user where a new primary email is selected:

* **SP assertion impact**: List each SP the user can access (via groups or "all users" mode).
  For each SP, show:
  * SP name
  * Current NameID format (`emailAddress`, `persistent`, `transient`, `unspecified`)
  * Impact level:
    * `persistent`/`transient`: "Not affected" (NameID is independent of email)
    * `emailAddress`/`unspecified`: "Will change" (next assertion carries new email)

* **IdP routing impact**: Compare the user's current `saml_idp_id` with the IdP bound to
  the new email's domain (if any). Show one of:
  * "No change" (same IdP, or domain not bound)
  * "IdP will change: [Current IdP] -> [New IdP]" (new domain bound to different IdP)
  * "IdP will be removed: [Current IdP] -> password only" (new domain not bound to any IdP)

* **Per-user IdP disposition** (only shown when IdP routing changes):
  * **Keep current IdP** (default): Leave `saml_idp_id` unchanged. User continues
    authenticating via their current IdP despite the new email domain.
  * **Switch to new IdP**: Update `saml_idp_id` to the IdP bound to the new domain.
  * **Remove IdP (password only)**: Set `saml_idp_id` to NULL. User falls back to
    password authentication.

**Acceptance Criteria:**

*Selection and preparation:*
- [ ] "Change Primary Email" button in user list action bar (only when selected users have secondaries)
- [ ] Action page at `/users/bulk-ops/primary-emails` shows selected users in a grid
- [ ] Grid columns: name, current primary email, dropdown of secondary emails (or "No change")

*Navigation guard:*
- [ ] `beforeunload` listener warns admin before navigating away mid-flow (same pattern as group graph edit-layout mode)

*Dry-run report:*
- [ ] "Preview Changes" enqueues a dry-run background job (no data modified)
- [ ] UI polls job status and shows progress indicator while computing
- [ ] When complete, report renders inline with per-user SP assertion impact and NameID format
- [ ] Report shows per-user IdP routing change (if any) with disposition selector
- [ ] Default IdP disposition is "Keep current IdP" (least disruptive)
- [ ] Admin can change disposition per user (keep, switch, remove)
- [ ] Summary banner: "N users affected, N SPs will see new email, N IdP changes"

*Execution:*
- [ ] "Apply Changes" enqueues execution background job with the admin's chosen dispositions
- [ ] UI polls job status and shows progress indicator while executing
- [ ] Each promotion: secondary becomes primary, old primary becomes secondary
- [ ] IdP dispositions applied per user (keep/switch/remove per dry-run selections)
- [ ] Job result: N promoted, N skipped, N errors (with per-user details)
- [ ] Each promotion emits `primary_email_changed` audit event (old email, new email)
- [ ] IdP changes emit `user_saml_idp_assigned` audit event (old IdP, new IdP or null)
- [ ] Notification email sent to old primary address for each affected user

*API:*
- [ ] `POST /api/v1/users/bulk-ops/primary-emails/preview` accepts list of `{user_id, new_primary_email}` pairs, returns dry-run report
- [ ] `POST /api/v1/users/bulk-ops/primary-emails/apply` accepts list of `{user_id, new_primary_email, idp_disposition}` pairs

**Prerequisite:** "Primary Email Change: SP Assertion Impact Warnings" (below) must land first.
The `compute_email_change_impact()` service function it introduces is reused by the dry-run
report in this feature.

**Effort:** L
**Value:** High
**Version impact:** Minor (new feature)

---

## Bulk Inactivation and Reactivation (Browser-Native)

**User Story:**
As an admin,
I want to select users from the filtered list and inactivate or reactivate them in bulk,
So that I can handle department offboarding, seasonal staff changes, or post-migration cleanup efficiently.

**Context:**

The flow: filter users (e.g. by status, last activity, group), select them, click "Inactivate"
or "Reactivate" in the action bar. A confirmation dialog shows the count and warns about
consequences. On confirm, a deferred job processes each user.

The same guardrails from single-user inactivation apply: cannot inactivate the last super admin,
cannot inactivate service users.

**Acceptance Criteria:**

- [ ] "Inactivate" and "Reactivate" buttons in user list action bar when users are selected
- [ ] Buttons contextually enabled: "Inactivate" only if selection contains active users, "Reactivate" only if selection contains inactive users
- [ ] Confirmation modal: shows count, lists consequences (token revocation for inactivation)
- [ ] Deferred background job processes each user in turn
- [ ] Guardrails: last super admin protection, service user protection (per-user errors, not job failure)
- [ ] Job result: N inactivated/reactivated, N skipped, N errors
- [ ] Each state change emits `user_inactivated` or `user_reactivated` audit event
- [ ] API: `POST /api/v1/users/bulk-ops/inactivate` and `POST /api/v1/users/bulk-ops/reactivate` accept user IDs or filter

**Effort:** M
**Value:** Medium
**Version impact:** Minor (new feature)

---

## Bulk Group Assignment (Browser-Native)

**User Story:**
As an admin,
I want to add or remove users from a group in bulk from within the browser,
So that I can handle org restructures and team changes without tedious one-at-a-time clicking.

**Context:**

Two entry points:
1. From the group members page: "Bulk Add Members" opens the user list with multi-select,
   filtered to non-members. Select users, confirm, done.
2. From the user list: select users, click "Add to Group", pick a group from a dropdown, confirm.

Removal works from the group members page: select current members, click "Remove Selected"
(this already exists via the multiselect action bar).

IdP-synced groups reject bulk changes with a clear error.

**Acceptance Criteria:**

- [ ] Group members page: "Bulk Add" button opens user selection view (filtered to non-members of this group)
- [ ] User list: "Add to Group" button in action bar when users are selected, with group picker dropdown
- [ ] Both flows create a deferred job for the additions
- [ ] IdP-synced groups (`group_type = idp`) reject all changes with clear error
- [ ] Job result: N added, N skipped (already member), N errors
- [ ] Each addition emits `group_member_added` audit event
- [ ] Removal: existing multiselect on group members page already handles this (no new work needed)
- [ ] API: `POST /api/v1/groups/{group_id}/bulk-members` accepts list of user IDs or filter

**Effort:** M
**Value:** Medium
**Version impact:** Minor (new feature)

---

## User Audit Export

**User Story:**
As an admin,
I want to download a comprehensive spreadsheet of all users with their authentication history, group memberships, and app access,
So that I can produce audit evidence, review access patterns, and answer compliance questions without writing API queries.

**Context:**

This is a read-only XLSX export (no upload/re-import). It produces a multi-sheet workbook
covering three dimensions of user data: the users themselves, their group memberships, and
their app (SP) access. Each sheet is designed so that an auditor can filter on any column
in Excel to answer common questions ("which users haven't logged in for 90 days?", "who
has access to app X?", "which users were provisioned via JIT?").

All users are included (active, inactive, anonymized). The status column allows filtering.
Event-log-derived fields (last login, creation method, etc.) are computed at export time.

Accessible from the admin section (not under Bulk Ops, since it's a read-only export).

**Acceptance Criteria:**

- [ ] Page at `/admin/exports/users` (or similar admin export location)
- [ ] Download-only (no upload flow). Single "Export Users" button that enqueues a background job.
- [ ] Produces a multi-sheet XLSX workbook with three sheets:

**Sheet 1: Users** (one row per user)
- [ ] Columns: `user_id`, `first_name`, `last_name`, `primary_email`, `domain`, `secondary_emails` (comma-separated), `role`, `status` (active/inactive/anonymized), `created_at`, `creation_method` (invited, jit, cli), `auth_method` (password, IdP name), `last_login_at`, `last_login_ip`, `last_activity_at`, `password_last_changed_at`, `mfa_enabled` (yes/no), `app_count` (number of SPs accessible)
- [ ] Auto-filter enabled on header row

**Sheet 2: Group Memberships** (one row per user-group pair)
- [ ] Columns: `user_id`, `email`, `group_name`, `group_type` (weftid/idp), `membership_since`
- [ ] A user with 3 group memberships appears in 3 rows
- [ ] Auto-filter enabled on header row

**Sheet 3: App Access** (one row per user-SP pair)
- [ ] Columns: `user_id`, `email`, `app_name`, `last_auth_at` (last SAML assertion for this user+SP), `access_via` (comma-separated group names, or "All users" if SP is not group-restricted)
- [ ] A user with access to 5 SPs appears in 5 rows
- [ ] Auto-filter enabled on header row

**General:**
- [ ] Download is password-encrypted (uses shared encrypted XLSX capability)
- [ ] Background job fetches event log data in batches to control memory
- [ ] API endpoint: `POST /api/v1/exports/users`, `GET /api/v1/exports/users/download/{job_id}`
- [ ] Audit event logged: `user_export_task_created`
- [ ] Admin page shows password alongside download link when ready

**Effort:** L
**Value:** High
**Version impact:** Minor (new feature)

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

## ~~Audit Log XLSX: Access Change Coverage~~ (Complete)

---

## ~~Password-Encrypted XLSX Export Capability~~ (Complete)

---

## ~~Audit Log XLSX Export with Date Range~~ (Complete)

---

## Self-Updating Management Script and Env Var Diffing

**User Story:**
As a self-hosting operator upgrading to a new version
I want the management script to update itself and tell me about new configuration variables
So that I don't miss required settings or run stale management tooling

**Context:**

The `weftid` management script is downloaded once during install and never updated. New versions
may add subcommands, change upgrade behavior, or introduce new `.env` variables. Today the
operator has no way to discover this except reading the changelog.

Two related problems to solve:

1. **Self-updating `weftid`:** During `./weftid upgrade`, after pulling the new image but before
   restarting, download the matching `weftid` script from GitHub (same tag as the target version)
   and overwrite the local copy. The current version's upgrade flow runs to completion using the
   old script. The next command uses the new one. No mid-execution weirdness.

2. **Env var diffing:** After pulling the new image, extract `.env.production.example` from it
   (`docker compose run --rm app cat /app/.env.production.example`), diff the keys against the
   current `.env`, and show any new variables with their descriptions and defaults. Per
   `VERSIONING.md`, minor versions add vars with sensible defaults (informational). Major versions
   may add required vars without defaults (blocking).

**Acceptance Criteria:**

- [ ] `./weftid upgrade` downloads the new `weftid` script from GitHub after pulling the image
- [ ] The old script completes the upgrade before being overwritten
- [ ] `./weftid upgrade` extracts `.env.production.example` from the new image
- [ ] New env vars are shown to the operator with descriptions and default values
- [ ] Required vars without defaults block the upgrade until the operator adds them to `.env`
- [ ] Optional vars with defaults are informational (operator can accept defaults or customize)

**Effort:** M
**Value:** High

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

## ~~User List Filter Improvements~~ (Complete)

---

## ~~User List Filter: Negation and Group Hierarchy~~ (Complete)

---

## Audit Event Visibility Tiers

**User Story:**
As an admin reviewing the audit log,
I want the default view to show security-relevant and admin actions without operational noise,
So that I can quickly find meaningful events without scrolling through automated system activity.

**Context:**

All events continue to be logged to the database. Nothing is lost. The change is purely about
default visibility in the audit log UI and export.

Each event type gets a visibility tier. The audit log UI defaults to showing "security" and
"admin" tiers. A toggle or filter lets the admin include "operational" and "system" tiers
when needed (e.g. debugging group sync or certificate rotation).

**Tier definitions:**

* **security** -- authentication, authorization, credential changes, account lifecycle.
  These are the events an auditor or security reviewer cares about.
* **admin** -- configuration changes made by admins (IdP/SP setup, settings, group management,
  email management, branding). Human-initiated mutations to the tenant's configuration.
* **operational** -- high-volume automated activity that is useful for debugging but noisy in
  day-to-day review (SSO assertions, IdP group sync, certificate auto-rotation, domain
  auto-assignment).
* **system** -- internal bookkeeping with no audit value (task creation, job cleanup, export
  downloads, setup initiation steps).

**Proposed classification:**

Security tier:
* `login_failed`, `password_set`, `password_changed`, `password_reset_forced`,
  `password_reset_completed`, `password_reset_requested`, `password_self_reset_completed`,
  `password_breach_detected`, `password_policy_compliance_enforced`
* `user_signed_in`, `user_signed_in_saml`, `user_signed_out`
* `authorization_denied`
* `user_created`, `user_created_jit`, `user_deleted`, `user_inactivated`, `user_reactivated`,
  `user_auto_inactivated`, `user_anonymized`, `super_admin_self_reactivated`
* `mfa_totp_enabled`, `mfa_email_enabled`, `mfa_downgraded_to_email`, `mfa_disabled`,
  `mfa_backup_codes_regenerated`, `mfa_reset_by_admin`
* `oauth2_user_tokens_revoked`, `oauth2_client_secret_regenerated`
* `reactivation_requested`, `reactivation_approved`, `reactivation_denied`

Admin tier:
* `user_updated`, `user_profile_updated`, `invitation_resent`
* `email_added`, `email_deleted`, `email_verified`, `primary_email_changed`
* `group_created`, `group_updated`, `group_deleted`, `group_member_added`,
  `group_member_removed`, `group_members_bulk_added`, `group_members_bulk_removed`,
  `user_groups_bulk_added`, `group_relationship_created`, `group_relationship_deleted`
* `saml_idp_created`, `saml_idp_updated`, `saml_idp_deleted`, `saml_idp_enabled`,
  `saml_idp_disabled`, `saml_idp_set_default`, `saml_idp_metadata_refreshed`
* `saml_idp_trust_established`, `saml_idp_sp_certificate_created`,
  `saml_idp_sp_certificate_rotated`, `saml_sp_certificate_created`,
  `saml_sp_certificate_rotated`
* `saml_domain_bound`, `saml_domain_unbound`, `saml_domain_rebound`,
  `user_saml_idp_assigned`
* `service_provider_created`, `service_provider_updated`, `service_provider_deleted`,
  `service_provider_enabled`, `service_provider_disabled`,
  `service_provider_trust_established`, `sp_nameid_format_updated`,
  `sp_access_mode_updated`, `sp_metadata_refreshed`, `sp_metadata_reimported`,
  `sp_signing_certificate_created`, `sp_signing_certificate_rotated`
* `sp_group_assigned`, `sp_group_unassigned`, `sp_groups_bulk_assigned`
* `oauth2_client_created`, `oauth2_client_updated`, `oauth2_client_deleted`,
  `oauth2_client_role_changed`, `oauth2_client_deactivated`, `oauth2_client_reactivated`
* `privileged_domain_added`, `privileged_domain_deleted`
* `tenant_certificate_lifetime_updated`, `tenant_certificate_rotation_window_updated`,
  `password_policy_updated`, `tenant_settings_updated`, `group_assertion_scope_updated`
* `domain_group_link_created`, `domain_group_link_deleted`
* `branding_logo_uploaded`, `branding_logo_deleted`, `branding_settings_updated`,
  `group_logo_uploaded`, `group_logo_removed`, `group_avatar_style_updated`,
  `sp_logo_uploaded`, `sp_logo_removed`
* `sso_consent_denied`

Operational tier:
* `sso_assertion_issued`, `slo_sp_initiated`, `slo_idp_propagated`
* `idp_group_created`, `idp_group_discovered`, `idp_group_invalidated`,
  `idp_group_member_added`, `idp_group_member_removed`,
  `idp_group_relationship_created`
* `domain_group_auto_assigned`
* `saml_idp_sp_certificate_auto_rotated`, `saml_idp_sp_certificate_cleanup_completed`,
  `sp_signing_certificate_auto_rotated`, `sp_signing_certificate_cleanup_completed`

System tier:
* `export_task_created`, `export_downloaded`, `jobs_deleted`,
  `bulk_secondary_emails_task_created`
* `totp_setup_initiated`
* Deprecated events: `idp_certificate_added`, `idp_certificate_activated`,
  `idp_certificate_deactivated`, `idp_certificate_removed`

**Acceptance Criteria:**

- [ ] Each event type in `EVENT_TYPE_DESCRIPTIONS` has a tier annotation (security/admin/operational/system)
- [ ] Audit log UI defaults to showing security + admin tiers
- [ ] Filter/toggle in the audit log UI to include operational and/or system tiers
- [ ] Audit log XLSX export includes all tiers (with a tier column) regardless of UI filter
- [ ] Tier classification is stored in `event_types.py` alongside the description (e.g. a dict or a second mapping)
- [ ] No changes to what gets logged. All events still written to the database.

**Effort:** M
**Value:** High
**Version impact:** Patch (UI filtering, no schema changes)

---


