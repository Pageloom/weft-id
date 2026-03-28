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

## Bulk Add Secondary Emails (Browser-Native)

**User Story:**
As an admin,
I want to select users from the filtered user list and add secondary email addresses in the browser,
So that I can prepare for domain migrations without downloading and re-uploading spreadsheets.

**Context:**

The flow: filter users on the user list (e.g. by domain), select them, click "Manage Secondary
Emails (N)". This navigates to an action page showing a grid of the selected users with their
current emails and an input field for a new secondary address per user. On submit, the additions
are processed as a deferred background job.

Current secondary addresses are shown as read-only reference so the admin can see the full
picture before adding.

**Acceptance Criteria:**

- [ ] "Manage Secondary Emails" button appears in user list action bar when users are selected
- [ ] Action page at `/users/bulk-ops/secondary-emails` shows selected users in a grid
- [ ] Grid columns: name, primary email, current secondary emails (read-only), new secondary email (text input)
- [ ] Admin enters a new secondary address per user (or leaves blank to skip)
- [ ] On submit, creates a deferred background job to process additions
- [ ] Each addition: add as verified secondary email (admin-added), skip if address already exists in tenant
- [ ] Job result: N emails added, N skipped, N errors (with per-user error details)
- [ ] Results displayed on the page when job completes (poll job status)
- [ ] Each addition emits `email_added` audit event
- [ ] API: `POST /api/v1/users/bulk-ops/secondary-emails` accepts list of `{user_id, email}` pairs or filter + email rule
- [ ] Selected users passed via session or URL state (not lost on navigation)

**Effort:** M
**Value:** High
**Version impact:** Minor (new feature)

---

## Bulk Change Primary Email (Browser-Native)

**User Story:**
As an admin,
I want to select users and promote one of their secondary emails to primary in the browser,
So that I can complete domain migrations without spreadsheet round-trips.

**Context:**

The flow: filter users who have secondary emails, select them, click "Change Primary Email (N)".
Action page shows each user with their primary and secondary addresses. A dropdown per user lets
the admin pick which secondary to promote. The old primary becomes a secondary.

Only users with at least one secondary email should be selectable for this action (the filter
"has secondary email: yes" supports this).

**Acceptance Criteria:**

- [ ] "Change Primary Email" button in user list action bar (only enabled when all selected users have secondaries)
- [ ] Action page at `/users/bulk-ops/primary-emails` shows selected users in a grid
- [ ] Grid columns: name, current primary email, dropdown of secondary emails (select one to promote, or leave as "No change")
- [ ] On submit, creates a deferred background job
- [ ] Each promotion: secondary becomes primary, old primary becomes secondary
- [ ] Job result: N promoted, N skipped, N errors
- [ ] Each promotion emits `email_promoted_to_primary` audit event with old and new primary
- [ ] API: `POST /api/v1/users/bulk-ops/primary-emails` accepts list of `{user_id, new_primary_email}` pairs

**Effort:** M
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


