# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## ~~Email Address Management: Admin-Only Controls~~ (Complete)

---

## Bulk User Attribute Update via Spreadsheet

**User Story:**
As an admin,
I want to download a spreadsheet of current users and upload it with secondary emails and/or name changes populated,
So that I can prepare user records in bulk before an upstream IdP migration (e.g. renaming email domains).

**Context:**

The primary use case is pre-migration preparation: before an IdP email domain change takes effect,
admins add the new addresses as secondary emails on each user. When the IdP sync eventually pushes
the new address, WeftID matches it to the existing secondary email and the transition is seamless.
The spreadsheet also supports first/last name corrections.

The download should be generated as a background job (deferred) rather than synchronously, since
large tenants could have thousands of users.

**Acceptance Criteria:**

- [ ] Admin page has a "Download user template" button that enqueues a background job and shows a status indicator (spinner → download link when ready)
- [ ] The generated Excel file has columns: `user_id`, `email` (current primary, read-only reference), `first_name` (current), `last_name` (current), `new_secondary_email` (blank), `new_first_name` (blank), `new_last_name` (blank)
- [ ] The file is named `users_YYYY-MM-DD.xlsx` and uses the tenant subdomain prefix
- [ ] Download link is scoped to the requesting admin's session (not guessable)
- [ ] Admin uploads the filled-in spreadsheet via a file input on the same admin page
- [ ] On upload, each row is processed in turn:
  - If `new_secondary_email` is non-empty: add it as a verified secondary email (admin-added emails are auto-verified, per existing behaviour). Skip if the address already exists on the user or is already in use by another user in the tenant.
  - If `new_first_name` or `new_last_name` is non-empty: update those fields
  - Rows with all blank "new" columns are skipped
- [ ] After processing, show a summary: N emails added, N names updated, N rows skipped (with per-row error details for failures)
- [ ] Each mutation emits the appropriate audit log events (`email_added`, `user_updated`)
- [ ] API endpoints: `POST /api/v1/users/bulk-update/request-download` (returns job ID), `GET /api/v1/users/bulk-update/download/{job_id}` (returns file or 202 if pending), `POST /api/v1/users/bulk-update/upload` (multipart form, returns summary)
- [ ] Row limit enforced: refuse uploads exceeding 10,000 rows with a clear error
- [ ] The spreadsheet uses `openpyxl`; no new library dependencies are introduced for Excel support (check if already present before adding)

**Effort:** L
**Value:** High
**Version impact:** Minor (new feature)

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

## Password-Encrypted XLSX Export Capability

**User Story:**
As an admin,
I want all XLSX exports to be password-encrypted,
So that exported files containing PII are protected at rest and cannot be opened if a device is lost or the file is shared accidentally.

**Context:**

Any XLSX export from WeftID (user data, audit logs) contains PII: email addresses, IP addresses,
authentication events, session metadata. These files end up on admin laptops and in email attachments.
Encryption is always on. There is no unencrypted XLSX option. Programmatic consumers who need raw
data should use the API.

The worker generates a random one-time password per export, encrypts the file with `msoffcrypto-tool`
(AES, natively supported by Excel, LibreOffice, and Google Sheets), and stores the password only in
the background task's result payload. The admin page displays the password once alongside the download
link. If the admin navigates away, they re-export. The password is cleaned up with the task on the
standard expiry cycle. The file is never stored unencrypted.

This is a shared capability used by all XLSX exports (bulk user update template, audit log export,
and any future exports).

**Acceptance Criteria:**

- [ ] New utility function that takes an `openpyxl` Workbook and returns an encrypted bytes buffer with a generated password
- [ ] Uses `msoffcrypto-tool` for AES encryption (compatible with Excel, LibreOffice, Google Sheets)
- [ ] Password is a passphrase of six random lowercase words joined by dashes (e.g. `velvet-morning-copper-bridge-eastern-lamp`). Words are drawn from a curated wordlist of ~2048 common English words (short, unambiguous, easy to type). Six words gives ~66 bits of entropy, which is infeasible to brute-force offline even if an attacker knows the format. No digits or special characters beyond the dashes.
- [ ] The encrypted file is what gets stored (local or Spaces). The plaintext XLSX is never written to storage.
- [ ] Password is stored in the background task result payload (JSON field), not in the file or a separate table
- [ ] Password is displayed once on the admin page alongside the download link
- [ ] Password is cleaned up when the background task expires (standard expiry cycle)
- [ ] Existing bulk user update export uses this capability
- [ ] Dependency `msoffcrypto-tool` added to `pyproject.toml`
- [ ] Tests verify encryption produces a file that requires a password to open, and that the correct password works

**Effort:** S
**Value:** High
**Version impact:** Minor (new capability, no breaking changes)

---

## Audit Log XLSX Export with Date Range

**User Story:**
As an admin,
I want to export the audit log as a password-encrypted Excel file for a specific date range,
So that I can produce compliance evidence for a given period without handling unprotected PII.

**Context:**

The existing JSON export is being retired from the UI. Programmatic consumers should use the
event log API directly. The XLSX export replaces it as the admin-facing export.

Date range filtering serves two purposes: compliance teams are often asked to produce evidence for
a specific period (e.g. "all authentication events in Q4 2025"), and it provides a natural way to
chunk exports for large tenants that might exceed the ~1M row XLSX limit.

All XLSX exports are always password-encrypted (see "Password-Encrypted XLSX Export Capability").

**Acceptance Criteria:**

- [ ] Export form on the audit events page includes optional start date and end date pickers
- [ ] "All time" is the default (both dates blank)
- [ ] Date range is validated: start must be before end, dates must not be in the future
- [ ] Background job generates an XLSX with columns: Timestamp, Event Type, Description, Actor Email, Artifact Type, Artifact ID, Artifact Name, IP Address, User Agent, Device, API Client, Additional Metadata (JSON string for event-specific fields)
- [ ] The file is password-encrypted using the shared encrypted XLSX capability
- [ ] Filename includes the date range: `audit-log_YYYY-MM-DD_to_YYYY-MM-DD.xlsx` (or `audit-log_all.xlsx` for full export)
- [ ] Events are fetched in batches to control memory usage (consistent with existing export job pattern)
- [ ] If the export exceeds 1,000,000 rows, the job fails with a clear message suggesting a narrower date range
- [ ] The existing JSON export (`export_events` job) is removed from the admin UI. The API endpoint for creating exports accepts a `format` parameter but only `xlsx` is supported.
- [ ] API endpoint: `POST /api/v1/exports` accepts optional `start_date` and `end_date` query parameters (ISO 8601)
- [ ] Admin page shows the one-time password alongside the download link when the export is ready
- [ ] Audit event logged: `export_task_created` with metadata including format and date range

**Effort:** M
**Value:** High
**Version impact:** Minor (new feature, deprecates JSON export from UI)

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


