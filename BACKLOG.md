# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Email Address Management: Admin-Only Controls

**User Story:**
As an admin or super admin,
I want full control over user email addresses without users being able to manage their own,
So that email address changes (which affect IdP routing) are always intentional administrative actions.

**Context:**

Currently, users can add, remove, and promote email addresses via `/account/emails`. Because
primary email domain determines IdP routing (which identity provider a user is authenticated
against), this is too sensitive to leave as self-service. An unintended primary email promotion
could silently route a user to a completely different IdP.

**Acceptance Criteria:**

- [ ] The `/account/emails` page is replaced with a read-only view (users can see their email addresses but not add, remove, or promote)
- [ ] All self-service email mutation API endpoints (`POST/DELETE /api/v1/users/me/emails`, `POST /api/v1/users/me/emails/{id}/set-primary`) are removed or return 403
- [ ] The tenant security setting `allow_users_add_emails` is removed (no longer needed); migration drops the column
- [ ] Admin and super admin retain all existing email management capabilities on the user detail page
- [ ] When an admin promotes a secondary email to primary, and the new primary's domain routes to a **different IdP** than the current primary, a confirmation warning is shown: "Switching the primary email to `new@domain.com` will route this user to a different identity provider. They will authenticate via [IdP name] going forward."
- [ ] The IdP routing warning also applies to the API: the `POST /api/v1/users/{id}/emails/{email_id}/set-primary` endpoint returns a 409 with a `routing_change` error code and details when a routing change would occur, unless a `confirm_routing_change=true` parameter is passed
- [ ] Event log entries are unchanged (email operations continue to be logged)
- [ ] API endpoint docstrings document the `confirm_routing_change` parameter and `routing_change` error

**Effort:** M
**Value:** High
**Version impact:** Minor (removes user capability, adds admin-only routing warning)

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

## Resend Invitation Email

**User Story:**
As an admin,
I want to resend an invitation email to a user who has not yet accepted their invitation,
So that I can help users who missed or lost the original email without recreating the account.

**Context:**

Currently there is no way to resend an invitation. The only workaround is deleting and recreating
the user, which loses audit history and group memberships. This is especially painful for large
bulk imports where some users never accept.

**Acceptance Criteria:**

- [ ] A "Resend invitation" button appears on the user detail page when the user has no `password_hash` set (i.e. has never completed onboarding)
- [ ] Clicking it generates a fresh invitation link (new nonce for non-privileged domains; new signed token for privileged domains — see the "Invitation Link Security Hardening" item) and sends the appropriate invitation email
- [ ] The old invitation link is invalidated when a new one is sent (nonce incremented)
- [ ] An audit event (`invitation_resent`) is logged with the actor admin and target user
- [ ] API endpoint: `POST /api/v1/users/{user_id}/resend-invitation`
- [ ] Button is hidden and API returns 400 if the user has already set a password

**Effort:** S
**Value:** Medium
**Version impact:** Minor (new feature)

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


