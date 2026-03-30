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

## ~~Primary Email Change: SP Assertion Impact Warnings~~ (Complete)

---

## ~~Bulk Change Primary Email (Browser-Native)~~ (Complete)

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

## ~~User Audit Export~~ (Complete)

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

## ~~Self-Updating Management Script and Env Var Diffing~~ (Removed)

---

## Remove `weftid` Management Script

**User Story:**
As a self-hosting operator,
I want the self-hosting setup to rely on `install.sh` for bootstrapping and standard Docker Compose commands for ongoing management,
So that the operational model is simple, well-documented by Docker itself, and doesn't require maintaining a separate shell tool.

**Context:**

The `weftid` management script (~630 lines) wraps Docker Compose with backup, upgrade, rollback,
and tenant provisioning subcommands. In practice it adds a layer of complexity that is hard to
maintain alongside the release process and is effectively a separate product. The underlying
operations (`docker compose up`, `docker compose exec`, `pg_dump`, etc.) are simple enough to
document directly. `install.sh` handles the one-time bootstrap and is easy to maintain.

**Acceptance Criteria:**

- [ ] Delete the `weftid` script from the repo
- [ ] Update `install.sh` to stop generating/referencing the `weftid` script
- [ ] Update `docs/self-hosting/index.md` to replace all `./weftid` commands with direct Docker Compose equivalents and plain shell commands
- [ ] Update CLAUDE.md if it references the `weftid` script
- [ ] Remove any `weftid`-related entries from ISSUES.md or ISSUES_ARCHIVE.md
- [ ] Rebuild the documentation site (`make docs`)

**Effort:** S
**Value:** High
**Version impact:** Patch (operational tooling change, no application changes)

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

## User List Filter Panel Redesign

**User Story:**
As an admin browsing the user list,
I want a compact, floating filter panel triggered by a funnel icon,
So that I can build multi-criteria filters without the panel pushing page content around,
and clearly see when filters are active.

**Context:**

The current filter panel is a collapsible inline section that pushes content down when expanded.
Filters auto-apply on every dropdown change, which causes a page reload and closes the panel,
making it tedious to set multiple filters at once.

This redesign replaces the inline panel with a floating popover anchored to a funnel icon button.
The admin can set multiple filter values, then apply them all at once by clicking "Apply Filters"
or clicking outside the panel (both are the same action). The panel always starts closed on
page load.

All backend filter parameters already exist. This is a frontend-only change (template + JS).

**Design:**

1. **Funnel icon button** replaces the current "Filters" text button. Tooltip: "Filter results".
2. **Floating popover** appears below the funnel icon, overlaying page content (no layout shift).
   Panel always starts closed on page load (no localStorage persistence of open/closed state).
3. **Vertical filter rows**, each clearly separated (dividers or generous spacing). Each row
   follows the pattern: `Label  IS  [Dropdown]` where "IS" is a clickable toggle that switches
   to "IS NOT" (same negation behavior as today, but inline on the row).
4. **Filters exposed:**
   * Role (IS/IS NOT dropdown)
   * Status (IS/IS NOT dropdown)
   * Auth Method (IS/IS NOT dropdown)
   * Domain (IS/IS NOT dropdown). Tooltip: "Matches users who have any email (primary or
     secondary) at this domain."
   * Group (IS/IS NOT dropdown) with "Include child groups" checkbox beneath it
   * Has Secondary Email (Yes/No dropdown, no IS/IS NOT needed since it is inherently binary)
   * Last Activity date range (start date, end date inputs)
5. **Apply behavior:** explicit "Apply Filters" button at the bottom of the panel. Clicking
   outside the panel is equivalent to clicking Apply. No auto-apply on individual changes.
6. **Active filter indicator:** when any filter is active, the funnel icon gets a visually
   distinct active style (color fill or highlight). The page displays "Filtered results" text
   with a "Clear filter" link, same as today but retained in the new design.

**Acceptance Criteria:**

*Funnel button:*
- [ ] Funnel icon replaces the current "Filters" text button
- [ ] Tooltip on hover: "Filter results"
- [ ] Visually distinct active state when any filter is applied (color/fill change)

*Floating panel:*
- [ ] Panel floats over page content (absolute/fixed positioning), no layout shift
- [ ] Panel always starts closed on page load
- [ ] Click outside panel applies current filter state and closes
- [ ] "Apply Filters" button at bottom applies and closes
- [ ] Panel contains all filter rows in a vertical layout with clear separation

*Filter rows:*
- [ ] Each row: `Label  IS  [Dropdown]` with IS clickable to toggle IS NOT
- [ ] Role, Status, Auth Method, Domain, Group filters retain current behavior
- [ ] Domain filter has a tooltip explaining it matches any email (primary or secondary)
- [ ] Group filter has "Include child groups" checkbox beneath it
- [ ] Has Secondary Email exposed as Yes/No dropdown
- [ ] Last Activity exposed as date range (start and end date inputs)

*Page indicators:*
- [ ] "Filtered results" text shown when filters are active
- [ ] "Clear filter" link removes all filters

*Behavior:*
- [ ] No auto-apply on individual dropdown changes (filters batch until applied)
- [ ] Filter state passed as query parameters on apply (same URL scheme as today)
- [ ] Multiselect and bulk action bar continue to work with the new filter panel

**Effort:** M
**Value:** High
**Version impact:** Patch (UI enhancement, no API or schema changes)

---

## ~~Audit Event Visibility Tiers~~ (Complete)

---


