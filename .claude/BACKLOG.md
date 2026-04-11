# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## ~~Tenant-Scope the SAML ACS Rate Limit Key~~ (Complete)

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

## Downstream SP Assertion Preview

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

## Upstream IdP Verbose Assertion Logging

**User Story:**
As an admin or super admin,
I want to temporarily enable verbose assertion logging on an upstream IdP,
So that I can see exactly what the IdP sends (including raw XML and parsed attributes) for both successful and failed authentications, helping me debug attribute mapping, group sync, and configuration issues.

**Context:**

WeftID already captures full assertion details for **failed** SAML authentications in the
`saml_debug_entries` table (raw XML, error type, error detail). These are auto-cleaned after
24 hours and accessible to super admins at `/debug/saml`.

However, **successful** authentications log only minimal metadata to the event log (IdP ID,
email, password_preserved). When debugging attribute mapping or group sync issues, the
frustrating scenario is: "the user can log in, but their name is wrong or groups aren't
syncing." The assertion succeeded, so no debug entry exists. You have to guess what the IdP
actually sent.

This feature adds a per-IdP toggle that temporarily enables verbose logging for all
assertions (both successful and failed) processed from that IdP. It auto-expires after 24
hours to prevent unbounded data accumulation.

**Acceptance Criteria:**

*Toggle and expiry:*
- [ ] Per-IdP "verbose assertion logging" toggle, accessible from the IdP configuration page
- [ ] Admin and super admin roles can enable/disable
- [ ] Auto-expires after exactly 24 hours from activation. No renewal, must be re-enabled.
- [ ] Clear visual indicator on the IdP page when verbose mode is active, showing remaining time
- [ ] Enabling/disabling verbose mode logs an audit event (`saml_idp_debug_enabled` / `saml_idp_debug_disabled`) with actor and IdP

*What gets logged when verbose mode is active:*
- [ ] **Successful assertions** create a detailed event log entry (new event type, e.g. `saml_assertion_received`) with metadata containing: NameID, NameID format, all mapped attribute values (first name, last name, email, groups), any unmapped attributes the IdP sent, and a reference to the stored raw assertion
- [ ] **Failed assertions** also create an event log entry (new event type, e.g. `saml_assertion_failed`) with error type, error detail, and a reference to the stored raw assertion. This surfaces failures that currently only appear in the debug table.
- [ ] Raw assertion XML (both base64 and decoded) is stored for both successes and failures
- [ ] All verbose entries clearly associated with the IdP and (where known) the authenticating user

*Viewing verbose logs:*
- [ ] Verbose assertion events appear in the standard audit log alongside other events
- [ ] Admin can drill into a verbose event to see the full assertion details (parsed attributes and raw XML)

*Cleanup:*
- [ ] Raw assertion data stored during verbose mode follows the same 24-hour cleanup lifecycle as existing debug entries
- [ ] Event log entries themselves persist (they are audit records) but the raw XML references may expire

**Effort:** L
**Value:** Medium
**Version impact:** Minor (new feature, no breaking changes)

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

## ~~Bulk Inactivation and Reactivation (Browser-Native)~~ (Complete)

---

## ~~Bulk Group Assignment (Browser-Native)~~ (Complete)

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

## ~~Remove `weftid` Management Script~~ (Complete)

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

## ~~User List Filter Panel Redesign~~ (Complete)

---

## ~~Audit Event Visibility Tiers~~ (Complete)

---

## ~~Per-SP AES-256-GCM Assertion Encryption~~ (Complete)

---

## ~~Rename "Loom Identity Platform" to "WeftID" in Certificates and API Title~~ (Complete)

---



