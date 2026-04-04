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

## ~~Bulk Inactivation and Reactivation (Browser-Native)~~ (Complete)

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

## Streamlined Sign-In Flow (Skip Email Verification by Default)

**User Story:**
As a user signing in to WeftID,
I want to enter my email and immediately be directed to my sign-in method,
So that I don't have to prove email possession just to reach the login form.

**Context:**

The current "discovery" flow requires email verification (6-digit code) before revealing the user's auth method. This prevents email enumeration but adds a full email round-trip on every first-time or new-device sign-in. The trust cookie covers repeat visits, but the initial experience is friction-heavy and unusual compared to other identity platforms.

This item introduces a second sign-in track that becomes the default, while the current discovery flow becomes opt-in per tenant. The new flow accepts the trade-off of revealing auth method in exchange for speed, mitigated by rate limiting. The forgot-password flow absorbs the "prove email, then discover your situation" role that the discovery flow serves today.

**Rationale:** This changes the default authentication experience. The current discovery flow remains available as an opt-in tenant setting for security-conscious deployments. The enumeration risk in the new flow is accepted and mitigated by IP+tenant rate limiting, which is consistent with how most identity platforms operate.

**Key invariant:** In both flows, SAML users are redirected to their IdP and never see a password form or forgot-password link. The only difference is whether email possession is verified *before* routing (old flow) or not (new flow). The old flow doubles as a discovery mechanism and anti-enumeration measure. The new flow trades that for ease of use.

**Sign-in flow (new default):**

- User enters email
- System looks up auth method and routes immediately:
  - **Password user** → password form
  - **SAML/SSO user** → redirect to assigned IdP
  - **Inactivated user** → password form (no status disclosure)
  - **Unknown email** → password form (no existence disclosure)
- Rate limited by IP+tenant combination (prevents bulk enumeration)

**Sign-in flow (opt-in, current behavior):**

- User enters email → verification code sent → prove possession → routed to auth method
- Tenant setting enables this mode (e.g., `require_email_verification_for_login`)

**Forgot-password flow changes:**

The forgot-password flow becomes the proof-of-possession discovery mechanism:

- User enters email on forgot-password page
- If account exists (any type, any status): sends a neutral email ("click here to continue", no account details in the email body)
- If no account exists, or active SAML user: no email sent (but UI shows same "check your email" message)
- After clicking the link (email possession proven), the landing page reveals the user's situation:
  - **Password user** → password reset form (as today)
  - **Inactivated user** (password or SAML) → inactivation status + reactivation flow
  - **No account** → "No account found at [tenant]. Contact your administrator."

**Acceptance Criteria:**

- [ ] New tenant setting to opt in to email-verification-first login (current discovery flow)
- [ ] Default sign-in flow: email entry routes immediately to auth method without verification
- [ ] Unknown emails and inactivated users are routed to the password form (no info disclosure)
- [ ] IP+tenant rate limiting on the email-entry endpoint
- [ ] Forgot-password email is neutral (no account details, just a "continue" link)
- [ ] Forgot-password landing page (after click = proof of possession) shows situation-appropriate outcome: password reset form, inactivation status, or "no account found"
- [ ] Active SAML users who manually navigate to forgot-password do not receive an email
- [ ] Existing trust cookie optimization continues to work in both flows
- [ ] Existing rate limits on password login attempts preserved
- [ ] Event logging for sign-in routing decisions (audit trail)
- [ ] Database migration for tenant setting

**Effort:** L
**Value:** High
**Version impact:** Minor (new default behavior, old behavior preserved via tenant setting; no breaking API changes)

---


