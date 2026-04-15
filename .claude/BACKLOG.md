# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Standard User Attribute Expansion

**User Story:**
As a super admin,
I want to enable standard profile fields (phone, title, department, address, etc.) for my tenant,
So that user profiles contain the information my organization needs, synced from identity providers
and available in downstream SAML assertions.

**Standard Attribute Categories and Fields:**

*Contact*
| Field | Type | SAML OID |
|-------|------|----------|
| Phone (work) | string(50) | `urn:oid:2.5.4.20` |
| Phone (mobile) | string(50) | `urn:oid:0.9.2342.19200300.100.1.41` |

*Professional*
| Field | Type | SAML OID |
|-------|------|----------|
| Display name | string(255) | `urn:oid:2.16.840.1.113730.3.1.241` |
| Job title | string(255) | `urn:oid:2.5.4.12` |
| Department | string(255) | `urn:oid:2.5.4.11` |
| Organization | string(255) | `urn:oid:2.5.4.10` |
| Employee ID | string(255) | `urn:oid:2.16.840.1.113730.3.1.3` |
| Manager | user reference | `urn:oid:0.9.2342.19200300.100.1.10` |

*Location*
| Field | Type | SAML OID |
|-------|------|----------|
| Street address | string(500) | `urn:oid:2.5.4.9` |
| City | string(255) | `urn:oid:2.5.4.7` |
| State/Province | string(255) | `urn:oid:2.5.4.8` |
| Postal code | string(20) | `urn:oid:2.5.4.17` |
| Country | string(2), ISO 3166-1 alpha-2 | `urn:oid:2.5.4.6` |

*Profile*
| Field | Type | SAML OID |
|-------|------|----------|
| Profile photo | image (bytea blob) | `urn:oid:0.9.2342.19200300.100.1.7` |
| Preferred language | string(10), BCP 47 | `urn:oid:2.16.840.1.113730.3.1.39` |
| Description/Bio | text(2000) | `urn:oid:2.5.4.13` |

**Data Model:**

Storage: `user_attributes` table (EAV-style). Each row holds one attribute value for one user.
Columns: `user_id`, `tenant_id`, `attribute_key`, `value` (text), `source` (`idp` | `admin` | `self`),
`source_idp_id` (nullable, which IdP set this), `updated_at`.

Profile photo: stored as `bytea` blob (similar to email logo PNGs). Served via an unguessable
public URL with long cache headers so browsers and CDNs cache effectively.

Attribute configuration: `tenant_attribute_config` table. One row per attribute per tenant.
Columns: `tenant_id`, `attribute_key`, `category`, `enabled` (boolean), `required` (boolean).

**Category Opt-In Model:**

Each attribute has its own enabled/required toggle. The UI groups attributes by category and
shows a category-level toggle. Activating a category enables all attributes in it. Deactivating
individual attributes within an enabled category is supported. A category shows as "on" if any
attribute in it is enabled.

**Source and Editability Rules:**

Each attribute value tracks its source: `idp`, `admin`, or `self`.

* IdP-sourced values are **read-only for everyone** (admins included). The UI shows "Set by
  [IdP name]" with a hint explaining the value is updated on sign-in.
* Admin-sourced values are editable by admins only.
* Self-sourced values are editable by the user (subject to tenant policy on `allow_users_edit_profile`).
* On IdP login, if the assertion includes a value for an enabled attribute, it writes with
  `source=idp` regardless of the current source. If the assertion omits the attribute, the
  existing value is preserved with its current source.

**Manager Field:**

When an IdP sends a manager value (typically an email or DN), WeftID looks up the user by
email in the same tenant. If found, store as a user reference. If not found, store the raw
value as unresolved text. A recurring background job checks for unresolved managers and
resolves them when the referenced user appears in WeftID. Admins can manually set a manager
on any user (stored with `source=admin`).

**Profile Photo:**

Users can upload their own photo. Admins can set photos on users. Upstream IdPs can provide
a photo URL in assertions, which WeftID fetches, resizes, and stores as a blob. Served via
an unguessable public URL with cache headers. Falls back to the existing mandala avatar when
no photo is set.

**Required Field Enforcement:**

Super admins can mark any enabled attribute as required. Enforcement is progressive:

1. **Passive (default):** A non-dismissable banner on the user's dashboard reads something
   like "Your profile is incomplete" and links to their editable profile page.
2. **Active (admin-escalated):** From the incomplete profiles view, admins can bulk-select
   users and click "Force profile completion." Those users can sign in normally, but are
   redirected to their profile page and cannot navigate away until all required fields
   are populated.
3. **JIT-provisioned users:** Required fields cannot be enforced at provisioning time (the
   IdP may not provide them). The passive banner appears immediately. Admins can escalate
   to active enforcement at their discretion.

**Admin Tooling:**

* **Incomplete profiles view:** List of users with missing required attributes, filterable
  by which fields are missing. Supports bulk selection.
* **Force profile completion:** Bulk action that flags selected users. Flagged users are
  redirected to their profile page after sign-in and cannot navigate away until all
  required fields are populated.
* **User creation/invitation:** The creation dialog surfaces enabled attributes and suggests
  admins prepopulate them, with a note like "Or the invited user will be asked to enter
  these values."

**SAML Attribute Mapping:**

* **Upstream (IdP to WeftID):** Per-IdP configuration mapping IdP assertion attribute names
  to WeftID standard attribute keys. Admin configures which IdP attributes map to which
  standard fields.
* **Downstream (WeftID to SP):** Standard attributes are available in per-SP attribute mapping
  configuration. Admins can include any enabled standard attribute in SP assertions using
  the standard SAML OIDs or custom friendly names.

**Acceptance Criteria:**

*Data model and configuration:*
- [ ] `user_attributes` table with `user_id`, `tenant_id`, `attribute_key`, `value`, `source`, `source_idp_id`, `updated_at`
- [ ] `tenant_attribute_config` table with `tenant_id`, `attribute_key`, `category`, `enabled`, `required`
- [ ] Profile photo stored as `bytea` blob with unguessable public URL and cache headers
- [ ] Manager stored as user reference (resolved) or raw text (unresolved)
- [ ] Migration for all new tables

*Category opt-in UI:*
- [ ] Settings page with category-level toggles (Contact, Professional, Location, Profile)
- [ ] Per-attribute toggles within each category
- [ ] Activating a category enables all its attributes
- [ ] A category shows as "on" if any attribute within it is enabled
- [ ] Super admins can mark individual attributes as required

*Editability and source tracking:*
- [ ] Every attribute value tracks source (`idp`, `admin`, `self`)
- [ ] IdP-sourced values are read-only for everyone with "Set by [IdP name]" indicator
- [ ] Admin-sourced values editable by admins
- [ ] Self-sourced values editable by the user (subject to `allow_users_edit_profile`)
- [ ] IdP login overwrites with `source=idp` when assertion includes the attribute
- [ ] Missing assertion attributes preserve existing values

*Profile photo:*
- [ ] Users can upload their own photo
- [ ] Admins can set photos on users
- [ ] IdP-provided photo URLs fetched, resized, and stored
- [ ] Served via unguessable public URL with cache headers
- [ ] Falls back to mandala avatar when no photo is set

*Manager field:*
- [ ] Resolved to user reference when possible, stored as raw text when not
- [ ] Background job resolves unresolved managers periodically
- [ ] Admins can manually set manager on any user

*Required field enforcement:*
- [ ] Non-dismissable "profile incomplete" banner on dashboard linking to profile page
- [ ] Admin view of users with incomplete required attributes
- [ ] Bulk "force profile completion" action
- [ ] Forced users can sign in but are redirected to profile and cannot navigate away until complete
- [ ] User creation dialog surfaces enabled attributes with prepopulation suggestion

*SAML mapping:*
- [ ] Per-IdP upstream attribute mapping configuration (IdP attribute name to WeftID standard key)
- [ ] Standard attributes available in per-SP downstream assertion configuration
- [ ] Standard SAML OIDs used by default, custom friendly names supported

*API:*
- [ ] API endpoints for reading/writing user attributes
- [ ] API endpoints for tenant attribute configuration
- [ ] API endpoint for incomplete profiles list

*Audit:*
- [ ] Attribute changes logged via `log_event()` with old/new values in metadata
- [ ] Configuration changes (enable/disable/require) logged
- [ ] `track_activity()` for read operations

**Effort:** XL
**Value:** High
**Version impact:** Minor (new feature, no breaking changes to existing attributes)

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
