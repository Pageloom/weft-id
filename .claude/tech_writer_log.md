# Tech Writer Log

## 2026-03-08 - Documentation Site Scaffold

**Starting commit:** 2ca23e9
**Mode:** Documentation

### Changes Made

1. **Moved OpenAPI docs** from `/docs` → `/api/docs` and `/redoc` → `/api/redoc` (app/main.py, 2 test files)
2. **Moved developer docs** from `docs/` to `docs/internal/` (3 files: api-baseline, api-implementation-plan, manual-testing-saml)
3. **Created `mkdocs.yml`** at project root with Material theme, dark/light toggle, navigation sections, code copy, admonitions
4. **Scaffolded 37 Markdown pages** across 6 sections: Getting Started (4), Admin Guide (21), User Guide (5), API (1), Self-Hosting (1), Home (1)
5. **Created `docs/assets/screenshots/`** directory for future screenshots
6. **Updated references** in CLAUDE.md (key files, directory structure), tech-writer SKILL.md (`docs/site/` → `docs/`, OpenAPI paths), .gitignore (added `site/` build output)
7. **Added `exclude_docs`** in mkdocs.yml to suppress warnings for `docs/internal/` and `docs/decisions/`

### Site Structure

```
mkdocs.yml
docs/
  index.md
  getting-started/    (4 pages)
  admin-guide/        (21 pages across users, groups, idps, sps, security, branding, audit)
  user-guide/         (5 pages)
  api/                (1 page)
  self-hosting/       (1 page)
  internal/           (3 moved developer docs)
  decisions/          (unchanged ADRs)
  assets/screenshots/ (empty, for future use)
```

### Pages With Content

- `docs/index.md` — Overview with section links
- All section index pages — Section descriptions with child page links
- `docs/api/index.md` — API auth, conventions, OpenAPI doc links

### Pages Still Stubs

All leaf pages (first-login, creating-users, saml-setup, etc.) contain only a title and "under construction" note. Priority fill-in candidates:
- Getting Started section (first-login, connecting-an-idp, adding-an-application)
- Roles and Permissions (foundational concept referenced by many pages)
- SSO Flow (key value proposition)

### Screenshots Requested

None.

---

## 2026-03-08 - Copy Review (Full Scan + Tightening Pass)

**Starting commit:** a9fd870
**Mode:** Copy review

### Pass 1: Terminology & Consistency Fixes

1. **login.html** (lines 14, 16, 18, 20): "log in" → "sign in" in 4 flash messages
2. **set_password.html** (line 74): "log in" → "sign in" in footer text
3. **super_admin_reactivate.html** (line 31): "log in" → "sign in"
4. **users_new.html** (line 176): "log in" → "sign in" in "What happens next?" list
5. **settings_mfa.html** (lines 14, 35): "Authenticator App / Password Manager" → "Authenticator App or Password Manager"; removed redundant "password managers" from description
6. **settings_profile.html** (line 104): "Account info" → "Account Info" (heading capitalization)
7. **saml_idp_sp_tab_attributes.html** (line 104): Removed emoji from tip text

### Pass 2: Copy Tightening (Terseness)

Target tone: security settings pages (short, direct, front-loaded, no filler).

**Settings & accounts:**
- **settings_privileged_domains.html**: Rewrote intro (4 sentences → 2), tightened success messages and binding warning
- **settings_profile.html**: "Choose how WeftId looks..." → "Choose your theme or use your system setting." + regional settings description tightened
- **account_inactivated.html**: Tightened reactivation flow copy
- **account_background_jobs.html**: "Export files are automatically deleted 24 hours after creation" → "Export files auto-delete after 24 hours"
- **admin_reactivation_requests.html**: Tightened intro and denial note

**SAML IdP templates:**
- **saml_idp_tab_details.html**: 9 edits. Tightened SP metadata sharing, settings help text (enabled, default IdP, MFA, JIT), connection testing, domain bindings
- **saml_idp_tab_certificates.html**: 5 edits. Tightened cert descriptions, PEM explanations, empty state
- **saml_idp_tab_attributes.html**: No changes needed (already terse)
- **saml_idp_tab_danger.html**: 4 edits. Tightened delete blockers and warnings

**SAML SP templates:**
- **saml_idp_sp_tab_details.html**: 4 edits. Tightened setup flow copy, metadata URL help
- **saml_idp_sp_tab_certificates.html**: 2 edits. Tightened cert intro and rotation note
- **saml_idp_sp_tab_metadata.html**: 2 edits. Rewrote intro, tightened refresh note
- **saml_idp_sp_tab_danger.html**: 3 edits. Tightened disable/delete copy
- **saml_idp_sp_tab_groups.html**: 2 edits. Tightened access description, "supplementary" → "for organization only"
- **saml_idp_sp_new.html**: 2 edits. Tightened step instructions and field help

**Group templates:**
- **groups_list.html**: Tightened intro (2 sentences → 2 shorter ones)
- **groups_detail_tab_relationships.html**: 3 edits. Parent/child descriptions tightened
- **groups_detail_tab_membership.html**: "IdP groups are managed automatically..." → "Members sync automatically from the identity provider."
- **groups_members.html**: Same IdP message tightened
- **groups_detail_tab_danger.html**: 4 edits. Tightened relationship blocker and delete messages
- **groups_detail_tab_delete.html**: 4 edits. Same changes mirrored from danger tab

### Skill Definition Updated

- **SKILL.md**: Added "Be terse" as principle #1 with reference to security settings pages as gold standard

### Cross-File Issues Logged to ISSUES.md

1. **"Login" vs "Sign in" noun/label** - "Back to Login", "Return to Login", "Last Login" across 8+ locations including pages.py
2. **"log in" in email templates** - app/utils/email.py (2 locations, Python code)

### Observations (Not Actioned)

- **"Deactivate" for OAuth2/B2B clients** - Reasonable for non-user entities. No change needed.
- **Product name "WeftId"** - Canonical form, used consistently.
- **"IdP" abbreviation** - Acceptable in admin UI for federation audience.

### Areas Reviewed

- All 82 HTML templates in app/templates/
- app/pages.py (navigation labels)
- Flash messages and error messages in templates
- Email template strings in app/utils/email.py
- Skill definition (.claude/skills/tech-writer/SKILL.md)

### Areas Not Yet Reviewed

- API error response messages (app/routers/api/)
- Service layer error messages (app/services/exceptions.py usage)
- Documentation site (Mode 2 not run)

### Screenshots Requested

None.

---

## 2026-03-08 - Structural IA Review + Copy Fixes

**Starting commit:** b610395
**Mode:** Copy review (structural focus per user request)

### Skill Definition Updated

- **SKILL.md**: Added principles 10-13 (page scanability, information density, hierarchy signals meaning, task flow). Added structural concerns to "What to Review" table and "What Goes to ISSUES.md" section.

### Direct Copy Fixes

1. **user_detail_tab_profile.html:89** - "super administrators" → "super admins" (glossary consistency)
2. **user_detail_tab_profile.html:162** - Removed stray `<br>` tag before `<strong>Note:</strong>` in amber warning box

### Structural Issues Logged to ISSUES.md

1. **Dead template: groups_detail_tab_danger.html** - Not referenced by any router. The group detail base only renders a "Delete" tab. Nearly identical code to groups_detail_tab_delete.html. Recommend deletion.
2. **Branding global: form spans two visual sections** - Site Title and Display Mode share a single `<form>` but have separate H2 headings and border-t separators, creating misleading visual hierarchy.
3. **User profile tab: read-only info at same visual weight as edit sections** - Five H2 sections with identical border-t separation. Read-only User Information grid uses same weight as edit forms. No task-based grouping.
4. **Branding global: logo requirements note at page bottom** - Blue info box with format/size requirements appears after all upload sections. Users hit validation errors before seeing constraints.

### Structural Observations (Not Logged)

These patterns were reviewed and found acceptable or debatable:

- **Privileged domains: dense cards** - Domain cards pack binding + group linking + metadata. Dense but appropriate for the admin audience managing multiple domains.
- **SAML trust establishment: nested tabs** - URL/XML/Manual tabs inside a card within the page-level tab bar. Creates visual hierarchy ambiguity, but the numbered steps (1, 2) provide enough orientation.
- **IdP/SP tab bars: destructive tab alongside operational** - Delete/Disable tab at the end of the tab bar. Common pattern (GitHub, AWS console). The red styling provides sufficient visual distinction.
- **Group membership tab: high complexity** - Search, filtering, sorting, pagination, multiselect, inherited members all in one view. Complex but the list manager pattern keeps it consistent with other list views.
- **Settings profile: multiple H1 per card** - Unusual heading hierarchy but each card is a visually independent section. Works in practice.
- **Duplicate pagination controls** (top + bottom) - Standard pattern for long tables. Acceptable.

### Full Structural Review Coverage

All 82 templates reviewed for:
- Heading hierarchy (H1/H2/H3 usage and consistency)
- Section grouping and logical separation
- Information density per section
- Help text proportionality to complexity
- Task flow alignment (does page order match user workflow?)
- Mixed concerns (unrelated content in same section)

### Areas Not Yet Reviewed

- API error response messages (app/routers/api/)
- Service layer error messages (app/services/exceptions.py usage)
- Documentation site (Mode 2 not run)

### Screenshots Requested

None.

---

## 2026-03-08 - Documentation Content (All Leaf Pages)

**Starting commit:** d74f440
**Mode:** Documentation

### Changes Made

Wrote content for all 25 stub pages and expanded 2 section pages (branding, audit). Every page was written from source code research (templates, routers, services) to ensure accuracy.

### Pages Written

**Getting Started (3 pages):**
- `first-login.md` -- Email verification, password setup, dashboard overview, next steps
- `connecting-an-idp.md` -- Create connection, share metadata, establish trust (3 methods)
- `adding-an-application.md` -- Create SP, share metadata, import app metadata, configure access

**Admin Guide - Users (3 pages):**
- `creating-users.md` -- Manual creation, JIT provisioning, auto-assignment to groups
- `user-lifecycle.md` -- Active, inactivated (reactivation flows), anonymized (GDPR)
- `roles-and-permissions.md` -- Super admin, admin, user capabilities and assignment rules

**Admin Guide - Groups (4 pages):**
- `creating-groups.md` -- Creation flow, WeftId vs IdP group types
- `group-hierarchy.md` -- DAG model, parent-child management, graph visualization
- `membership-management.md` -- Add/remove members, IdP groups, inherited membership
- `group-based-access.md` -- SP group assignments, access enforcement, hierarchy

**Admin Guide - Identity Providers (2 pages):**
- `saml-setup.md` -- 3-step setup, connection settings, attribute mapping, metadata refresh, deletion
- `privileged-domains.md` -- Add domain, bind IdP, link groups, example workflow

**Admin Guide - Service Providers (4 pages):**
- `registering-an-sp.md` -- 4-step registration, settings table, deletion
- `sp-certificates.md` -- Auto-generation, viewing, rotation with grace period
- `attribute-mapping.md` -- Default attributes, group claims, custom mappings, NameID formats
- `sso-flow.md` -- SP-initiated and IdP-initiated flows, consent screen, assertion contents

**Admin Guide - Security (4 pages):**
- `sessions.md` -- Max session length, persistent sessions, auto-inactivation (all options listed)
- `certificates.md` -- Validity period and rotation window (all options listed)
- `permissions.md` -- Profile edit and email add toggles
- `mfa.md` -- Per-IdP MFA requirement, admin MFA reset

**Admin Guide - Section Pages Updated (2 pages):**
- `branding/index.md` -- Expanded with site title, display mode, logo upload details, group branding
- `audit/index.md` -- Expanded with filtering, event detail, export, event types table, activity tracking

**User Guide (4 pages):**
- `dashboard.md` -- Identity display, My Apps, My Groups
- `profile.md` -- Name, theme, regional settings, email management, account info
- `mfa.md` -- TOTP setup, backup codes, email MFA, switching/disabling
- `signing-in.md` -- Email-first flow, trust cookies, IdP sign-in, sign-out

**Self-Hosting (1 page):**
- `self-hosting/index.md` -- Requirements, services table, env vars (required, email, optional), database, getting started

### Documentation Principles Applied

- Task-oriented (each page answers "how do I do X?")
- Audience-appropriate (admin guide assumes federation knowledge, user guide assumes nothing)
- Mirrors the UI navigation structure
- Tables for options/settings, numbered lists for step-by-step flows
- Cross-linked between related pages

### Screenshots Requested

None. Pages were written to be useful without screenshots. Screenshots would enhance the Getting Started section and SSO Flow page in particular.

### Areas Not Yet Reviewed

- API error response messages (app/routers/api/) -- copy review pending
- Service layer error messages (app/services/exceptions.py usage) -- copy review pending
