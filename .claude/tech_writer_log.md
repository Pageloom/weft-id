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
- **settings_profile.html**: "Choose how WeftID looks..." → "Choose your theme or use your system setting." + regional settings description tightened
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
- **Product name "WeftID"** - Canonical form, used consistently.
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
- `creating-groups.md` -- Creation flow, WeftID vs IdP group types
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

---

## 2026-03-08 - Rename MFA to Two-Step Verification

**Starting commit:** a4d8565
**Mode:** Both (copy review + documentation)

### Changes Made

Renamed all user-facing references from "MFA" / "Multi-Factor Authentication" / "Two-Factor Authentication" to "Two-Step Verification" across templates, navigation, and documentation. Rewrote the signing-in documentation to explain email verification vs two-step verification.

### Template Changes (8 files)

1. **settings_mfa.html** -- Title "MFA Settings" → "Two-Step Verification", heading "Multi-Factor Authentication" → "Two-Step Verification", backup codes text updated
2. **mfa_verify.html** -- Title and heading "Two-Factor Authentication" → "Two-Step Verification"
3. **mfa_backup_codes.html** -- Heading "Two-Factor Authentication Enabled!" → "Authenticator App Enabled!"
4. **mfa_downgrade_verify.html** -- Title/text "Disable MFA" → "Switch to Email Verification", button "Verify and Disable MFA" → "Verify and Switch to Email"
5. **user_detail_tab_danger.html** -- Section heading, descriptive text, button label, confirmation dialog all updated
6. **user_detail_tab_profile.html** -- Labels "MFA Enabled" → "Two-Step Verification", "MFA Method" → "Verification Method"
7. **user_detail_base.html** -- Success message for MFA reset updated
8. **saml_idp_tab_details.html** -- Label "Require Platform MFA" → "Require Platform Two-Step Verification"

### Navigation Changes (pages.py)

- "MFA Settings" → "Two-Step Verification"
- "Verify MFA Downgrade" → "Verify Method Change"
- "MFA" → "Two-Step Verification"
- "MFA Verification" → "Verification"

### Documentation Changes

**Renamed files:**
- `docs/user-guide/mfa.md` → `docs/user-guide/two-step-verification.md`
- `docs/admin-guide/security/mfa.md` → `docs/admin-guide/security/two-step-verification.md`

**Rewrote signing-in page** (`docs/user-guide/signing-in.md`):
- Restructured as 3 steps: email verification, password/IdP, two-step verification
- Added "Why two codes on first sign-in?" section explaining the difference between email possession verification and two-step verification
- Explained that email verification exists so WeftID can safely identify users before revealing account details

**Updated cross-references in 9 docs files:**
- `mkdocs.yml` (2 nav entries)
- `docs/index.md`, `docs/user-guide/index.md`, `docs/admin-guide/index.md`
- `docs/admin-guide/security/index.md`
- `docs/admin-guide/users/roles-and-permissions.md` (2 references)
- `docs/admin-guide/users/user-lifecycle.md`
- `docs/admin-guide/identity-providers/saml-setup.md`
- `docs/admin-guide/audit/index.md`
- `docs/admin-guide/service-providers/sso-flow.md`
- `docs/self-hosting/index.md`

### Not Changed (Intentional)

- Internal developer docs (`docs/internal/`) -- developer-facing, use technical terminology
- File names for templates (`settings_mfa.html`, `mfa_verify.html`, etc.) -- internal implementation
- URL paths (`/account/mfa`, `/mfa/verify`) -- internal implementation
- Python variable/column names (`mfa_enabled`, `mfa_method`, `require_platform_mfa`) -- internal implementation
- HTML comments referencing MFA -- not user-facing

### Areas Not Yet Reviewed

- API error response messages (app/routers/api/) -- copy review pending
- Service layer error messages (app/services/exceptions.py usage) -- copy review pending

---

## 2026-03-08 - Full Documentation Gap Scan

**Starting commit:** 8aa8fde
**Mode:** Documentation (full gap analysis)

### Gap Analysis

Compared the complete application feature inventory (routers, templates, pages.py, API endpoints, background jobs) against all 34 documentation pages. Identified 6 gaps:

1. **Single Logout (SLO)** -- Critical. No documentation despite full implementation (SP-initiated, IdP-initiated propagation, HTTP-Redirect/POST bindings, signed messages).
2. **OAuth2 / Integrations** -- Critical. Complete OAuth2 system (authorization code + client credentials flows, PKCE, client management UI) with zero documentation. API index referenced a non-existent Integrations section.
3. **Event Export + Background Jobs** -- Medium. Audit docs mentioned export but referenced a non-existent Background Jobs page. No details on format, retention, or the jobs UI.
4. **Admin Reactivation Workflow** -- Medium. User lifecycle mentioned reactivation requests but didn't document the admin pending requests page, approve/deny flows, email notifications, or denial behavior.
5. **Sign-out / SLO propagation** -- Minor. One sentence about sign-out with no mention of SLO propagation to downstream SPs or upstream IdP.
6. **My Apps launch flow** -- Minor. Dashboard docs didn't connect app launch to IdP-initiated SSO.

### New Pages Created (5)

1. **`docs/admin-guide/service-providers/slo.md`** -- Single Logout: SP-initiated and IdP-initiated flows, SLO URL configuration (SP and IdP sides), metadata advertising, signing, best-effort propagation, audit events.
2. **`docs/admin-guide/integrations/index.md`** -- Integrations overview: two client types, common operations, client secret handling.
3. **`docs/admin-guide/integrations/apps.md`** -- Apps: creation fields, authorization code flow (step-by-step), PKCE support, token lifetimes, management operations.
4. **`docs/admin-guide/integrations/b2b.md`** -- B2B Service Accounts: creation fields, client credentials flow, service roles table, management operations.
5. **`docs/user-guide/background-jobs.md`** -- Background Jobs: job statuses, viewing output, downloading files, retention, deleting old jobs.

### Pages Updated (8)

1. **`docs/admin-guide/service-providers/index.md`** -- Added SLO link
2. **`docs/admin-guide/service-providers/sso-flow.md`** -- Cross-referenced SLO from session index
3. **`docs/admin-guide/index.md`** -- Added Integrations section link
4. **`docs/admin-guide/audit/index.md`** -- Expanded export section: format (gzipped JSON), retention (24h), admin requirement
5. **`docs/admin-guide/users/user-lifecycle.md`** -- Expanded reactivation: admin notification, pending requests page, approve/deny flow, email notifications, denial behavior, super admin self-reactivation
6. **`docs/user-guide/index.md`** -- Added Background Jobs link
7. **`docs/user-guide/signing-in.md`** -- Expanded sign-out: SLO propagation to downstream SPs, IdP SLO redirect, best-effort behavior
8. **`docs/user-guide/dashboard.md`** -- Connected My Apps launch to IdP-initiated SSO flow with cross-reference

### Navigation Updated

- **`mkdocs.yml`** -- Added Single Logout under Service Providers, added Integrations section (index + Apps + B2B), added Background Jobs under User Guide

### Config/Links Fixed

- **`docs/api/index.md`** -- Fixed broken Integrations link (pointed to admin-guide/index.md, now points to admin-guide/integrations/index.md). Added client credentials flow mention.

### Screenshots Requested

None.

### Areas Not Yet Reviewed (as of 2026-03-08)

- API error response messages (app/routers/api/) -- copy review pending
- Service layer error messages (app/services/exceptions.py usage) -- copy review pending

---

## 2026-03-16 - Documentation Gap Fill (New Features)

**Starting commit:** 40b6789
**Mode:** Documentation

### Gap Analysis

Compared 40 commits since last session (8aa8fde..HEAD) against documentation pages. Found 5 undocumented features. 3 features (tenant provisioning CLI, self-hosting, versioning) were already well-documented.

### Pages Updated (9)

1. **`docs/admin-guide/service-providers/registering-an-sp.md`** -- Added Logo section (upload, formats, size requirements, removal). Added user access count explanation under Step 4.
2. **`docs/admin-guide/service-providers/attribute-mapping.md`** -- Added Assertion Encryption section (AES-256-CBC, RSA-OAEP, automatic from metadata, UI status indicator).
3. **`docs/admin-guide/service-providers/sso-flow.md`** -- Updated SP-initiated step 6 to mention encryption. Added encryption bullet to "What's in the assertion" section.
4. **`docs/admin-guide/service-providers/index.md`** -- Updated attribute mapping link text to mention encryption.
5. **`docs/admin-guide/branding/index.md`** -- Added "Custom acronyms" subsection under Group branding (up to 4 chars, override auto-generated initials, set from group Details tab).
6. **`docs/admin-guide/groups/creating-groups.md`** -- Added cross-reference to custom acronyms after group creation.
7. **`docs/user-guide/index.md`** -- Added note about contextual help icon in the navigation bar.
8. **`docs/user-guide/dashboard.md`** -- Mentioned SP logos in My Apps section.
9. **`docs/getting-started/first-login.md`** -- Added tip about contextual help icon before "Next steps".

### Features Documented

| Feature | Where Documented |
|---------|-----------------|
| SAML assertion encryption | attribute-mapping.md (new section), sso-flow.md (2 updates) |
| SP logo/avatar | registering-an-sp.md (new section), dashboard.md (mention) |
| Customizable group acronyms | branding/index.md (new subsection), creating-groups.md (cross-ref) |
| Contextual help links | user-guide/index.md (note), first-login.md (tip) |
| User access count on SP list | registering-an-sp.md (paragraph under Step 4) |

### Already Documented (No Changes Needed)

- Tenant provisioning CLI (self-hosting/index.md)
- Self-hosting guide (self-hosting/index.md)
- Versioning and release (VERSIONING.md, self-hosting/index.md)

### Screenshots Requested

None.

### Areas Not Yet Reviewed (as of 2026-03-16)

- API error response messages (app/routers/api/) -- copy review pending
- Service layer error messages (app/services/exceptions.py usage) -- copy review pending

---

## 2026-03-21 - Documentation Update (Password Features + Graph)

**Starting commit:** 40b6789
**Mode:** Documentation

### Gap Analysis

Compared 37 commits since last session against documentation pages. Identified 2 major undocumented feature areas and 1 minor update.

### New Pages Created (2)

1. **`docs/admin-guide/security/passwords.md`** -- Password policy settings (min length, min score), super admin enforcement, HIBP breach detection (at-set-time and weekly monitoring), forced password reset, password change, audit events.
2. **`docs/user-guide/password.md`** -- Changing password, forgot password flow, forced reset, password requirements.

### Pages Updated (8)

1. **`docs/admin-guide/security/index.md`** -- Added Passwords link at top of list.
2. **`docs/user-guide/index.md`** -- Added Password link between Profile and Two-Step Verification.
3. **`docs/user-guide/signing-in.md`** -- Added forgot password link to step 2, noted forced password reset flow.
4. **`docs/admin-guide/users/user-lifecycle.md`** -- Added "password reset required" sub-state under Active.
5. **`docs/admin-guide/audit/index.md`** -- Added password resets and breach detection to Authentication event examples.
6. **`docs/getting-started/first-login.md`** -- Updated password section with strength meter mention, super admin minimum length, password manager recommendation.
7. **`docs/admin-guide/groups/group-hierarchy.md`** -- Added Shift+drag subtree move and improved tooltip positioning to graph visualization section.
8. **`mkdocs.yml`** -- Added Passwords under Security, Password under User Guide.

### Features Documented

| Feature | Where Documented |
|---------|-----------------|
| Password policy settings | admin-guide/security/passwords.md (new) |
| HIBP breach detection | admin-guide/security/passwords.md (new) |
| Forced password reset | admin-guide/security/passwords.md, user-lifecycle.md, signing-in.md |
| Self-service forgot password | user-guide/password.md (new), signing-in.md |
| Password change | user-guide/password.md (new), admin-guide/security/passwords.md |
| Password audit events | admin-guide/security/passwords.md, audit/index.md |
| Shift+drag subtree in graph | admin-guide/groups/group-hierarchy.md |
| Tooltip repositioning in graph | admin-guide/groups/group-hierarchy.md |

### Not Documented (Intentional)

- **About WeftID page** -- An admin settings page that displays the version and links to docs. It's a navigation convenience, not a feature that needs its own documentation page.
- **Production Dockerfile changes** (Poetry to pip) -- Internal build optimization. No impact on self-hosting users who pull pre-built images.
- **Dependency bumps** -- No user-facing changes.

### Screenshots Requested

None.

### Areas Not Yet Reviewed (as of 2026-03-21)

- API error response messages (app/routers/api/) -- copy review pending
- Service layer error messages (app/services/exceptions.py usage) -- copy review pending

---

## 2026-03-21 - Documentation Update (Group Assertion Scope)

**Starting commit:** 2e66a95
**Mode:** Documentation

### Gap Analysis

Compared 8 commits since last session (3b452dc..HEAD) against documentation pages. One new feature needed documenting: group assertion scope with consent screen disclosure.

### Pages Updated (7)

1. **`docs/admin-guide/service-providers/attribute-mapping.md`** -- Expanded "Group claims" section. Added "Group assertion scope" subsection with scope table (access-granting, top-level, all), resolution order, and consent screen cross-reference.
2. **`docs/admin-guide/service-providers/sso-flow.md`** -- Updated consent screen section to mention group disclosure with 10-item threshold. Updated "What's in the assertion" to reference group assertion scope.
3. **`docs/admin-guide/security/permissions.md`** -- Added "Group assertion scope" section with scope table, default behavior, and cross-references to attribute mapping and audit docs.
4. **`docs/admin-guide/groups/group-based-access.md`** -- Added "Groups in assertions" section explaining relationship between access and assertion scope.
5. **`docs/admin-guide/security/index.md`** -- Added group assertion scope to the overview description.
6. **`docs/admin-guide/audit/index.md`** -- Added group assertion scope changes to Settings event category.
7. **`docs/glossary.md`** -- Added "Group assertion scope" definition. Updated "Consent screen" to mention group disclosure.

### Features Documented

| Feature | Where Documented |
|---------|-----------------|
| Group assertion scope (tenant default) | permissions.md (new section), attribute-mapping.md (new subsection) |
| Per-SP scope override | attribute-mapping.md (scope resolution order) |
| Consent screen group disclosure | sso-flow.md (updated consent screen section) |
| Scope options (access-granting, trunk, all) | attribute-mapping.md, permissions.md, glossary.md |

### Not Documented (Intentional)

- Version bumps (1.0.4) -- no user-facing changes
- Dependency bumps -- no user-facing changes
- Zensical 0.0.28 docs rebuild -- infrastructure only
- Production Dockerfile version extraction -- internal build change

### Screenshots Requested

None.

### Areas Not Yet Reviewed

- API error response messages (app/routers/api/) -- copy review pending
- Service layer error messages (app/services/exceptions.py usage) -- copy review pending

---

## 2026-03-21 - Copy Review + Documentation (Self-Hosting Restructure)

**Starting commit:** ea01468
**Mode:** Both (copy review + documentation)

### Mode 2: Documentation — Self-Hosting Restructure

Rewrote `docs/self-hosting/index.md` for a clearer first-setup flow. The previous version mixed
setup steps with reference material, making it hard for a first-time deployer to follow.

**Structural changes:**
- Restructured as numbered steps: 1. DNS → 2. Install → 3. Configure email → 4. Start → 5. Provision
- DNS setup moved from a subsection of "Quick start" to step 1 (DNS propagation takes time, start early)
- Email configuration extracted as its own step between install and start (clarifies that non-SMTP users need to edit .env before starting)
- Added "Manual install" collapsible note for users who prefer not to pipe the script
- Added troubleshooting guidance in step 4 (check service status, view migration logs)
- Merged "Provisioning additional tenants" into step 5 (was a disconnected section at the bottom)
- Day-2 operations (Upgrading, Backups, Monitoring) grouped together after the setup steps
- Architecture, Configuration reference, Database, and TLS details moved under a "Reference" heading at the end

**Content fixes:**
- Fixed Postgres version: `postgres:16-alpine` → `postgres:18-alpine` (matching docker-compose.production.yml)
- Updated "MFA secrets" → "two-step verification secrets" in SECRET_KEY description (terminology)
- Updated "Ensures MFA codes are always verified" → "Ensures verification codes are always checked" (terminology)
- Clarified that install script only handles SMTP interactively; SendGrid/Resend require editing .env after

### Mode 1: Copy Review — Password Templates + API/Service Error Messages

**Password template copy fixes (5 files):**

1. **forced_password_reset.html:22** — Intro tightened: "An administrator has required you to change your password before continuing. Please choose a new password." → "An administrator has required a password change. Choose a new password."
2. **forced_password_reset.html:32** — "The password is not strong enough. Please choose a stronger password." → "Password is not strong enough. Choose a stronger password."
3. **reset_password.html:32** — Same password_too_weak fix (was "The password")
4. **set_password.html:38** — "Please choose" → "Choose" (already dropped article)
5. **settings_password.html:39** — "The new password is not strong enough. Please choose..." → "New password is not strong enough. Choose..."
6. **settings_password.html:21** — "Update your password. We recommend using a password manager to generate and store a strong password." → "Update your password."
7. **forgot_password.html:11** — "Enter your email address and we'll send you a link to reset your password." → "We'll send a reset link to your email address."
8. **set_password.html:101** — "After setting your password, you'll be able to sign in and access your account." → "After setting your password, you can sign in."

**Password error message standardization:**

| Error | Before | After |
|-------|--------|-------|
| password_too_weak (forced_password_reset) | "The password is not strong enough. Please choose a stronger password." | "Password is not strong enough. Choose a stronger password." |
| password_too_weak (reset_password) | "The password is not strong enough. Please choose a stronger password." | "Password is not strong enough. Choose a stronger password." |
| password_too_weak (set_password) | "Password is not strong enough. Please choose a stronger password." | "Password is not strong enough. Choose a stronger password." |
| password_too_weak (settings_password) | "The new password is not strong enough. Please choose a stronger password." | "New password is not strong enough. Choose a stronger password." |

**API error message review (app/routers/api/):**

Reviewed all files in `app/routers/api/v1/`. Found 11 total messages:
- 7 "Client not found" in oauth2_clients.py (consistent)
- 1 "Per-IdP SP certificate not found" in saml.py (correct)
- 1 "Unknown provider type" in saml.py (uses internal identifiers, acceptable for API consumers)
- 1 "Failed to create export task" in exports.py
- 1 "Verification email sent" in users/emails.py

Most API endpoints delegate error handling to `translate_to_http_exception()`, which converts service-layer exceptions to HTTP responses. The direct HTTPException raises are consistent.

**Service layer error message review (app/services/):**

Reviewed 288+ error occurrences across all service modules. Messages are well-structured with descriptive `code` parameters and consistent patterns. Minor inconsistency: some messages have trailing periods, some don't. Not user-facing (these surface through the API or get mapped to template error codes).

### Issues Logged

None. All findings were directly fixable copy changes.

### Screenshots Requested

None.

### Areas Fully Reviewed

All pending areas from previous sessions are now covered:
- API error response messages (app/routers/api/) — reviewed, consistent
- Service layer error messages (app/services/) — reviewed, consistent
- Self-hosting documentation — restructured for first-setup flow
