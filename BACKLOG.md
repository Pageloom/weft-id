# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Tooling: Dead Links Compliance Check

**User Story:**
As a developer
I want the `./code-quality` script to flag template links that don't match any registered route
So that typos and stale paths in templates are caught during CI rather than at runtime

**Acceptance Criteria:**
- [ ] New `--check template-links` principle added to `scripts/compliance_check.py`
- [ ] Scans all `app/templates/**/*.html` files for `href` and `action` attribute values
- [ ] Skips external URLs, relative-only links (`?...`, `#`), and static/branding paths
- [ ] Normalizes Jinja2 dynamic segments (`{{ ... }}`) to wildcards before matching
- [ ] Collects all registered route paths from Python router files in `app/routers/`
- [ ] Strips query strings from template paths before matching
- [ ] Reports unmatched paths as violations with file and line number
- [ ] Integrated into the default `--check all` run (picked up by `./code-quality`)
- [ ] Zero false positives on the existing template set at time of implementation

**Effort:** S
**Value:** Medium

---

## Admin: User-App Access Query

**User Story:**
As an admin
I want to check whether a specific user has access to a specific application, and see all
apps available to a user
So that I can troubleshoot access issues and audit permissions

**Context:**

`check_user_sp_access()` already exists in the database layer. This item adds a UI and
API surface for it. The dependency on SAML IdP Phase 2 is resolved.

**Acceptance Criteria:**

- [ ] Admin page or widget: select a user, see all their accessible SPs
- [ ] Shows which groups grant each SP access (traceability)
- [ ] Search/filter by user
- [ ] API endpoint: `GET /api/v1/users/{user_id}/accessible-apps`

**Effort:** M
**Value:** Medium (Admin troubleshooting, low implementation cost)

---

## Service Provider: "Available to All Users" Access Mode

**User Story:**
As an admin
I want to mark a service provider as available to all users without requiring explicit group
assignments
So that universal apps (e.g., company intranet, HR portal) are accessible to everyone without
maintaining a catch-all group

**Context:**

Currently, SP access requires at least one group connection. For apps that every user should
access, admins must create a catch-all group and keep it up to date. This item adds a
first-class "available to all" toggle that grants access to every active user in the tenant.

A future enhancement may add group-based exclusions ("available to all except Group X"), but
that is out of scope for this item.

**Acceptance Criteria:**

Database:
- [ ] New boolean column on the `service_providers` table: `available_to_all` (default `false`)
- [ ] Migration adds the column with appropriate default and constraint
- [ ] `check_user_sp_access()` updated to return `true` when `available_to_all` is `true`
      (regardless of group membership)
- [ ] SP list/detail queries include the new field

Service:
- [ ] Update SP create/update schemas to accept `available_to_all`
- [ ] When `available_to_all` is `true`, the SP appears in every user's accessible apps
- [ ] SSO flow treats "available to all" SPs identically to group-connected SPs (consent
      screen, attribute assertions, audit logging all behave the same)
- [ ] Event logged when `available_to_all` is toggled (`sp_access_mode_updated`)

Dashboard and IdP-initiated SSO:
- [ ] "Available to all" SPs appear in every user's "My Apps" on the dashboard
- [ ] Users can initiate IdP-initiated sign-in to these SPs from the dashboard

SP detail page (no-access warning):
- [ ] When an SP has `available_to_all = false` AND has zero group connections, show a
      prominent banner at the top of the detail page: "No users have access to this application"
- [ ] Banner includes a "Set up access" link that navigates to the SP's group/access
      configuration section
- [ ] The access configuration section offers two options: "Available to all users" (toggle)
      or connecting specific groups (existing behaviour)

API:
- [ ] `available_to_all` field exposed in SP API responses
- [ ] SP create/update API endpoints accept and persist the field
- [ ] `GET /api/v1/users/{user_id}/accessible-apps` includes "available to all" SPs

Tests:
- [ ] Service tests: toggling `available_to_all` grants/revokes universal access
- [ ] Service tests: SSO flow works identically for "available to all" SPs
- [ ] API tests: create/update SP with `available_to_all`, verify in accessible-apps response
- [ ] Template tests: no-access banner appears when SP has no groups and is not available to all
- [ ] Template tests: banner is hidden when SP has groups or is available to all

**Effort:** M
**Value:** High

---

## Auto-assign Users to Groups Based on Privileged Email Domains

**User Story:**
As a super admin
I want to configure privileged domains to automatically assign users with matching email
addresses to specified groups
So that I do not have to manually manage group memberships for users from known domains

**Acceptance Criteria:**

- [ ] Link one or more WeftId groups to a privileged domain
- [ ] When a user is created or verified with an email matching the domain, auto-add to linked groups
- [ ] Existing users can be bulk-processed when a domain-group link is added
- [ ] Domain-group links shown on privileged domain detail page
- [ ] Auto-assigned memberships are regular memberships (can be manually removed)
- [ ] Event log entries for auto-assignments

**Effort:** S-M
**Value:** Medium (Reduces admin toil for common onboarding pattern)

---

## Reusable SVG Icon System

**User Story:**
As a developer
I want all SVG icons stored as named, reusable assets and includable via a simple macro call
So that icons are consistent, maintainable, and not duplicated across templates

**Context:**

There are currently 45 inline SVG elements copy-pasted across 25 template files, representing 20 distinct icon shapes. There is no icon system, no shared macro, and no central storage. Many icons are heavily duplicated (chevron-down appears 7 times, warning-triangle 5 times, check-mark 4 times). There are also inconsistencies: two different pencil/edit icon styles and two different warning triangle styles (solid vs outline) used for the same semantic purpose.

All icons are Heroicons-compatible paths embedded manually. The mandalas (decorative generative art) are excluded from this item.

**What exists today (20 distinct icons, by duplication count):**

| Icon | Uses | Templates |
|------|------|-----------|
| chevron-down | 7 | base, groups_members_add, groups_members, users_list |
| warning-triangle-solid | 5 | mfa_backup_codes, saml_idp_tab_danger (x2), saml_idp_tab_details, saml_test_result |
| check-mark | 4 | mfa_backup_codes, reactivation_requested, saml_test_result, super_admin_reactivate |
| chevron-up | 3 | groups_members_add, groups_members, users_list |
| chevron-right | 3 | integrations_apps, integrations_b2b, saml_idp_select |
| x-close | 3 | saml_error, saml_idp_sso_error, saml_test_result |
| sort-arrows | 3 | groups_members_add, groups_members, users_list |
| pencil-edit | 3 | saml_idp_sp_tab_details (x2), saml_idp_tab_details |
| check-circle | 2 | saml_debug_list, saml_idp_tab_details |
| info-circle | 2 | saml_debug_detail, saml_idp_tab_attributes |
| arrow-right | 1 | dashboard |
| shield-check | 1 | saml_idp_sso_consent |
| warning-triangle-outline | 1 | account_inactivated |
| pencil-edit-document | 1 | users_list |
| clipboard-document | 1 | account_background_jobs |
| download | 1 | account_job_output |
| grid-plus | 1 | integrations_apps |
| server-stack | 1 | integrations_b2b |
| envelope | 1 | saml_idp_sso_consent |
| person-user | 1 | saml_idp_sso_consent |

**Acceptance Criteria:**

Icon storage and macro:
- [ ] Create a dedicated icon directory (e.g., `app/templates/icons/`) with one `.svg` file per icon, named semantically (e.g., `chevron-down.svg`)
- [ ] Create a Jinja2 macro (e.g., `icon(name, class="")`) that includes an icon by name and applies CSS classes
- [ ] Macro supports passing Tailwind classes for sizing and color (e.g., `{{ icon('chevron-down', class='w-5 h-5 text-gray-400') }}`)

Icon consolidation:
- [ ] Resolve inconsistencies: pick one pencil/edit icon style, one warning triangle style
- [ ] All 20 distinct icons extracted to the icon directory
- [ ] All 45 inline SVG instances replaced with macro calls

Quality:
- [ ] All existing tests continue to pass
- [ ] Visual appearance unchanged (icons render identically to before)
- [ ] Document the icon system and available icon names in skill references

**Effort:** S-M
**Value:** Medium (DRY, consistency, maintainability)

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

## Group Graph: Toolbar, New Group Modal, and Label Overlap

**User Story:**
As an admin using the group graph view
I want a cleaner toolbar, the ability to create groups directly from the graph, and non-overlapping edge labels
So that the graph feels polished, I can build the group hierarchy without leaving the canvas, and off-screen labels are readable

**Acceptance Criteria:**

Toolbar (icon-only buttons):
- [ ] "Add relationship", "Cut relationship", and "Edit layout" toolbar buttons show only an icon (no text label)
- [ ] Each button has a `title` tooltip that describes its function (visible on hover)
- [ ] Visual appearance and active/inactive states are preserved

New Group tool:
- [ ] A "New group" button is added to the graph toolbar (icon + tooltip, consistent with other toolbar items)
- [ ] Clicking it opens a modal with a "Name" field (required) and a "Description" field (optional), plus Cancel and Create buttons
- [ ] Submitting the modal creates the group via the existing group creation service and adds it to the graph
- [ ] The new node appears in the graph in a selected/highlighted state so the admin can immediately connect it
- [ ] Cancel closes the modal without creating anything
- [ ] Validation: name is required; shows inline error if empty on submit
- [ ] Creation failure (e.g. duplicate name) shows an error in the modal without closing it

Edge label de-overlap:
- [ ] When multiple off-screen edge labels (showing a connected group's name) would be rendered at overlapping or near-overlapping positions at the viewport boundary, they are spread out so no two labels overlap
- [ ] De-overlap logic is applied only to the off-screen labels (labels for visible nodes are unaffected)
- [ ] Labels remain close to the edge line's viewport intersection point where possible

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


## SAML: Group Assertion Transparency (Trunk-Only Mode + Consent Screen Visibility)

**User Story:**
As a super admin
I want to control whether full group memberships or only trunk groups are communicated in
SAML assertions, and as a user I want to see which groups will be shared during authentication
So that admins can minimize group exposure to service providers, and users understand what
identity information is being disclosed before they consent

**Context:**

Currently, SAML assertions include all of the user's group memberships. Two related gaps:

1. **Trunk-only mode:** A "trunk group" is any group the user belongs to that has no parent
   groups in the DAG. It represents the broadest, most concise outline of the user's group
   footprint without enumerating every nested membership. Communicating only trunk groups
   reduces how much internal group structure is leaked to service providers.

2. **Consent screen visibility:** The consent screen during SAML authentication does not show
   which groups will be shared with the SP. If group attributes are being asserted, the user
   should see exactly which groups are being disclosed before completing sign-in.

These are linked: if trunk-only mode is active, the consent screen should reflect the filtered
group set (not the full membership list).

**Acceptance Criteria:**

Trunk-only admin setting:
- [ ] New tenant-level setting in admin security settings: "Group assertion scope" with two
      options: "All groups" (share all group memberships) and "Trunk groups only" (share only
      groups with no parent groups in the DAG). Default: "Trunk groups only"
- [ ] "Trunk groups only" filters the group list included in any SAML assertion to those
      where the user has no parent group in the `group_lineage` table
- [ ] Setting is persisted with a migration; readable via the settings service
- [ ] Event logged (`group_assertion_scope_updated`) when the setting changes
- [ ] API endpoint exposes and allows updating the setting

Consent screen group disclosure:
- [ ] If the SP's attribute mapping includes a groups attribute, the consent screen displays
      the list of groups that will be shared in the assertion
- [ ] If trunk-only mode is active, the displayed groups reflect the filtered set
- [ ] If the SP does not request a groups attribute, this section is hidden
- [ ] Groups are listed by name; if the list is long (>10), show a count with a collapsible
      "show all" expansion

**Effort:** M
**Value:** Medium

---

## Service Provider Logo / Avatar

**User Story:**
As an admin
I want to upload a logo for each service provider, with a generated acronym avatar as fallback
So that SPs are visually identifiable in lists, detail pages, and the user dashboard

**Context:**

Service providers currently have no visual identity. Group logos already support PNG and SVG
uploads with an acronym fallback. This item brings the same pattern to service providers,
reusing the existing validation and serving infrastructure.

Upload happens from the SP detail page. The acronym fallback uses the same generation logic
as groups (works with any UUID + name). Logos appear in the SP list, SP detail header,
dashboard "My Apps" cards, and the SSO consent screen.

**Acceptance Criteria:**

Database:
- [ ] New `sp_logos` table (parallel to `group_logos`): `sp_id`, `logo_data`, `content_type`,
      `created_at`, `updated_at`, tenant-scoped with RLS
- [ ] Migration adds the table with appropriate constraints
- [ ] Add `has_logo` and `logo_updated_at` fields to SP response schemas

Service:
- [ ] Reuse validation from `app/services/branding.py` (`_validate_png`, `_validate_svg_content`)
- [ ] Same constraints as group logos: PNG (square, >=48x48, <=256KB) or SVG
- [ ] Upload and delete service functions with event logging

Serving and API:
- [ ] `/branding/sp-logo/{sp_id}` endpoint (parallel to `/branding/group-logo/{group_id}`)
- [ ] Upload endpoint under SP admin routes
- [ ] Delete endpoint under SP admin routes
- [ ] API endpoints for upload and delete under `/api/v1/`

Templates:
- [ ] SP list (`saml_idp_sp_list.html`): show logo or acronym avatar
- [ ] SP detail header (`saml_idp_sp_tab_details.html`): show logo with upload/remove controls
- [ ] Dashboard "My Apps" cards (`dashboard.html`): show logo or acronym avatar
- [ ] SSO consent screen (`saml_idp_sso_consent.html`): show logo or acronym avatar

Frontend:
- [ ] Acronym generation reuses `generateGroupAcronym()` from `static/js/group-mandala.js`
      (works with any UUID + name)

Tests:
- [ ] Service layer tests for upload validation (PNG constraints, SVG sanitization)
- [ ] Service layer tests for upload and delete with event logging
- [ ] API integration tests for upload, serve, and delete endpoints
- [ ] Template rendering tests verify logo/acronym fallback behavior

**Effort:** M
**Value:** Medium

---

## Group Graph: Extended Selection Highlighting with Depth-Aware Edge Styles

**User Story:**
As an admin using the group graph view
I want the selected node's full ancestry and descendancy to be visually represented,
with solid edges for immediate neighbours and dashed edges for more distant relatives
So that I can understand the complete hierarchical context of a group at a glance

**Context:**

Currently, selecting a node highlights only its immediate children (solid arrows pointing in)
and immediate parents (orange arrows). Grandchildren, grandparents, and more remote relatives
are invisible in the selection state.

The new rule is: **dashed line = more than one step removed.** The direction of arrows and
colour conventions remain unchanged; only the reach and stroke style change.

**Acceptance Criteria:**

Descendant side (children, grandchildren, …):
- [ ] When a node is selected, solid arrows are drawn from all **immediate children** to the
      selected node (existing behaviour, retained)
- [ ] Dashed arrows are drawn from all **grandchildren and more remote descendants** to the
      selected node
- [ ] Arrow direction is the same for all descendants (child → selected)

Ancestor side (parents, grandparents, …):
- [ ] Immediate parents continue to be highlighted with **solid orange arrows** pointing from
      the selected node to each parent (existing behaviour, retained)
- [ ] **Grandparents and more remote ancestors** are connected with **dashed arrows** (same
      direction: selected → ancestor, same orange colour or a subdued variant that is clearly
      distinguishable from immediate parents)

General:
- [ ] Depth 1 neighbours (immediate parents and children) always use solid lines
- [ ] Depth 2+ neighbours (any relative more than one step away) always use dashed lines
- [ ] Unrelated nodes remain visually neutral (no highlight, no extra edges)
- [ ] The existing Cytoscape layout and node positions are unaffected by the style change
- [ ] De-selection resets all edges to their default appearance

**Effort:** S
**Value:** Medium

---

## Groups: Remove Mandala Avatar Option

**User Story:**
As a developer
I want to remove the mandala option from group avatar styles
So that we simplify the codebase and standardize on the acronym avatar

**Context:**

Groups currently support two avatar styles: mandala (generative art from the group UUID) and
acronym (letter-based, derived from the group name). The mandala option adds complexity with
limited value. Removing it simplifies the frontend and reduces the number of code paths.

Scope: groups only. The tenant-level site logo mandala generator (`app/utils/mandala.py`)
stays, as it serves a different purpose.

**Acceptance Criteria:**

Enum and migration:
- [ ] Remove `MANDALA = "mandala"` from `GroupAvatarStyle` enum
- [ ] Migration updates any tenant with `group_avatar_style = 'mandala'` to `'acronym'`
- [ ] Migration updates the `CHECK` constraint on the column to exclude `'mandala'`

Templates:
- [ ] Remove mandala rendering branch from group list template
- [ ] Remove mandala rendering branch from group detail template
- [ ] Remove mandala rendering branch from group graph template
- [ ] Remove mandala radio option from `settings_branding_groups.html`

JavaScript:
- [ ] Remove `generateGroupMandala()` from `static/js/group-mandala.js`
- [ ] Keep `generateGroupAcronym()` (still needed for groups and SP acronym avatars)
- [ ] Rename `group-mandala.js` to `group-avatar.js`
- [ ] Update all `<script>` references to the renamed file

Backend:
- [ ] Keep `app/utils/mandala.py` (still used for site logo)
- [ ] Remove any mandala-specific service or template logic for groups

Tests:
- [ ] Existing tests continue to pass after enum and template changes
- [ ] Verify migration correctly converts existing `'mandala'` rows to `'acronym'`

**Effort:** S
**Value:** Low

---

## Onboarding Wizard for New Super Admins

> **Status: Needs grooming.** The shape is roughed out below but the details need more thought before implementation.

**User Story:**
As the first super admin of a new WeftID instance
I want a guided setup wizard that helps me get my identity layer running
So that I can reach a working configuration quickly without guessing what to do first

**Context:**

A brand new WeftID instance gives no guidance on where to start. The wizard meets the first super admin after onboarding and walks them through initial setup. It is dismissable forever (per-user flag) and only appears for super admins.

WeftID serves three primary deployment scenarios, and the wizard should adapt to whichever the admin is pursuing:

- **Identity Federation Hub:** Multiple upstream IdPs unified behind one identity layer
- **Standalone Identity Provider:** WeftID manages users directly (email/password, MFA)
- **SSO Gateway:** One IdP, but WeftID adds group-based access control and audit for downstream apps

**Rough Flow:**

1. **Welcome.** Friendly intro, explain what the wizard will help with.
2. **"How will your people sign in?"** Branching question: existing IdP, directly with WeftID, or both. Determines whether the next step is IdP setup or domain/user setup.
3. **Identity source setup.** If IdP: walk through connecting the first provider (Okta, Entra, Google, generic SAML). If direct: collect company email domain, create a privileged domain.
4. **"Let's organize your people."** Create the first group (suggest a name based on domain, e.g. "Acme Staff"). Link the domain to the group if applicable.
5. **"Connect an application."** Optional. Walk through registering the first SP, or skip for later.
6. **"Who should have access?"** Assign the group from step 4 to the SP from step 5. This is the "aha" moment.
7. **Quick security check.** MFA policy toggle, session timeout recommendation.
8. **Summary and next steps.** Show what was accomplished, link to key areas (audit logs, more apps, invite users).

**Open Design Questions:**

- Should step 3 (IdP setup) be a full inline walkthrough or just navigate to the existing config page with contextual guidance?
- For the "Both" path in step 2, run both flows sequentially or pick one as primary?
- Persistence model: wizard state as JSON on the tenant (checklist on dashboard) vs. a modal/sequential experience?
- Should "invite a co-admin" be a wizard step?
- Does the auto-assign-users-to-groups backlog item need to land first for the domain-to-group linking in step 4?

**Acceptance Criteria:**

- [ ] Wizard appears for the first super admin on a new tenant (not for subsequent admins unless they haven't dismissed it)
- [ ] Dismissable forever via a per-user flag
- [ ] Adapts flow based on the admin's stated intent (federation, standalone, SSO gateway)
- [ ] Each step is skippable ("I'll do this later")
- [ ] Completing or dismissing the wizard never blocks access to the main UI
- [ ] Progress is persisted so the wizard can be resumed across sessions
- [ ] Summary step links to relevant admin pages for continued setup

**Effort:** XL
**Value:** High

---

