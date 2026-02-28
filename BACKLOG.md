# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Groups: Inline Members Tab (Remove Manage Members Indirection)

**User Story:**
As an admin managing a group
I want the Members tab to show the full paginated member list directly, with an "Add Members" button in the header
So that I don't have to navigate to a separate page just to see or manage who's in the group

**Context:**

The current Members tab (`groups_detail_tab_membership.html`) shows a truncated preview of
members and a "Manage Members" button that navigates to `/admin/groups/{id}/members`. That
page then shows the same list again, with pagination, search, sort, and remove controls.
The extra hop adds friction without adding value.

The target state: the Members tab IS the members page. Full list, paginated, searchable,
sortable, with remove controls inline. "Add Members" button in the tab header. The separate
`/admin/groups/{id}/members` route is removed (or redirects to the tab).

The add-members flow at `/admin/groups/{id}/members/add` is unaffected.

**Acceptance Criteria:**

- [ ] The Members tab renders the full paginated member list directly (no truncation, no "View all" link)
- [ ] Tab header contains an "Add Members" button (links to `/admin/groups/{id}/members/add`) for weftid groups
- [ ] Members list supports pagination, search, and sort (matching the current `/admin/groups/{id}/members` page)
- [ ] Direct members can be removed inline (individual remove button or checkbox + bulk remove bar), for weftid groups only
- [ ] The separate `/admin/groups/{id}/members` route is removed; any inbound links redirect to the group detail Members tab (`/admin/groups/{id}?tab=members` or equivalent)
- [ ] IdP groups show the read-only notice and no add/remove controls (same as today)
- [ ] Inherited members are still shown and labeled (same as today)
- [ ] `app/pages.py` updated: `/admin/groups/{id}/members` entry removed
- [ ] All existing tests updated or replaced; new tests cover the inline tab behaviour
- [ ] API endpoints for member management are unchanged

**Effort:** M
**Value:** Medium

---

## Groups: Unique Names for WeftId Groups + IdP Group Labeling

**User Story:**
As an admin
I want WeftId-managed groups to have unique names and IdP groups to be clearly labeled everywhere
So that I can unambiguously identify groups and avoid confusion between locally-managed and externally-synced groups

**Context:**
Groups have a `type` field: `weftid` (manually managed) or `idp` (synced from an external identity provider). IdP groups may legitimately share names across providers. WeftId groups have no such excuse and duplicate names cause confusion.

**Acceptance Criteria:**
- [ ] Database: partial unique constraint on `(tenant_id, name)` WHERE `type = 'weftid'`
- [ ] Migration added for the constraint
- [ ] Service layer: creating or renaming a WeftId group to a name already in use returns a clear `ValidationError` ("A group with this name already exists")
- [ ] IdP groups are explicitly exempt: no uniqueness check applies when syncing IdP groups
- [ ] UI: IdP groups display a visible "IdP" badge/tag in all views where groups appear:
  - [ ] Group list (table and graph views)
  - [ ] Group detail page header
  - [ ] Membership lists (where a group is shown as a member)
  - [ ] Relationship views (parent/child group listings)
  - [ ] Application access views (groups granting SP access)
  - [ ] Any user profile group membership listings
- [ ] Badge styling makes clear the group is read-only / externally managed (e.g. tooltip "Managed by identity provider")
- [ ] API: group create/update endpoints return 400 with descriptive message on name collision for WeftId groups

**Effort:** M
**Value:** High

---

## Groups: IdP Umbrella Group Descriptive Copy

**User Story:**
As an admin
I want the auto-created IdP umbrella group to have a clear, informative description
So that I understand what the group is, how it was created, and what it represents without needing outside documentation

**Context:**

When an IdP is created, the system auto-creates an umbrella group (the "base group") named
after the IdP. Its current description is the terse string `"All users authenticating via
{idp_name}"`. Groups discovered from SAML assertions get an equally terse `"Discovered from
{idp_name}"`. Neither copy explains the relationship between them or the automated nature of
the membership.

The umbrella group description should read something like:

> This group was created automatically when setting up {idp_name}. It contains every user
> who authenticates through this identity provider. Groups reported by the IdP during
> authentication appear as children of this group.

The assertion sub-group description should read something like:

> This group is synced from {idp_name}. Membership is managed automatically whenever a user
> authenticates through the identity provider.

**Acceptance Criteria:**

- [ ] `create_idp_base_group()` generates the improved description (referencing the IdP name)
- [ ] `get_or_create_idp_group()` generates the improved description for assertion sub-groups
- [ ] The Details tab for an umbrella group shows a contextual read-only notice distinguishing
      it from a regular IdP sub-group (e.g. "This is the root group for {idp_name}. All
      authenticating users are added automatically.")
- [ ] The Details tab for an assertion sub-group shows a different read-only notice (e.g.
      "This group is synced from {idp_name}. Membership is managed during authentication.")
- [ ] The Relationships tab for the umbrella group replaces the current
      "IdP groups cannot have child groups" notice with one that accurately describes the
      umbrella's role: assertion groups from this IdP appear here as read-only children
- [ ] The Relationships tab for an assertion sub-group shows a read-only parent entry (the
      umbrella) with explanatory copy indicating the relationship is IdP-managed

**Effort:** S
**Value:** Medium

---

## Groups: SAML Assertion Groups as DAG Children of Umbrella

**User Story:**
As an admin
I want groups reported by the IdP during authentication to automatically appear as DAG
children of the IdP's umbrella group, with that relationship protected from manual removal
So that the group hierarchy accurately reflects the IdP's structure and cannot be accidentally broken

**Depends on:** IdP Umbrella Group Descriptive Copy (the Relationships tab notices established
by that item are extended here).

**Context:**

Currently, groups discovered from SAML assertions are created as standalone IdP groups
associated with the IdP via `idp_id`. They are NOT wired into the group hierarchy as children
of the umbrella group. From the Relationships tab the umbrella looks like it has no children,
and the assertion groups look like they have no parents.

The `sync_user_idp_groups()` function manages user memberships correctly, but it does not
create entries in `group_relationships` or `group_lineage`. The DAG therefore does not
reflect the IdP's group structure, and effective membership via lineage does not propagate
correctly from sub-groups through the umbrella.

Additionally, there is no protection preventing an admin from removing an IdP-managed
parent-child relationship (once it exists). The service layer must enforce that these
relationships are read-only.

**Acceptance Criteria:**

Hierarchy wiring:
- [ ] In `get_or_create_idp_group()`, after resolving or creating an assertion group, ensure
      a `group_relationships` entry and corresponding `group_lineage` entries exist with the
      umbrella group as parent and the assertion group as child. This must be transactional
      (relationships + lineage updated atomically).
- [ ] If the assertion group already exists and the relationship already exists, the call is
      idempotent (no duplicate edges, no error)
- [ ] `sync_user_idp_groups()` ensures all resolved groups (existing + newly created) have
      the parent-child wiring with the umbrella
- [ ] Event log entry (`idp_group_relationship_created`) emitted when a new umbrella→child
      relationship is established

Relationship protection:
- [ ] The service layer function for removing a group parent raises `ForbiddenError` if the
      parent is an IdP umbrella group and the child is an assertion group belonging to that
      same IdP
- [ ] The service layer function for removing a group child raises `ForbiddenError` if the
      child is an IdP assertion group and the parent is that IdP's umbrella group
- [ ] API endpoints for removing parent/child relationships return HTTP 403 with a descriptive
      message when the relationship is IdP-managed
- [ ] The Remove button for IdP-managed parent/child entries is hidden in the Relationships
      tab UI (not just disabled); the entry is shown as read-only with an "IdP-managed" label
- [ ] Both admin and super admin roles are subject to this restriction

UI updates:
- [ ] The Relationships tab for the umbrella group shows its assertion sub-groups as read-only
      children (no Add/Remove controls for IdP-managed children; manually-added WeftId
      children remain manageable)
- [ ] The Relationships tab for an assertion sub-group shows the umbrella as a read-only
      parent entry
- [ ] The "IdP groups cannot have child groups" notice is removed for umbrella groups; a
      contextual notice replaces it

Tests:
- [ ] Unit tests for `get_or_create_idp_group()` verify the relationship is created and is
      idempotent
- [ ] Unit tests for `sync_user_idp_groups()` verify relationships are established for all
      resolved groups
- [ ] Service layer tests verify `ForbiddenError` is raised when attempting to remove an
      IdP-managed relationship
- [ ] API integration tests verify HTTP 403 is returned for protected removals

**Effort:** M
**Value:** High

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
