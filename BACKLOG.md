# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Tooling: Dev Environment Seed Script

**User Story:**
As a developer
I want to run a single command (`make seed-dev`) on a fresh dev environment
So that I have realistic, pre-populated data to work with immediately without manual setup

**Context:**

Currently a fresh `make up` leaves the database empty. Engineers must manually create
tenants, users, groups, SPs, and IdPs before they can meaningfully exercise the platform.
This is especially painful for features involving group hierarchies, SP access control,
and IdP federation.

The seed represents **Meridian Health** (a mid-sized healthcare organisation) as the primary
dev tenant, with believable partner SPs and IdP tenants also wired in.

**Dev Tenant: Meridian Health**

- Subdomain: `meridian-health` (i.e. `meridian-health.weftid.localhost`)
- Email domain: `@meridian-health.dev`
- ~350 users with realistic names and email addresses
- One super-admin and several admins pre-configured
- All dev users get a known fixed password (e.g. `DevSeed123!`) for immediate login

**Service Providers (5) — Meridian Health uses WeftId as their IdP for these apps:**

| Name | Subdomain | Description |
|---|---|---|
| Compass Patient Portal | `compass-portal` | Patient-facing portal |
| NorthStar HR | `northstar-hr` | HR & payroll system |
| Apex Analytics | `apex-analytics` | Clinical data analytics |
| MediFlow EHR | `mediflow` | Electronic health records |
| AuditBridge Compliance | `auditbridge` | HIPAA compliance tooling |

Each SP is registered in the Meridian Health tenant with a plausible entity ID and ACS
URL. Group-based access control is configured so different departments access different apps.

**Identity Providers (3) — Meridian Health federates with these external IdPs:**

| Name | Subdomain | Description |
|---|---|---|
| Cloudbridge IdP | `cloudbridge-idp` | Primary SSO provider |
| Vertex SSO | `vertex-sso` | Vendor partner federation |
| HealthConnect SSO | `healthconnect-sso` | Regional health network IdP |

Each IdP is registered in the Meridian Health tenant with a plausible entity ID and SSO URL.
Domain bindings are configured where appropriate.

**Group Hierarchy (~25 groups, DAG structure):**

Top-level anchor group plus eight department groups, each with 2-3 sub-department children.
Cross-cutting groups (e.g. "HIPAA Covered Entities", "Remote Workers", "Leadership")
demonstrate the DAG model (a group can have multiple parents). Example structure:

```
All Staff (350)
├── Clinical Operations (140)
│   ├── Emergency Department (35)
│   ├── Inpatient Care (40)
│   ├── Outpatient Services (35)
│   └── Intensive Care Unit (30)
├── Research & Innovation (80)
│   ├── Clinical Trials (40)
│   ├── Biostatistics & Analytics (20)
│   └── Medical Informatics (20)
├── Information Technology (55)
│   ├── Infrastructure & Cloud (20)
│   ├── Application Support (20)
│   └── Cybersecurity (15)
├── Compliance & Risk (40)
│   ├── HIPAA & Privacy (20)
│   └── Risk Management (20)
├── Finance & Accounting (35)
│   ├── General Accounting (18)
│   └── Budget & Planning (17)
├── Human Resources (30)
│   ├── Talent Acquisition (15)
│   └── Benefits & Compensation (15)
├── Executive Leadership (10)
│   ├── C-Suite (6)
│   └── Board of Directors (4)
└── Patient Services (60)
    ├── Patient Experience (30)
    └── Medical Records (30)

Cross-cutting (DAG edges, not tree):
HIPAA Covered Entities ← [Clinical Operations, Research & Innovation, Patient Services]
Leadership ← [Executive Leadership, (department head users from each dept)]
Remote Workers ← (cross-department selection of users)
```

**Acceptance Criteria:**

Script and invocation:
- [ ] Script lives at `scripts/seed_dev.py`
- [ ] `make seed-dev` target added to Makefile; runs the script inside the `dev_app`
      container so it has access to app environment variables and the service layer
- [ ] Script is idempotent: re-running on an existing database skips already-created
      entities (uses existence checks, not blind inserts)
- [ ] Script prints clear progress output as it runs (tenant, users, groups, SPs, IdPs)
- [ ] Script is gated: exits with a clear error if `IS_DEV` is not `true`, preventing
      accidental execution against non-dev databases

Tenants and users:
- [ ] Dev tenant (Meridian Health) created with correct subdomain and display name
- [ ] ~350 users created with realistic first/last names and `@meridian-health.dev` emails
- [ ] At least one `super_admin` user with a known email (e.g. `admin@meridian-health.dev`)
- [ ] Several `admin` users (one per major department)
- [ ] Remaining users are `member` role
- [ ] All users have a known fixed password (documented in the script header and README)
- [ ] SP and IdP tenants each have 2-3 admin users with domain-appropriate email addresses

Service providers:
- [ ] 5 SPs registered in the Meridian Health tenant (Compass, NorthStar, Apex, MediFlow,
      AuditBridge)
- [ ] Each SP has a plausible entity ID and ACS URL (using `*.weftid.localhost` dev URLs)
- [ ] Group-based SP access control configured: each SP is accessible to at least one
      relevant department group

Identity providers:
- [ ] 3 IdPs registered in the Meridian Health tenant (Cloudbridge, Vertex, HealthConnect)
- [ ] Each IdP has a plausible entity ID and SSO URL
- [ ] At least one IdP has a domain binding configured

Groups:
- [ ] ~25 groups created matching the hierarchy above
- [ ] All direct parent-child relationships in the tree created
- [ ] Cross-cutting groups (HIPAA Covered Entities, Leadership, Remote Workers) added with
      multiple parents, demonstrating the DAG model
- [ ] Group lineage closure table is correct and consistent after seeding
- [ ] Users distributed across leaf groups; memberships also roll up through the hierarchy

Documentation:
- [ ] `README.md` or `CONTRIBUTING.md` updated with a "Dev Seed Data" section: how to
      run it, what it creates, and the default credentials

**Effort:** M
**Value:** High

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
- [ ] New criterion: As super admin only: ability to impersonate a user ONLY for 
      debugging purposes - i.e not actually signing in to the SP.

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

## Group Detail: Tabbed Layout with Relationship Diagram

**User Story:**
As an admin
I want the group detail page reorganized into tabs with a visual relationship diagram
So that I can navigate group content more efficiently and understand a group's position in the hierarchy at a glance

**Context:**

The current group detail page is a long scroll of stacked sections: name/description form, members, assigned apps, parent groups, child groups. The service provider and IdP detail pages use tabbed layouts that work well for organizing this kind of multi-faceted content. The same pattern should be applied here.

The Relationships tab replaces the current flat parent/child lists with a local neighborhood diagram: the current group in the center, with arrows to each direct parent and child. Each adjacent node shows a hint of its own relationship count. Clicking a node navigates to that group's detail page.

**Acceptance Criteria:**

Tab structure:
- [ ] Details tab: name, description, type badge, IdP source (if applicable), created/updated timestamps, delete action
- [ ] Members tab: direct member count, effective (inherited) member count, link to member management page, IdP-managed notice where applicable
- [ ] Applications tab: list of SPs this group grants access to (current Assigned Applications section)
- [ ] Relationships tab: local neighborhood diagram (see below)
- [ ] Active tab preserved in URL hash or query param for direct linking and browser back/forward

Relationships tab:
- [ ] Current group rendered as a center node
- [ ] Direct parent groups rendered as connected nodes with directed arrows (child to parent)
- [ ] Direct child groups rendered as connected nodes with directed arrows (child to parent)
- [ ] Each adjacent node shows a hint: e.g. "2 parents" or "3 children"
- [ ] Clicking an adjacent node navigates to that group's detail page (same tab)
- [ ] Add/remove parent and add/remove child controls remain accessible within this tab
- [ ] Read-only display for IdP groups (no add/remove controls)

**Effort:** M
**Value:** High (Reduces scroll fatigue; makes group relationships immediately navigable)

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

## Branding: Group Avatar Customization (Acronyms, Per-Group Logos, Tabbed Branding Page)

**User Story:**
As an admin
I want to choose whether groups display as mandalas or acronyms, and optionally upload a
custom logo for individual groups
So that I can match our organization's visual identity and make groups immediately recognizable

**Context:**

Groups currently display a deterministic mandala generated from the group UUID. While
visually distinctive, mandalas are abstract and provide no text cue. An acronym mode would
derive 1-3 letters from the group name and render them on a color background (color still
derived from UUID for consistency). For example: "Engineering" → "E", "IT Department" → "IT",
"Human Resources" → "HR".

The existing tenant branding page already supports logo upload (PNG/SVG, square, max 256KB,
with ETag caching). The same upload flow and validation can be reused for per-group logos.

The branding page should follow the established tabbed layout pattern (same as SP, IdP, and
group detail pages) with two tabs: "Global" (existing settings, unchanged) and "Groups"
(the new avatar settings).

**Acceptance Criteria:**

Branding page restructure:
- [ ] `GET /admin/settings/branding` redirects to `/admin/settings/branding/global`
- [ ] New base template `settings_branding_base.html` with tab nav (Global, Groups)
- [ ] "Global" tab (`/admin/settings/branding/global`) contains exactly the current branding
      page content, unchanged
- [ ] "Groups" tab (`/admin/settings/branding/groups`) is a new page (see below)
- [ ] All existing branding routes and functionality continue to work

Groups tab - avatar style setting:
- [ ] A tenant-level setting "Group avatar style" with two options: "Mandala" (default) and
      "Acronym"
- [ ] The setting is persisted in `tenant_branding` (new column or via existing settings
      JSON mechanism, with migration)
- [ ] When "Acronym" is selected, all group avatars across the UI render the acronym instead
      of the mandala (group list, group detail, neighborhood diagram, full graph, etc.)
- [ ] Acronym derivation: first letters of each word in the group name, up to 3 characters,
      uppercased (e.g. "Engineering" → "E", "IT Department" → "IT", "Human Resources" → "HR")
- [ ] Acronym style: letters on a colored background (color from group UUID, same palette as
      mandala), in the same circular or rounded-square container shape used everywhere mandalas
      appear today

Per-group logo upload:
- [ ] The Groups branding tab includes a list of groups (name + current avatar thumbnail) with
      an "Upload logo" action per group
- [ ] Uploaded group logos follow the same validation as tenant logos: PNG or SVG, square,
      min 48x48px, max 256KB, SVG safety checks (no XXE, no scripts, no event handlers)
- [ ] An uploaded group logo overrides both mandala and acronym for that specific group,
      regardless of the tenant avatar style setting
- [ ] The "Upload logo" flow is also accessible from the group detail page (Details tab)
- [ ] A "Remove logo" action reverts the group to the mandala or acronym fallback
- [ ] Group logos stored in a new `group_logos` table
      (`group_id`, `logo_data`, `logo_mime`, `updated_at`), with migration
- [ ] Group logos served from a new unauthenticated route
      `GET /branding/group-logo/{group_id}` with ETag caching and 1-hour `Cache-Control`
      headers (same pattern as `/branding/logo/{slot}`)
- [ ] API endpoints: `POST /api/v1/groups/{group_id}/logo` (upload),
      `DELETE /api/v1/groups/{group_id}/logo` (remove), `GET /api/v1/groups/{group_id}`
      includes `has_logo: bool`

Avatar resolution order (highest priority first):
1. Custom uploaded logo for the group
2. Tenant avatar style setting (mandala or acronym)

Event logging:
- [ ] `group_logo_uploaded` event logged on upload (actor, group_id, mime_type)
- [ ] `group_logo_removed` event logged on removal
- [ ] `group_avatar_style_updated` event logged when the tenant-level style setting changes

**Effort:** L
**Value:** Medium

---

