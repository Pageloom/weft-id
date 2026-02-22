# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

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

