# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Opportunistic Certificate Cleanup on Metadata Serving

**User Story:**
As a system operator
I want expired grace-period certificates to be cleaned up immediately when the SP metadata endpoint is called
So that stale previous certificates are removed promptly without waiting for the daily background job

**Context:**

The daily background job (`rotate_certificates.py`) handles certificate cleanup after the grace period expires. However, the metadata endpoint (`/saml/idp/metadata/{sp_id}`) is a natural trigger point. If an SP is fetching metadata, and the grace period has already expired, we can clean up the previous certificate inline. This is a lightweight write (null out 4 columns) that makes the cleanup more responsive. Uses the existing `sp_signing_certificate_cleanup_completed` event type.

**Acceptance Criteria:**

- [ ] When the per-SP metadata endpoint is called, check if `rotation_grace_period_ends_at` has passed
- [ ] If expired, call `clear_previous_signing_certificate()` inline before serving metadata
- [ ] Log `sp_signing_certificate_cleanup_completed` event with `SYSTEM_ACTOR_ID`
- [ ] Metadata response is not delayed significantly (cleanup is a simple UPDATE)
- [ ] If cleanup fails, log a warning but still serve the metadata (do not break the endpoint)
- [ ] Background job still runs as a safety net (no change to existing behavior)
- [ ] Tests cover: cleanup triggered on metadata fetch, cleanup failure doesn't break metadata, no cleanup when grace period is still active

**Key files:**
- Modify: `app/services/service_providers/metadata.py` (add cleanup check before serving)

**Effort:** S
**Value:** Medium (More responsive cleanup, reduces stale data window)

---

## SP-Side Certificate Rotation & Lifecycle Management

**User Story:**
As a super admin
I want SP-side signing certificate rotation to serve both old and new certificates during the grace period, rotate automatically before expiry, and clean up expired certificates
So that IdP administrators can transition smoothly without SSO breaking

**Context:**

Mirrors Item 2 but for the SP side (per-IdP signing certificates from the Per-IdP SP Metadata item). Per-IdP SP Metadata & Trust Establishment is now complete.

**Depends on:** None (Per-IdP SP Metadata & Trust Establishment is complete)

**Acceptance Criteria:**

**Dual-certificate metadata:**
- [ ] `generate_sp_metadata_xml()` in `app/utils/saml.py` accepts optional `previous_certificate_pem` parameter
- [ ] When provided, per-IdP metadata includes two `<md:KeyDescriptor use="signing">` elements (new cert first, previous second)
- [ ] Metadata service checks `rotation_grace_period_ends_at` on `saml_idp_sp_certificates`

**Rotation guard:**
- [ ] `rotate_idp_sp_certificate()` rejects rotation when grace period is active
- [ ] Raises `ValidationError` with message "Certificate rotation already in progress"

**Auto-rotation (extend background job from IdP-Side Rotation):**
- [ ] Same daily job also queries `saml_idp_sp_certificates` across tenants
- [ ] Same logic: rotate 90 days before expiry (90-day grace period), clean up when grace period ends
- [ ] Job summary includes both IdP-side and SP-side cert counts

**Grace period behavior:**
- [ ] Manual rotation: 7-day grace period
- [ ] Auto-rotation: 90-day grace period
- [ ] When grace period ends: old cert removed from metadata AND database simultaneously

**Event logging:**
- [ ] `saml_idp_sp_certificate_auto_rotated` event
- [ ] `saml_idp_sp_certificate_cleanup_completed` event

**Tests:**
- [ ] Dual-cert SP metadata generation
- [ ] Rotation guard during active rotation
- [ ] Background job auto-rotates and cleans up SP-side certs
- [ ] Auto-rotation uses configurable lifetime setting

**Key files:**
- Modify: `app/utils/saml.py:319` (dual-cert SP metadata generation)
- Modify: `app/jobs/rotate_certificates.py` (extend from IdP-Side Rotation item)
- Modify: `app/services/saml/idp_sp_certificates.py` (rotation guard, from per-IdP SP metadata feature)

**Effort:** M
**Value:** High

---

## Per-SP NameID Configuration

**User Story:**
As a super admin
I want to configure the NameID format for each service provider
So that each SP receives user identifiers in the format it expects

**Context:**

The infrastructure for NameID configuration is partially complete. The `nameid_format` column exists on the `service_providers` table, metadata parsing extracts NameID format from SP metadata XML, and the SSO assertion builder reads the format field. However, the actual logic for persistent and transient NameID generation is missing. Currently, when an SP's NameID format is set to "persistent" (via metadata import), the system still sends the user's email address instead of a stable opaque identifier. Additionally, there is no UI or API support for changing the NameID format after SP creation (it's read-only).

**What's Already Done:**
- Database column (`nameid_format`) exists with default `emailAddress`
- Metadata parser extracts NameID format from SP metadata
- Assertion builder reads and includes the format in SAML responses
- SP detail page displays NameID format (read-only)

**What Remains:**
- Persistent NameID logic (generate and store stable opaque identifiers per user-SP pair)
- Transient NameID logic (generate per-session identifiers)
- UI/API to configure or change NameID format after SP creation

**Acceptance Criteria:**

- [ ] DB migration: create `sp_nameid_mappings` table (user_id, sp_id, nameid_value, created_at)
- [ ] Persistent NameID: generate stable opaque identifier (UUID-based) per user-SP pair on first SSO, store in `sp_nameid_mappings`, reuse on subsequent SSO
- [ ] Transient NameID: generate new opaque identifier per session (UUID, not persisted)
- [ ] Assertion builder calls appropriate NameID generation function based on SP's `nameid_format` (emailAddress uses user email, persistent uses mapping table, transient generates new UUID)
- [ ] Add `nameid_format` to `SPUpdate` schema (allow updating format via API and UI)
- [ ] SP detail page: NameID format selection dropdown (emailAddress, persistent, transient, unspecified) with save functionality
- [ ] API endpoint: `PUT /api/v1/service-providers/{sp_id}` accepts `nameid_format` in request body
- [ ] Event log entry when NameID format is changed (`sp_nameid_format_updated`)
- [ ] Tests for persistent NameID generation and reuse
- [ ] Tests for transient NameID generation (new value per session)

**Effort:** S (Infrastructure exists, only need logic and UI)
**Value:** Medium (Required for SPs that mandate non-email NameID formats)

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

## Standardize List Row Navigation and Full-Width Layout

**User Story:**
As a super admin
I want all list views to use the same navigation pattern (name column as a link) and full-width layout
So that the UI is consistent and predictable across the entire admin experience

**Context:**

The app currently uses three different patterns for navigating from a list row to a detail page:
1. Name/title column as an `<a href>` link (preferred, used by IdP list, SP list, Groups list)
2. Action column with icon links (Users list, OAuth2 Apps, B2B Clients, SAML Debug)
3. Clickable row via JavaScript with `data-href` (Event Log)

The standard should be pattern 1: make the name or primary identifier column a standard `<a href>` link. This is the most accessible, requires no JavaScript, works with browser features (open in new tab, copy link), and follows web conventions.

Additionally, list pages use inconsistent width constraints. Some use `mx-auto px-4 py-8` (full width), others use `max-w-6xl` or `max-w-4xl`. All list views should use `{% block content_wrapper %}mx-auto px-4 py-8{% endblock %}` for full-width layout since tables benefit from horizontal space.

**Audit of current state:**

| Template | Navigation Pattern | Width | Needs Fix? |
|---|---|---|---|
| IdP List (`saml_idp_list.html`) | Link on name | `mx-auto px-4 py-8` | No |
| SP List (`saml_idp_sp_list.html`) | Link on name | `mx-auto px-4 py-8` | No |
| Users List (`users_list.html`) | Action column icon | `mx-auto px-4 py-8` | Nav only |
| Groups List (`groups_list.html`) | Link on name | `max-w-6xl` (default) | Width only |
| Group Members (`groups_members.html`) | Action column (Remove) | `mx-auto px-4 py-8` | N/A (no detail page) |
| OAuth2 Apps (`integrations_apps.html`) | Action column icon | `max-w-6xl` (default) | Both |
| B2B Clients (`integrations_b2b.html`) | Action column icon | `max-w-6xl` (default) | Both |
| Event Log (`admin_events.html`) | Clickable row via JS | `w-full` (custom) | Nav only |
| SAML Debug (`saml_debug_list.html`) | Action column link | `max-w-6xl` (default) | Both |
| Background Jobs (`account_background_jobs.html`) | Links in output column | `w-full` (custom) | Width OK, nav N/A |
| Reactivation Requests (`admin_reactivation_requests.html`) | Action buttons | `max-w-4xl` (default) | Width only (no detail page) |
| Reactivation History (`admin_reactivation_history.html`) | None (read-only) | `max-w-4xl` (default) | Width only |

**Acceptance Criteria:**

Navigation pattern (make name/primary identifier a link):
- [ ] Users list: make user name column an `<a href>` to user detail page, remove action column icon
- [ ] OAuth2 Apps: make app name column an `<a href>` to app detail page, remove action column arrow
- [ ] B2B Clients: make client name column an `<a href>` to client detail page, remove action column arrow
- [ ] Event Log: make event type or timestamp an `<a href>` to event detail, remove `clickable-row` JS pattern
- [ ] SAML Debug: make timestamp or error type an `<a href>` to debug detail, remove action column "View Details" link

Full-width layout (`{% block content_wrapper %}mx-auto px-4 py-8{% endblock %}`):
- [ ] Groups list
- [ ] OAuth2 Apps
- [ ] B2B Clients
- [ ] SAML Debug
- [ ] Reactivation Requests
- [ ] Reactivation History

Post-implementation:
- [ ] Update skill references (e.g., `.claude/references/`) to document the standard list pattern
- [ ] All existing tests continue to pass
- [ ] No JavaScript required for basic list navigation

**Effort:** M
**Value:** Medium (Consistency, accessibility, maintainability)

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

