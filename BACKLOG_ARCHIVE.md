# Product Backlog Archive

This document contains completed backlog items for historical reference.

---

## Branding: Group Avatar Customization (Acronyms, Per-Group Logos, Tabbed Branding Page)

**Status:** Complete

**Summary:** Added a tenant-level group avatar style setting (mandala/acronym) stored in `tenant_branding.group_avatar_style`, per-group custom logo upload via a new `group_logos` table, and a restructured branding settings page with Global and Groups tabs. Avatar resolution order: custom group logo > tenant style setting. All group avatar surfaces updated (group list, group detail neighborhood diagram, full graph). New API endpoints: `POST/DELETE /api/v1/groups/{group_id}/logo`, `GET /branding/group-logo/{group_id}`. Migration 0004 adds the enum, column, and table with RLS. Event types `group_logo_uploaded`, `group_logo_removed`, `group_avatar_style_updated` logged on mutations.

**Acceptance Criteria:**

Branding page restructure:
- [x] `GET /admin/settings/branding` redirects to `/admin/settings/branding/global`
- [x] New base template `settings_branding_base.html` with tab nav (Global, Groups)
- [x] "Global" tab (`/admin/settings/branding/global`) contains exactly the current branding page content, unchanged
- [x] "Groups" tab (`/admin/settings/branding/groups`) is a new page (see below)
- [x] All existing branding routes and functionality continue to work

Groups tab - avatar style setting:
- [x] A tenant-level setting "Group avatar style" with two options: "Mandala" (default) and "Acronym"
- [x] The setting is persisted in `tenant_branding` (new `group_avatar_style` column, with migration)
- [x] When "Acronym" is selected, all group avatars across the UI render the acronym instead of the mandala (group list, group detail, neighborhood diagram, full graph, etc.)
- [x] Acronym derivation: first letters of each word in the group name, up to 3 characters, uppercased
- [x] Acronym style: letters on a colored background (color from group UUID, same palette as mandala), circular container

Per-group logo upload:
- [x] The Groups branding tab includes a list of groups (name + current avatar thumbnail) with an "Upload logo" action per group
- [x] Uploaded group logos follow the same validation as tenant logos: PNG or SVG, square, min 48x48px, max 256KB, SVG safety checks
- [x] An uploaded group logo overrides both mandala and acronym for that specific group
- [x] The "Upload logo" flow is also accessible from the group detail page (Details tab)
- [x] A "Remove logo" action reverts the group to the mandala or acronym fallback
- [x] Group logos stored in a new `group_logos` table, with migration
- [x] Group logos served from `GET /branding/group-logo/{group_id}` with ETag caching and 1-hour Cache-Control
- [x] API endpoints: `POST /api/v1/groups/{group_id}/logo`, `DELETE /api/v1/groups/{group_id}/logo`, `GET /api/v1/groups/{group_id}` includes `has_logo: bool`

Avatar resolution order (highest priority first):
1. Custom uploaded logo for the group
2. Tenant avatar style setting (mandala or acronym)

Event logging:
- [x] `group_logo_uploaded` event logged on upload
- [x] `group_logo_removed` event logged on removal
- [x] `group_avatar_style_updated` event logged when the tenant-level style setting changes

---

## Group Detail: Tabbed Layout with Relationship Diagram

**Status:** Complete

**Summary:** Implemented as a 5-tab layout (Details, Members, Applications, Relationships, Delete) with a shared base template (`groups_detail_base.html`) and per-tab templates. The Relationships tab uses Cytoscape.js for an interactive neighborhood graph. Tabs are implemented as separate routes under `/admin/groups/{group_id}/<tab>` with `_load_group_common()` for shared data. Active tab state is tracked via route-set template variables. Inherited application and membership counts are surfaced in the Members and Applications tabs.

**Acceptance Criteria:**

Tab structure:
- [x] Details tab: name, description, type badge, IdP source (if applicable), delete action
- [x] Members tab: direct member count, effective (inherited) member count, member management
- [x] Applications tab: list of SPs this group grants access to
- [x] Relationships tab: local neighborhood diagram
- [x] Active tab reflected in URL for direct linking

Relationships tab:
- [x] Current group rendered as a center node
- [x] Direct parent and child groups rendered as connected nodes with directed arrows
- [x] Clicking an adjacent node navigates to that group's detail page
- [x] Add/remove parent and add/remove child controls accessible within this tab
- [x] Read-only display for IdP groups (no add/remove controls)

---

## Tooling: Dev Environment Seed Script

**Status:** Complete

**Summary:** Implemented an idempotent seed script (`app/dev/seed_dev.py`) that provisions the
Meridian Health dev tenant with 350 users, 32 groups in a DAG hierarchy, 5 service providers,
and 3 identity providers. Run via `make seed-dev`. The script is gated behind `IS_DEV=true` and
prints step-by-step progress. All users share the fixed password `DevSeed123!`. The `make seed-dev`
Makefile target and a "Dev Seed Data" README section were added alongside the script.

**Path deviation:** The script lives at `app/dev/seed_dev.py` rather than `scripts/seed_dev.py`
as originally specified. This co-locates it with other dev utilities and gives it direct access
to the app's service layer.

**Known gap:** The criterion "SP and IdP tenants each have 2-3 admin users with domain-appropriate
email addresses" (creating separate WeftId tenant accounts per SP/IdP vendor) was not implemented.
Cross-tenant SSO testing is handled by the separate `sso_testbed.py` script.

**Acceptance Criteria:**

- [x] Script is idempotent
- [x] `make seed-dev` target added to Makefile
- [x] IS_DEV guard: exits with error if not dev environment
- [x] Clear progress output
- [x] Meridian Health tenant created with correct subdomain
- [x] ~350 users with realistic names and `@meridian-health.dev` emails (9 admins + 340 bulk)
- [x] super_admin user (`admin@meridian-health.dev`) and 8 department admin users
- [x] Known fixed password `DevSeed123!` for all users
- [x] 5 SPs registered (Compass, NorthStar, Apex, MediFlow, AuditBridge) with entity IDs and ACS URLs
- [x] Group-based SP access control configured
- [x] 3 IdPs registered (Cloudbridge, Vertex, HealthConnect) with entity IDs and SSO URLs
- [x] Domain binding on Cloudbridge IdP
- [x] 32 groups created (exceeds ~25 spec) in DAG hierarchy
- [x] Cross-cutting groups with multiple parents (HIPAA Covered Entities, Leadership, Remote Workers)
- [x] Group lineage closure table maintained via `database.groups.add_group_relationship`
- [x] Users distributed across leaf groups
- [x] README updated with "Dev Seed Data" section
- [ ] SP and IdP tenants have admin users (not implemented — see known gap above)

---

## Groups Overview: Redesigned List and Network Graph View

**Status:** Complete

**Summary:** Redesigned the groups overview page with a new list view (Name, Type, Parents, Children, Members columns; Description and Actions columns removed) and an interactive graph view powered by Cytoscape.js. Graph supports zoom, pan, node click to navigate, and DB-persisted per-user layouts with snap-to-grid. The implementation also added relationship editing directly from the graph canvas (add/remove parent relationships) and fullscreen mode, beyond the original spec.

**Acceptance Criteria:**

- [x] Columns: Name, Type, Parents (count), Children (count), Members (direct + inherited total)
- [x] Remove the Description column and the Actions column
- [x] Existing search and pagination remain
- [x] Toggle button to switch between list view and graph view (persisted in localStorage)
- [x] One node per group; directed edges from child to parent
- [x] Nodes labeled with group name and member count
- [x] Supports zoom in/out
- [x] Supports pan when content exceeds the visible area
- [x] Clicking a node navigates to that group's detail page
- [x] Graph view is read-only (no editing from the graph) — exceeded: relationship editing added

---

## Standardize List Row Navigation and Full-Width Layout

**Status:** Complete

**Summary:** All list views use the name/primary identifier column as an `<a href>` link for navigation, and all use `{% block content_wrapper %}mx-auto px-4 py-8{% endblock %}` for full-width layout. Navigation: users_list, integrations_apps, integrations_b2b, admin_events, and saml_debug_list all use direct links. Width: groups_list, integrations_apps, integrations_b2b, saml_debug_list, admin_reactivation_requests, and admin_reactivation_history all use full-width layout.

**Acceptance Criteria:**

- [x] Users list: user name column is `<a href>` to user detail page
- [x] OAuth2 Apps: app name column is `<a href>` to app detail page
- [x] B2B Clients: client name column is `<a href>` to client detail page
- [x] Event Log: event type is `<a href>` to event detail, no `clickable-row` JS pattern
- [x] SAML Debug: error type is `<a href>` to debug detail
- [x] Groups list: full-width layout
- [x] OAuth2 Apps: full-width layout
- [x] B2B Clients: full-width layout
- [x] SAML Debug: full-width layout
- [x] Reactivation Requests: full-width layout
- [x] Reactivation History: full-width layout
- [x] All existing tests pass
- [x] No JavaScript required for basic list navigation

---

## Reorganize tests/ into packages mirroring app/ structure

**Status:** Complete

**Summary:** Test files are organized into packages mirroring the app/ structure: `tests/api/`, `tests/routers/`, `tests/services/`, `tests/database/`, `tests/utils/`, `tests/jobs/`, `tests/middleware/`, and `tests/helpers/`. Cross-cutting tests (`test_pages.py`, `test_auth_coverage.py`, etc.) remain at the root.

**Acceptance Criteria:**

- [x] `./test` passes with identical results
- [x] All test files are in a package matching their app layer
- [x] No flat test files remain at `tests/` root except cross-cutting concerns

---

## Per-SP NameID Configuration

**Status:** Complete

**Summary:** Implemented persistent and transient NameID generation for SAML assertions. Added the `sp_nameid_mappings` table to store stable per-user-per-SP identifiers for persistent NameID format. Added `nameid_format` to `SPUpdate` schema, a UI dropdown on the SP detail page, event logging on format change (`sp_nameid_format_updated`), and comprehensive tests for both persistent and transient generation paths.

**Acceptance Criteria:**

- [x] DB migration: create `sp_nameid_mappings` table (user_id, sp_id, nameid_value, created_at)
- [x] Persistent NameID: generate stable opaque identifier (UUID-based) per user-SP pair on first SSO, store in `sp_nameid_mappings`, reuse on subsequent SSO
- [x] Transient NameID: generate new opaque identifier per session (UUID, not persisted)
- [x] Assertion builder calls appropriate NameID generation function based on SP's `nameid_format` (emailAddress uses user email, persistent uses mapping table, transient generates new UUID)
- [x] Add `nameid_format` to `SPUpdate` schema (allow updating format via API and UI)
- [x] SP detail page: NameID format selection dropdown (emailAddress, persistent, transient, unspecified) with save functionality
- [x] API endpoint: `PUT /api/v1/service-providers/{sp_id}` accepts `nameid_format` in request body
- [x] Event log entry when NameID format is changed (`sp_nameid_format_updated`)
- [x] Tests for persistent NameID generation and reuse
- [x] Tests for transient NameID generation (new value per session)

---

## SP-Side Certificate Rotation & Lifecycle Management

**Status:** Complete

**Summary:** Implemented as part of the IdP-Side Rotation work. All acceptance criteria were already met when this item was reviewed. `generate_sp_metadata_xml()` accepts an optional `previous_certificate_pem` parameter and emits dual `<md:KeyDescriptor use="signing">` elements. The metadata service checks `rotation_grace_period_ends_at` and passes the previous cert during the grace period. `rotate_idp_sp_certificate()` rejects rotation when a grace period is active. The daily background job in `app/jobs/rotate_certificates.py` handles both SP signing certs and per-IdP SP certs, using the tenant-configured rotation window and lifetime. Event types `saml_idp_sp_certificate_auto_rotated` and `saml_idp_sp_certificate_cleanup_completed` are emitted. All tests were present and passing.

**Acceptance Criteria:**

**Dual-certificate metadata:**
- [x] `generate_sp_metadata_xml()` in `app/utils/saml.py` accepts optional `previous_certificate_pem` parameter
- [x] When provided, per-IdP metadata includes two `<md:KeyDescriptor use="signing">` elements (new cert first, previous second)
- [x] Metadata service checks `rotation_grace_period_ends_at` on `saml_idp_sp_certificates`

**Rotation guard:**
- [x] `rotate_idp_sp_certificate()` rejects rotation when grace period is active
- [x] Raises `ValidationError` with message "Certificate rotation already in progress"

**Auto-rotation (extend background job from IdP-Side Rotation):**
- [x] Same daily job also queries `saml_idp_sp_certificates` across tenants
- [x] Same logic: rotate 90 days before expiry (90-day grace period), clean up when grace period ends
- [x] Job summary includes both IdP-side and SP-side cert counts

**Grace period behavior:**
- [x] Manual rotation: 7-day grace period
- [x] Auto-rotation: 90-day grace period
- [x] When grace period ends: old cert removed from metadata AND database simultaneously

**Event logging:**
- [x] `saml_idp_sp_certificate_auto_rotated` event
- [x] `saml_idp_sp_certificate_cleanup_completed` event

**Tests:**
- [x] Dual-cert SP metadata generation
- [x] Rotation guard during active rotation
- [x] Background job auto-rotates and cleans up SP-side certs
- [x] Auto-rotation uses configurable lifetime setting

---

## Opportunistic Certificate Cleanup on Metadata Serving

**Status:** Declined (not worth the complexity; background job is sufficient)

---

## Audit and Harden SAML SLO (Single Logout) End-to-End

**Status:** Complete

**Summary:** Audited the full SLO implementation across all layers (database, schemas, services, routers, templates, API). All configuration paths were already complete: SP metadata import extracts SLO URLs, IdP metadata advertises SLO endpoints, SP detail page shows/edits SLO URL, API create/update accepts SLO URL, and manual registration supports SLO entry. The E2E testbed was missing SLO URL configuration, so it was updated. Added E2E tests for SP-initiated and IdP-initiated SLO flows. Filled unit test coverage gaps in `app/services/saml/logout.py` (86% to 100%) covering certificate fallback paths and exception handlers.

**Acceptance Criteria:**

Configuration audit:
- [x] SP metadata import extracts SLO endpoint URL (verified: `parse_sp_metadata_xml()` extracts from both POST and Redirect bindings)
- [x] IdP metadata includes SingleLogoutService endpoint (verified: `generate_idp_metadata_xml()` adds both bindings)
- [x] SP detail page shows SLO URL (verified: `saml_idp_sp_tab_details.html`)
- [x] SP detail page allows editing SLO URL (verified: manual trust entry form)
- [x] API `POST /api/v1/service-providers` accepts SLO URL (verified: SPCreate schema includes slo_url)
- [x] API `PATCH /api/v1/service-providers/{sp_id}` accepts SLO URL (verified: SPUpdate schema includes slo_url)
- [x] Manual SP registration supports SLO URL entry (verified: trust establishment form)

E2E tests:
- [x] SP-initiated SLO: SSO to SP, logout at SP, redirect through IdP SLO, return to SP /login?slo=complete, IdP session cleared
- [x] IdP-initiated SLO: SSO to SP, logout at IdP, propagation to SPs (server-to-server), IdP session cleared
- [x] Session index correlation verified at unit test level (existing coverage in `test_utils_saml_slo.py` and `test_services_service_providers_slo.py`)

Unit tests:
- [x] Certificate fallback: per-IdP cert missing, falls back to tenant-level cert
- [x] No certificate at all: returns None gracefully
- [x] Exception handling: `initiate_sp_logout()` and `process_idp_logout_request()` catch-all handlers

Testbed fix:
- [x] `sso_testbed.py` now configures SLO URLs on SP and IdP records

---

## Configurable Certificate Rotation Window in Security Settings

**Status:** Complete

**User Story:**
As a super admin
I want to configure the certificate rotation window (how far before expiry auto-rotation starts)
So that I can control how long downstream SPs have to update their trust configuration

**Acceptance Criteria:**

- [x] New DB column `certificate_rotation_window_days` in `tenant_security_settings` (default 90)
- [x] Migration adds the column with CHECK constraint for allowed values
- [x] Admin > Settings > Security page shows "Certificate rotation window" setting next to certificate validity
- [x] Options: 90 (default), 60, 30, and 14 days
- [x] Information text explains the setting: during this window, the upcoming certificate appears in SP metadata so downstream SPs can update their trust
- [x] `get_certificate_rotation_window()` function in database/security and services/settings
- [x] Background job uses the tenant's configured window instead of hardcoded 90 days
- [x] Cross-tenant query in `get_certificates_needing_rotation_or_cleanup()` joins with security settings to use per-tenant window
- [x] Event log entry when setting is changed (`tenant_certificate_rotation_window_updated`)
- [x] API endpoint for reading/updating the setting (via existing security settings endpoint)
- [x] Tests cover: default value, custom values, background job respects setting

---

## Baseline Schema & Forward-Only Migration System

**Status:** Complete

**Summary:** Replaced 46 sequential SQL migration files in `db-init/` with a single consolidated `schema.sql` baseline and a lightweight Python migration runner (`migrate.py`). The runner detects fresh, pre-existing, and already-migrated databases automatically. In dev, migrations run on `make up` via a `migrate` one-shot service. In production, migrations run on demand via `make migrate-onprem`. A `schema_migration_log` table tracks all migration attempts with success/failure status, timestamps, and error details.

**Acceptance Criteria:**

- [x] `db-init/schema.sql` contains the complete current schema (roles, tables, indexes, RLS, grants)
- [x] Old 46 migration files deleted (preserved in git history)
- [x] `db-init/migrate.py` detects fresh vs existing database
- [x] Fresh DB: applies `schema.sql` baseline, records `baseline` as successful
- [x] Existing DB: finds pending `.sql` files in `db-init/migrations/`, applies in order
- [x] Each migration runs in its own transaction with success/failure logging
- [x] Skips already-applied migrations (idempotent), allows retry of failed ones
- [x] `migrate` one-shot service in `docker-compose.yml` (dev auto-migration)
- [x] `migrate` service with `profiles: ["migrate"]` in `docker-compose.onprem.yml`
- [x] `make migrate` and `make migrate-onprem` targets added
- [x] `make db-init` wipes volume and reinitializes
- [x] CLAUDE.md and THOUGHT_ERRORS.md updated with new workflow
- [x] All existing tests pass

---

## Fix and Redesign IdP Attribute Mapping

**Status:** Complete

**Summary:** Redesigned the IdP attributes tab from two disconnected sections (editable form + read-only advertised attributes table) into a single editable table matching the SP attributes tab pattern. Fixed a Jinja2 scoping bug where `{% set %}` inside `{% for %}` didn't escape loop scope, causing "Mapped to" to always show "unmapped". Uses `namespace()` for cross-loop variable assignment, adds a conditional "Advertised by IdP" column with green Matched / amber Unmatched badges, datalist suggestions from advertised attributes, and inline reset-to-defaults.

**Acceptance Criteria:**

- [x] Single card, single table layout (replaces two disconnected sections)
- [x] Jinja2 namespace() fix for cross-loop variable assignment
- [x] "Advertised by IdP" column (conditional, only when metadata has attributes)
- [x] Green "Matched" badge when configured value matches an advertised attribute
- [x] Amber "Unmatched" badge when configured value doesn't match any advertised attribute
- [x] Datalist dropdown suggestions from advertised attributes
- [x] Reset-to-defaults link using data-default attributes
- [x] Load presets link (non-generic providers only)
- [x] Amber no-metadata notice inside the card
- [x] Form field names unchanged (POST handler compatibility)
- [x] Tests updated for new HTML structure

---

## Configurable Certificate Lifetime Setting

**Status:** Complete

**Summary:** Added tenant-level `max_certificate_lifetime_years` setting so enterprise environments can configure shorter certificate lifetimes (1, 2, 3, 5, or 10 years). All four certificate generation call sites now read the tenant setting instead of using the hardcoded 10-year default. Includes migration, database/service/schema/router layers, UI dropdown on Security settings page, dedicated event logging, and comprehensive tests across all layers.

**Acceptance Criteria:**

- [x] Add `max_certificate_lifetime_years` column to `tenant_security_settings` (INTEGER, NOT NULL, DEFAULT 10)
- [x] Add CHECK constraint: value must be in (1, 2, 3, 5, 10)
- [x] All certificate generation call sites fetch setting and pass to `generate_sp_certificate()`
- [x] If no tenant settings row exists, default to 10 years
- [x] Setting does NOT affect existing certificates (only new generation)
- [x] New "Certificate Lifetime" section on Admin > Settings > Security page
- [x] Select dropdown: 1, 2, 3, 5, 10 years with help text
- [x] GET/PATCH `/api/v1/settings/tenant-security` includes `max_certificate_lifetime_years`
- [x] `tenant_certificate_lifetime_updated` event with old/new metadata
- [x] Schema validates allowed values (rejects 4, 0, 11, etc.)
- [x] Certificate generation uses setting value (not hardcoded 10)
- [x] Tests: DB, service, API, router, and call site wiring

---

## Multiple IdP Certificates

**Status:** Complete

**Resolution:** Added multi-certificate support for IdP signing certificates, enabling seamless IdP-side certificate rotation without SSO downtime. Certificates are managed entirely through metadata sync (the IdP's metadata is the single source of truth). Uses python3-saml's native `x509certMulti` for validation against all certificates simultaneously.

The implementation includes: `idp_certificates` table with RLS, migration to seed existing certificates from `saml_identity_providers`, SHA-256 fingerprint-based deduplication, metadata import/refresh syncing certificates automatically, certificates tab UI with full fingerprint display, expiry coloring, relative timestamps, "Newest" badge, and expandable PEM view with explanation.

Manual add/remove/activate/deactivate were intentionally excluded. Certificate lifecycle is entirely driven by metadata.

**Acceptance Criteria:**

- [x] New table: `idp_certificates` (id UUID, idp_id UUID, tenant_id UUID, certificate_pem TEXT, fingerprint TEXT, expires_at TIMESTAMPTZ nullable, created_at TIMESTAMPTZ)
- [x] Migration to seed existing `certificate_pem` data from `saml_identity_providers` into `idp_certificates`
- [x] RLS policy on `idp_certificates` matching existing tenant isolation pattern
- [x] SAML validation uses all certificates via `x509certMulti` (native python3-saml support)
- [x] Metadata import extracts and stores all `<KeyDescriptor use="signing">` certificates
- [x] Metadata refresh syncs certificates (adds new, removes stale)
- [x] Certificates tab: list with SHA-256 fingerprint, expiry (green/red coloring), relative timestamps, "Newest" badge
- [x] Expandable PEM view with acronym explanation
- [x] SP certificate section unchanged
- [x] All 3024 tests pass

---

## Public Trust Page for IdP Configuration

**Status:** Complete

**Resolution:** Added a public page at `/pub/idp/{idp_id}` that external IdP administrators can use to configure their side of the SAML federation. The page shows SP metadata URL (with fold-out XML view and copy button), SP Entity ID, ACS URL, and the expected SAML attribute mappings with requirement indicators (required, optional, JIT-conditional). The "Share with your IdP" section on the admin IdP detail page was replaced with a full URL link to this public page, moved to the top of the tab.

**Acceptance Criteria:**

- [x] New public route: `GET /pub/idp/{idp_id}` (no authentication required)
- [x] Page is tenant-scoped (via `get_tenant_id_from_request`)
- [x] Returns 404 if IdP does not exist or is not enabled
- [x] Page has three sections: metadata URL (recommended), manual entry (Entity ID + ACS URL), expected attributes
- [x] Metadata XML fold-out with copy button
- [x] Attribute table shows required/optional status, with JIT provisioning context
- [x] Clean, standalone page with tenant branding
- [x] "Share with your IdP" section in IdP details tab shows full URL with copy button, moved to top of page
- [x] Tests: 13 new tests covering service and router layers
- [x] All existing tests pass (3005 total)

---

## IdP Detail Page UX Overhaul

**Status:** Complete

**Resolution:** Restructured the IdP detail page from a single long form into a tabbed layout (Details, Certificates, Attributes, Metadata, Delete) matching the SP detail page pattern. Details tab has read-only config fields, inline name editing, Settings form (Enabled, Default, MFA, JIT), connection test, SP metadata sharing, and domain bindings. Metadata tab has refresh-from-URL, re-import from XML, sync status display, and stored XML viewer. Delete tab is gated behind disabled-IdP check. Remaining tab-specific improvements (Certificates, Attributes) were broken out into dedicated backlog items.

**Acceptance Criteria:**

- [x] Tabbed layout with Details, Certificates, Attributes, Metadata, Delete tabs
- [x] Details tab: read-only fields (provider type, entity ID, SSO/SLO URL, created date)
- [x] Details tab: inline name editing via modal
- [x] Details tab: Settings form with Enabled, Default IdP, MFA, JIT checkboxes
- [x] Details tab: connection test button
- [x] Metadata tab: refresh from URL with last-synced timestamp and error display
- [x] Metadata tab: re-import from pasted XML with confirmation
- [x] Metadata tab: stored metadata XML viewer
- [x] Delete tab: delete button disabled while IdP is enabled
- [x] Delete tab: clear messaging pointing to Details tab for disabling
- [x] Service layer enforces delete-requires-disabled constraint
- [x] All existing IdP functionality preserved
- [x] API endpoints unchanged
- [x] All existing tests pass, new tests for settings and error paths

---

## IdP List View UX Overhaul

**Status:** Complete

**Resolution:** Streamlined the IdP list view by removing redundant UI elements and improving the presentation. Removed the SP metadata URL information box (now only on IdP detail page), removed the actions column (all actions available on detail page), made the list full-width for better scanning, converted metadata sync timestamps to relative time with hover tooltip for absolute time, and made each row clickable to navigate to the detail page.

**User Story:**
As a super admin
I want a clean, scannable identity providers list
So that I can quickly see the status of all configured IdPs without visual clutter

**Acceptance Criteria:**

- [x] Remove the SP metadata URL information box from the list page (this information lives on each IdP's detail page under "Share with your IdP")
- [x] Make the list view full-width (remove max-width constraint, use the full content area)
- [x] Show metadata sync time as relative time (e.g., "synced 2 hours ago", "synced 3 days ago") with the absolute timestamp available on hover/tooltip
- [x] Remove the "Actions" column entirely (Edit, Toggle, Set Default, Delete are all available on the detail page)
- [x] Each row links to the detail page (click anywhere on the row, or click the name)
- [x] All existing tests continue to pass

**Effort:** S
**Value:** Medium (Cleaner admin experience, removes redundant UI)

---

## Default Attribute Names

**Status:** Complete

**Resolution:** Changed default SAML attribute names from OID-based URIs to friendly format (`email`, `firstName`, `lastName`, `groups`). This provides a better out-of-box experience for new SP registrations. The `SAML_ATTRIBUTE_URIS` constant now uses friendly names instead of OID URIs, affecting IdP metadata, SP metadata, and SAML assertions. The lookup table was extended to recognize both old OID URIs and new friendly names, maintaining backward compatibility with SPs that use OID-based metadata.

**Acceptance Criteria:**

- [x] Change `SAML_ATTRIBUTE_URIS` in `saml_assertion.py` from OID-based URIs to friendly names: `email`, `firstName`, `lastName`, `groups`
- [x] Update IdP metadata attribute declarations in `saml_idp.py` to match
- [x] Existing per-SP attribute overrides continue to work (only the defaults change)

**Effort:** XS
**Value:** Medium

---

## SP Metadata Lifecycle Management

**Status:** Complete

**Resolution:** Fully implemented metadata lifecycle management with URL persistence, refresh workflows, and change previews. The `metadata_url` column was added to service providers (migration 00039). On SP creation via metadata URL, the source URL is persisted. The SP detail page includes a collapsible read-only viewer for stored metadata XML. SPs with a stored metadata URL have a "Refresh from URL" action that re-fetches metadata and shows a diff preview (ACS URL, SLO URL, NameID format, certificate, requested attributes, attribute mapping) before applying changes. SPs with stored XML but no URL have a "Re-import metadata" action for pasting new XML with preview. Four API endpoints handle preview and apply operations for both refresh and re-import workflows. Event logging tracks `sp_metadata_refreshed` and `sp_metadata_reimported` events.

**Acceptance Criteria:**

- [x] DB migration: add `metadata_url` column to service providers table (00039_sp_metadata_url.sql)
- [x] On SP creation via metadata URL: persist the metadata URL alongside the fetched metadata XML
- [x] On SP creation via pasted XML: persist the pasted metadata XML (already done via `metadata_xml` column)
- [x] On manual entry: no metadata to store
- [x] SP detail page: view the full stored metadata XML (read-only, collapsible code block)
- [x] SP with stored metadata URL: "Refresh from URL" action that re-fetches metadata and shows a preview/diff of what would change (ACS URL, SLO URL, certificate, requested attributes, attribute mapping) before applying
- [x] SP with stored XML but no URL: "Re-import metadata" action where admin can paste new XML and preview changes before applying
- [x] SP with neither: no metadata refresh available, manual editing only
- [x] API endpoints for metadata refresh and re-import (4 endpoints: preview-refresh, apply-refresh, preview-reimport, apply-reimport)

**Effort:** M
**Value:** High

---

## Attribute Mapping UX Improvements

**Status:** Complete

**Resolution:** Replaced technical SAML terminology with admin-friendly labels on the SP attribute mapping tab. Heading renamed to "User Attribute Mapping", description simplified, SP Expectation column hidden when no metadata expectations exist, and match/mismatch indicators added when expectations are on file.

**Acceptance Criteria:**

- [x] Rename "Assertion Attribute Mapping" to "User Attribute Mapping" throughout the UI
- [x] Use friendlier description instead of technical SAML jargon
- [x] If no SP expectations are on file, hide the "SP Expectation" column entirely rather than showing "None declared" for every row
- [x] For each attribute row, clearly indicate whether it matches the SP's declared expectations (when metadata is on file)

**Effort:** XS

---

## SAML IdP: SP Attribute Mapping from Metadata

**Status:** Complete

**Resolution:** Implemented per-SP attribute mapping from SAML metadata. SP metadata `<md:AttributeConsumingService>` / `<md:RequestedAttribute>` elements are parsed and stored. Auto-detection maps known OIDs, Azure AD claims URIs, and friendly names to IdP attributes. Admins can override mappings per-SP on the detail page. The assertion builder uses per-SP mappings when present, falling back to global defaults. Two new JSONB columns on `service_providers`: `sp_requested_attributes` and `attribute_mapping`.

**Acceptance Criteria:**

- [x] Parse `<md:RequestedAttribute>` elements from SP metadata
- [x] Auto-detect attribute mappings from OIDs, Azure AD claims, and friendly names
- [x] Store per-SP attribute mapping in JSONB column
- [x] Interactive mapping UI on SP detail page (3-column: IdP Attribute, SP Expectation, Assertion URI)
- [x] Assertion builder uses per-SP mapping when constructing `AttributeStatement`
- [x] Falls back to `SAML_ATTRIBUTE_URIS` defaults for unmapped attributes

**Effort:** M

---

## SAML Identity Provider - Phase 4: Attribute Mapping & NameID Configuration

**Status:** Partially Complete / Superseded

**Resolution:** The per-SP attribute mapping portion was implemented as part of "SP Attribute Mapping from Metadata". Remaining items (NameID configuration, error handling, SSO event logging) were moved into the new "SP Metadata Management and Attribute Mapping UX" backlog item.

**Effort:** M

---

## SAML IdP: Include Group Membership in SSO Assertions

**Status:** Complete

**Resolution:** Group memberships are included as a multi-valued `groups` attribute in SAML assertions when enabled per SP. Uses the closure table to include both direct and inherited memberships. Per-SP opt-in toggle added to the SP detail page and REST API. Defaults to disabled.

**Acceptance Criteria:**

- [x] Assertion includes group membership attribute (configurable attribute name, default `groups`)
- [x] Includes both direct and inherited group memberships (via closure table)
- [x] Configurable per SP: opt-in (some SPs don't want group claims)
- [x] Group names sent as multi-valued attribute
- [x] Toggle on SP detail page: "Include group memberships in assertions"
- [x] API support for enabling/disabling group claims per SP

**Effort:** S

---

## Branding: Randomize & Save Mandala as Logo

**Status:** Complete

**Resolution:** Added Randomize and Save as Logo buttons to the branding settings page. Admins can preview random mandalas (160px) and save a favorite as both light and dark custom logos (40px SVGs). Two new API endpoints handle generation and persistence. Logo mode automatically switches to custom on save. Existing branding settings are preserved.

**Acceptance Criteria:**

- [x] "Randomize" button on the branding settings page generates a new mandala preview on each click
- [x] Preview displays the light mode mandala at a visible size (not just the 40px nav icon)
- [x] Each click uses a new random seed (not sequential, not predictable)
- [x] "Save as Logo" button persists the displayed mandala as the custom light mode SVG logo
- [x] Dark mode variant generated from the same seed is saved as the custom dark mode logo
- [x] Favicon variant generated from the same seed is available (favicon preference follows existing logic)
- [x] After saving, logo mode automatically switches to "custom" with the mandala SVGs as the logos
- [x] Admin can continue randomizing and saving again (replaces previous)
- [x] Event log entry when a mandala is saved as logo (`branding_logo_uploaded` with metadata indicating mandala source)
- [x] API support: `POST /api/v1/branding/mandala/randomize` returns preview SVGs for a random seed; `POST /api/v1/branding/mandala/save` persists the mandala for a given seed

**Effort:** S

---

## Branding: Custom Logo Favicon Should Respect System Theme

**Status:** Complete

**Resolution:** Updated `base.html` favicon template logic to emit two `<link rel="icon">` tags with `media="(prefers-color-scheme: light|dark)"` attributes when both light and dark custom logos exist. Falls back to light-only (no media query) when only a light logo is uploaded. Mandala favicon unchanged (already handled via embedded CSS media query in SVG).

**Acceptance Criteria:**

- [x] When both light and dark custom logos exist, emit two `<link rel="icon">` tags with `media` attributes
- [x] When only a light logo exists, fall back to serving it without a media query (current behavior)
- [x] Mandala favicon behavior unchanged
- [x] Existing tests pass (2855/2855)

**Effort:** XS
**Value:** Low (Visual polish, consistency with nav bar behavior)

---

## Tenant Branding: Custom Logo Upload

**Status:** Complete

**Resolution:** Implemented custom logo upload for tenant branding. Added `tenant_branding` table with bytea columns for light/dark logo variants, logo_mode enum (mandala/custom), and favicon toggle. Service layer validates PNG (square, min 48x48) and SVG (square viewBox) up to 256KB. Public unauthenticated endpoint serves logos with ETag caching. Branding settings page at Admin > Settings > Branding. API endpoints for CRUD operations. Three new event types for audit trail.

**Acceptance Criteria:**

- [x] Upload page at Admin > Settings > Branding (admin+ access)
- [x] Accept two logo slots: light mode and dark mode
- [x] Accepted formats: PNG and SVG only
- [x] PNG uploads must be square, minimum 48x48px
- [x] SVG uploads validated for square viewBox
- [x] Maximum file size: 256KB per file
- [x] Clear error messages for validation failures
- [x] Preview uploaded logos on settings page
- [x] Light logo fallback with circle background in dark mode
- [x] Logo mode toggle: Mandala (default) vs Custom
- [x] Favicon toggle (use logo as favicon)
- [x] Public endpoint `/branding/logo/{slot}` with ETag/304 and cache headers
- [x] API: GET, POST, DELETE, PUT branding endpoints
- [x] Event logging for upload, delete, and settings changes
- [x] 43 tests (service, API, public endpoint)

---

## SAML IdP: Single Logout (SLO) for Downstream SPs

**Status:** Complete

**Resolution:** Full SLO implementation across 4 phases. Added `slo_url` column to `service_providers` with metadata extraction and admin UI. IdP metadata now advertises `SingleLogoutService` endpoints. SSO assertions include `SessionIndex` for session correlation. SP-initiated SLO handles incoming `LogoutRequest` at `/saml/idp/slo` (GET and POST), clears the session, and returns a signed `LogoutResponse`. IdP-initiated SLO propagates `LogoutRequest` to all downstream SPs with active sessions when a user signs out (best-effort, non-blocking). New `slo_sp_initiated` and `slo_idp_propagated` event types for audit trail.

**Acceptance Criteria:**

- [x] Add `SingleLogoutService` element to IdP metadata (HTTP-Redirect and HTTP-POST bindings)
- [x] SLO URL: `{base_url}/saml/idp/slo`
- [x] Handle incoming LogoutRequest at `/saml/idp/slo` (GET and POST)
- [x] Validate LogoutRequest (issuer is a registered SP)
- [x] Terminate user's WeftId session
- [x] Return LogoutResponse to SP's SLO URL
- [x] Event log entry for SLO events
- [x] When user signs out from WeftId, send LogoutRequest to all SPs with active sessions
- [x] Track which SPs have active SSO sessions per user (session cookie)
- [x] Best-effort delivery (don't block logout if an SP is unreachable)
- [x] Store SLO URL per SP (from metadata import or manual entry)
- [x] SP detail page shows SLO URL

---

## Group Membership UX Redesign

**Status:** Complete

**Resolution:** Replaced inline member list on group detail page with dedicated paginated member list and add-members pages. Added search, filtering (role/status), sortable columns, pagination, and bulk add/remove. Full-stack implementation across database, service, router, API, and template layers. New `group_members_bulk_removed` event type for audit trail. API enhanced with search/filter params on members endpoint, new available-users endpoint, and bulk-remove endpoint.

**Commits:**
- `d0a7229` Split groups.py router into package (REFACT-003)
- `14f9e75` Add dedicated group membership management pages

---

## SAML IdP: Per-SP Entity ID in Metadata and Assertions

**Status:** Complete

**Summary:** Fixed entity ID mismatch where per-SP metadata XML and SAML assertions used the tenant-level entity ID instead of the per-SP entity ID. Updated three locations (metadata generation, assertion Issuer, metadata URL info) to use `{base_url}/saml/idp/metadata/{sp_id}` for per-SP contexts. Tenant-level metadata remains unchanged.

**Acceptance Criteria:**

- [x] Per-SP metadata XML has `entityID="{base_url}/saml/idp/metadata/{sp_id}"`
- [x] Tenant-level metadata XML keeps `entityID="{base_url}/saml/idp/metadata"` (unchanged)
- [x] SAML assertion Issuer uses the per-SP entity ID when responding to an SP
- [x] `get_sp_metadata_url_info()` returns the per-SP entity ID
- [x] Existing tests updated to reflect per-SP entity ID
- [x] All tests pass

---

## SAML Identity Provider - Phase 3: Dashboard & Group-Based App Assignment

**Status:** Complete

**Summary:** Implemented group-based access control for downstream Service Providers, a "My Apps" dashboard section, and IdP-initiated SSO. SP access is controlled exclusively via group-to-SP assignments, leveraging the existing group hierarchy (DAG with closure table). Users inherit access through their group memberships. If an SP has no group assignments, no users can access it (security-first model).

**Completed Work:**

**Group-Based App Assignment Model:**

- [x] Super admins and admins can assign SPs to groups (both weftid and idp group types)
- [x] Assignment UI on SP detail page: view assigned groups, add/remove group assignments
- [x] Assignment UI on group detail page: view assigned SPs for the group (read-only)
- [x] Remove group assignments (revokes access for all group members)
- [x] Bulk assignment: assign an SP to multiple groups at once

**Access Control:**

- [x] Users can access an SP if any of their groups (or any ancestor of their groups) has an assignment to that SP
- [x] Group hierarchy is respected: assigning an SP to a parent group grants access to members of all descendant groups
- [x] If an SP has no group assignments, no users can access it (explicit grant required)
- [x] SP-initiated SSO validates user has access (via group/ancestor membership) before showing consent screen
- [x] Unauthorized access shows clear error message with "Return to Dashboard" and "Sign in as someone else" options
- [x] Access is evaluated at SSO time (not cached), so group membership and hierarchy changes take effect immediately

**User Dashboard - My Apps:**

- [x] "My Apps" section on user dashboard (visible to all users)
- [x] Shows all SPs the user can access via their group memberships
- [x] App display: name, optional description
- [x] Click app tile to launch (IdP-initiated SSO)
- [x] Empty state when user has no accessible apps: "No applications available"

**IdP-Initiated SSO:**

- [x] Launching from dashboard generates SAML Response without prior AuthnRequest
- [x] Same consent screen as SP-initiated flow
- [x] POST assertion to SP's ACS URL

**SP Enhancements:**

- [x] Add description field to SPs (optional, shown in dashboard)
- [x] SP list view shows assigned group count per SP

**REST API Endpoints:**

- [x] `GET /api/v1/service-providers/{sp_id}/groups` - list assigned groups
- [x] `POST /api/v1/service-providers/{sp_id}/groups` - assign group
- [x] `POST /api/v1/service-providers/{sp_id}/groups/bulk` - bulk assign
- [x] `DELETE /api/v1/service-providers/{sp_id}/groups/{group_id}` - remove assignment
- [x] `GET /api/v1/my-apps` - user's accessible apps (any authenticated role)
- [x] `GET /api/v1/groups/{group_id}/service-providers` - group's assigned SPs

**Technical Implementation:**

- Database migration: `db-init/00031_sp_group_assignments.sql`
  - `sp_group_assignments` table with RLS, indexes, and grants
  - `description` column added to `service_providers`
- Database layer: `app/database/sp_group_assignments.py` (assignment CRUD, access check via closure table, user accessible SPs)
- Service layer: Group assignment functions with authorization, event logging, and activity tracking
- SSO router: Access gate in consent page, IdP-initiated launch route (`GET /saml/idp/launch/{sp_id}`)
- Admin UI: Group assignment cards on SP detail and group detail pages
- Dashboard: My Apps section with launch tiles
- Event types: `sp_group_assigned`, `sp_group_unassigned`, `sp_groups_bulk_assigned`
- 87 new tests across service, admin router, SSO router, API, and dashboard layers (2612 total)

**Effort:** M
**Value:** High (User-facing feature, admin control over access via existing group infrastructure)

---

## SAML Identity Provider - Phase 2: Per-SP Signing Certificates & Metadata

**Status:** Complete

**Summary:** Implemented per-SP signing certificates and metadata URLs so that certificate compromise or rotation for one SP does not affect others. Each registered SP now gets its own auto-generated signing certificate, and metadata is available at per-SP URLs (`/saml/idp/metadata/{sp_id}`). The tenant-wide metadata URL remains as a fallback. The SSO flow signs assertions with the correct SP-specific certificate. Also moved Service Providers from the Integrations section to Settings and hid the tenant metadata URL when no SPs are registered.

**Completed Work:**

**Per-SP Signing Certificates:**

- [x] Each registered SP gets its own auto-generated signing certificate
- [x] Certificate generated on SP registration (alongside existing SP creation flow)
- [x] SP-specific certificate used when signing SAML assertions for that SP
- [x] Certificate rotation per SP (rotate one without affecting others)
- [x] Admin UI shows certificate status (expiry date) per SP

**Per-SP Metadata URLs:**

- [x] Metadata endpoint accepts SP identifier: `GET /saml/idp/metadata/{sp_id}`
- [x] Per-SP metadata returns that SP's signing certificate (not a shared tenant cert)
- [x] Tenant-wide metadata URL (`/saml/idp/metadata`) remains as a fallback returning the tenant cert
- [x] Admin UI shows per-SP metadata URL on SP detail/list page
- [x] Download and copy per-SP metadata URL

**Backward Compatibility:**

- [x] Existing SPs get certificates generated via a one-time migration or lazy generation
- [x] Entity ID and SSO URL remain tenant-scoped (no per-SP SSO endpoints)
- [x] Phase 1c SSO flow updated to sign with the correct SP-specific certificate

**Effort:** M
**Value:** High (Security isolation, matches industry standard IdP behavior)

---

## SAML Identity Provider - Phase 1c: SP-Initiated SSO Flow

**Status:** Complete

**Summary:** Implemented the full SP-Initiated SSO flow for the SAML IdP. SPs send AuthnRequests to `/saml/idp/sso` (HTTP-Redirect or POST binding). Unauthenticated users are redirected to login with SSO context preserved through session regeneration. Authenticated users see a consent screen showing the SP name and attributes being shared. On consent, a signed SAML Response (RSA-SHA256, Exclusive C14N, enveloped signature) is generated using `lxml` + `xmlsec` and POSTed to the SP's ACS URL via auto-submitting form.

**Delivered:**
- AuthnRequest parsing utility (`app/utils/saml_authn_request.py`) with redirect and POST binding support
- SAML Response/Assertion generation with XML Digital Signatures (`app/utils/saml_assertion.py`)
- SSO router (`app/routers/saml_idp/sso.py`) with GET/POST SSO and GET/POST consent endpoints
- Consent screen, auto-submit POST form, and error templates
- SSO service layer functions (`get_sp_by_entity_id`, `build_sso_response`)
- SSO context preservation through MFA verification and SAML authentication flows
- CSRF exemption for `/saml/idp/sso` (external SP POST), CSRF protection for consent form
- Event logging: `sso_assertion_issued`, `sso_consent_denied`
- 67 new tests across 5 test files (utilities, services, router, integration)

---

## SAML Identity Provider - Phase 1b: IdP Metadata Exposure

**Status:** Complete

**User Story:**
As a super admin
I want my tenant to expose SAML IdP metadata
So that downstream service providers can configure trust with my identity provider

**Completed Work:**

- [x] Tenant-specific IdP metadata endpoint: `GET /saml/idp/metadata`
- [x] Metadata includes: Entity ID, SSO endpoint URL, signing certificate, supported NameID formats
- [x] Downloadable as XML file via `GET /saml/idp/metadata/download`
- [x] Admin UI displays the metadata URL and provides download button on SP list page

**Technical Implementation:**

- New `app/routers/saml_idp/metadata.py`: public metadata endpoint (unauthenticated)
- `app/utils/saml_idp.py`: `generate_idp_metadata_xml()` produces SAML 2.0 IdP metadata XML
- `app/services/service_providers.py`: `get_tenant_idp_metadata_xml()` orchestrates cert lookup and XML generation
- Entity ID: `{base_url}/saml/idp/metadata`, SSO URL: `{base_url}/saml/idp/sso`
- Reuses existing `saml_sp_certificates` table for tenant signing certificate
- Router package: `app/routers/saml_idp/` with `_helpers.py` for shared `get_base_url()`

**Effort:** S
**Value:** High (Required for downstream SP configuration)

---

## SAML Identity Provider - Phase 1a: Service Provider Registration

**Status:** Complete

**User Story:**
As a super admin
I want to register downstream applications as SAML Service Providers
So that those applications can authenticate users via SSO against my tenant's identity provider

**Completed Work:**

- [x] Database migration (`db-init/00029_service_providers.sql`): `service_providers` table with RLS, indexes, triggers
- [x] Pydantic schemas (`app/schemas/service_providers.py`): SPCreate, SPConfig, SPListItem, SPListResponse, metadata import models
- [x] Database CRUD layer (`app/database/service_providers.py`): list, get, get_by_entity_id, create, delete
- [x] SP metadata parsing utility (`app/utils/saml_idp.py`): parse_sp_metadata_xml, fetch_sp_metadata using defusedxml
- [x] Service layer (`app/services/service_providers.py`): full CRUD with authorization, event logging, activity tracking
- [x] Admin UI router (`app/routers/saml_idp/admin.py`): list, new form, create (manual/XML/URL), delete
- [x] REST API router (`app/routers/api/v1/service_providers.py`): full CRUD endpoints under `/api/v1/service-providers`
- [x] Templates: SP list page (`saml_idp_sp_list.html`), registration form with 3 tabs (`saml_idp_sp_new.html`)
- [x] Event types: `service_provider_created`, `service_provider_deleted`
- [x] Pages registry updated with Service Providers under Integrations (super_admin)
- [x] Comprehensive tests: utility (8), service (19), router (13), API (13) = 53 new tests

---

## User-Centric Group Management

**Status:** Complete

**User Story:**
As an admin
I want to manage group assignments from the user's perspective (not just the group's perspective)
So that onboarding a user or adjusting their access doesn't require visiting each group page individually

**Completed Work:**

**User Detail - Groups Tab:**

- [x] "Groups" section on the user detail page (admin view)
- [x] Shows all groups the user is a direct member of, with group type badge (WeftID/IdP)
- [x] Shows effective groups (inherited via hierarchy) separately, marked as "Inherited"
- [x] Admin can add the user to a WeftID group from a dropdown (single add)
- [x] Admin can add the user to multiple WeftID groups at once (multi-select bulk add)
- [x] Admin can remove the user from a WeftID group (with confirmation)
- [x] IdP group memberships are shown as read-only

**Users List - Group Context:**

- [x] Users list shows a group count column (number of direct group memberships)
- [x] Group count is a link to the user's groups tab

**API Endpoints:**

- [x] `GET /api/v1/users/{user_id}/groups` returns direct group memberships
- [x] `POST /api/v1/users/{user_id}/groups` adds user to one or more groups
- [x] `DELETE /api/v1/users/{user_id}/groups/{group_id}` removes user from a group

**Technical Implementation:**

- Group membership data added to user detail service/query
- Groups section in user detail template with direct/inherited views
- Database queries for user-centric group operations
- API endpoints under `/api/v1/users/{user_id}/groups`
- Web routes in `app/routers/users/groups.py` for form submissions
- Service functions: `get_direct_memberships`, `get_effective_memberships`, `bulk_add_user_to_groups`, `list_available_groups_for_user`
- Reuses existing `add_member`/`remove_member` service functions
- Group count column via LEFT JOIN subquery in users listing query
- Comprehensive tests across router, API, service, and database layers

**Effort:** M
**Value:** High (Core admin workflow, daily-use feature)

---

## Users List UX Overhaul

**Status:** Complete

**User Story:**
As an admin
I want a more powerful and usable user listing page
So that I can quickly find, filter, and scan users without friction

**Completed Work:**

**1. Full-Width Layout:**

- [x] User listing table stretches to fill the full available screen width
- [x] Removed max-width container constraints on the listing page
- [x] Table columns use available space proportionally (name and email get more room)
- [x] Maintains responsive behavior on smaller screens (horizontal scroll preserved)

**2. Relative Date Display:**

- [x] Last Activity and Created columns show human-readable relative dates
- [x] Granularity: "Today", "Yesterday", "3 days ago", "2 weeks ago", "4 months ago", "1 year ago"
- [x] Threshold rules: days up to 13, weeks from 14-59 days, months from 60-364 days, years from 365+ days
- [x] Tooltip shows exact datetime in Babel medium format (timezone-aware)
- [x] "Never" shown when no activity exists
- [x] Computed server-side; date column sorting uses actual datetime values

**3. Tokenized Search:**

- [x] Search input split into whitespace-separated tokens
- [x] Each token matched independently against first_name, last_name, and email (AND across tokens, OR within)
- [x] Single-word searches backward compatible
- [x] Case-insensitive matching (ILIKE)
- [x] API endpoint benefits automatically (same database layer)

**4. Auth Method Filter + Collapsible Panel:**

- [x] Auth method filter section alongside existing Role and Status filters
- [x] Filter options built from static categories plus tenant's SAML IdPs
- [x] Categories: Password + Email, Password + TOTP, [IdP Name], [IdP Name] + TOTP, Unverified
- [x] Multiple auth methods selectable (checkbox-based)
- [x] Filter applied server-side in database query
- [x] Auth method parameter included in URL for bookmarkability
- [x] Collapsible filter panel (collapsed by default)
- [x] "Filtered results" indicator with "Clear filters" link when collapsed with active filters
- [x] Filter state persisted to localStorage (scoped by tenant_id)
- [x] Collapse/expand state also remembered in localStorage

**Also fixed:** Auth method column previously showed "None" for all users because the listing
query omitted `saml_idp_id`, `has_password`, `mfa_enabled`, and `mfa_method`. Now included.

**Technical Implementation:**

- `app/templates/base.html`: Content wrapper class overridable via `{% block content_wrapper %}`
- `app/templates/users_list.html`: Full-width layout, relative dates, collapsible filter panel, localStorage persistence
- `app/utils/datetime_format.py`: `format_relative_date()` and `create_relative_date_formatter()`
- `app/utils/template_context.py`: `fmt_relative` injected into template context
- `app/database/users/listing.py`: `_build_search_clauses()`, `_build_auth_method_clauses()`, auth_methods param
- `app/services/users/utilities.py`: `get_auth_method_options()` builds options from static + IdP data
- `app/services/users/crud.py`: `list_users()` accepts roles/statuses/auth_methods
- `app/routers/users/listing.py`: Parses auth_method query param, fetches options, passes to template
- `app/routers/api/v1/users/admin.py`: role/status/auth_method query params for API
- 26 new tests across database, router, API, and utility layers

**Effort:** M
**Value:** High (Daily-use admin page, reduces friction for common tasks)

---

## Group System - Phase 1: Core Infrastructure

**Status:** Complete

**User Story:**
As an admin
I want to create groups and organize them hierarchically
So that I can model my organization's structure and prepare for access control

**Completed Work:**

**WeftID Groups:**

- [x] Admin can create groups with name (required) and description (optional)
- [x] Admin can edit group name and description
- [x] Admin can delete groups (children become orphaned, not deleted)
- [x] Admin can add users as direct members of groups
- [x] Admin can remove users from groups
- [x] List view of all groups with member counts

**Group Hierarchy:**

- [x] Admin can make one group a child of another (group-in-group)
- [x] Groups can have multiple parents
- [x] Groups can have multiple children
- [x] Cycle detection prevents circular relationships
- [x] UI shows parent/child relationships

**Technical Implementation:**

- Database migration: `db-init/00027_groups.sql`
  - `groups`: id, tenant_id, name, description, group_type (enum: 'weftid', 'idp'), idp_id (nullable), is_valid (boolean, default true), created_at
  - `group_memberships`: id, group_id, user_id, created_at
  - `group_relationships`: id, parent_group_id, child_group_id, created_at (unique constraint on pair)
  - `group_lineage`: closure table for DAG ancestor-descendant tracking (O(1) cycle detection)
- New router: `app/routers/groups.py` (frontend)
- New API router: `app/routers/api/v1/groups.py` (RESTful API)
- New service: `app/services/groups.py`
- New database module: `app/database/groups.py`
- New schemas: `app/schemas/groups.py`
- Templates: `groups_list.html`, `groups_new.html`, `groups_detail.html`
- DAG model with closure table pattern for efficient hierarchy queries
- Cycle detection via lineage table (prevents A being both ancestor AND descendant of B)
- 52 comprehensive tests covering API, service, database, and router layers

**Effort:** M
**Value:** High (Foundation for access control)

---

## Group System - Phase 2: IdP Group Integration

**Status:** Complete

**User Story:**
As an admin
I want groups to be automatically discovered from IdP authentication
So that I can leverage existing organizational structure from upstream identity providers

**Completed Work:**

**Auto-created IdP Group:**

- [x] When an IdP is created, automatically create a group with the same name
- [x] Group is marked as type='idp' and linked to the IdP record
- [x] All users authenticating via that IdP are automatically added to this group
- [x] This group cannot have children (leaf-only constraint for IdP groups)

**SAML Group Discovery:**

- [x] Parse group claims from SAML assertions (common attribute names: groups, memberOf, etc.)
- [x] Auto-create IdP-scoped groups when new group names are discovered
- [x] Auto-associate users with discovered groups on each authentication
- [x] IdP groups display which IdP they belong to
- [x] IdP groups are read-only (admins cannot edit membership directly)

**IdP Group as Children:**

- [x] Admin can make IdP groups children of WeftID groups
- [x] IdP groups can have multiple WeftID parents
- [x] IdP groups cannot be parents (enforced)

**IdP Deletion Handling:**

- [x] When IdP is deleted, associated groups are marked is_valid=false
- [x] Invalid groups are visually distinguished in UI
- [x] Invalid groups preserve membership data for historical reference
- [x] Admin can delete invalid groups once empty

**Technical Implementation:**

- Database migration: `db-init/00028_idp_group_integration.sql`
- Updated `app/services/groups.py` with IdP group functions:
  - `create_idp_base_group()` - auto-creates group when IdP created
  - `sync_user_idp_groups()` - syncs user group memberships on SAML auth
  - `invalidate_idp_groups()` - marks groups invalid when IdP deleted
  - `list_groups_for_idp()` - lists groups belonging to an IdP
- Updated `app/services/saml/provisioning.py` to call group sync during authentication
- Updated `app/database/groups.py` with IdP group queries
- Updated templates: `groups_list.html`, `groups_detail.html` with IdP badges and invalid state
- Event types: `idp_group_created`, `idp_group_invalidated`, `idp_group_user_added`, `idp_group_user_removed`, `idp_group_discovered`
- 14 service tests + 2 API tests for IdP group functionality

**Effort:** M
**Value:** High (Bridges upstream IdPs with internal group model)

---

## Admin Navigation Reorganization

**Status:** Complete

**User Story:**
As an admin
I want the admin section organized into logical groupings
So that navigation is less cluttered and related functions are grouped together

**Completed Work:**

**Navigation Structure:**

- [x] Settings section containing:
  - Security (super_admin only)
  - Privileged Domains (admin)
  - Identity Providers (super_admin only)
- [x] Todo section containing:
  - Reactivation (admin)
- [x] Audit section containing:
  - Event Log (admin)
- [x] Integrations section containing:
  - Apps (admin)
  - B2B (admin)

**URL Changes (no redirects needed):**

- [x] `/admin/security` → `/admin/settings/security`
- [x] `/admin/privileged-domains` → `/admin/settings/privileged-domains`
- [x] `/admin/identity-providers/*` → `/admin/settings/identity-providers/*`
- [x] `/admin/events` → `/admin/audit/events`
- [x] `/admin/events/{id}` → `/admin/audit/events/{id}`
- [x] `/admin/reactivation-requests` → `/admin/todo/reactivation`
- [x] `/admin/reactivation-requests/history` → `/admin/todo/reactivation/history`
- [x] `/admin/integrations/*` → unchanged (already under `/admin/integrations/`)

**Technical Implementation:**

- Updated `app/pages.py` with new nested hierarchy structure (4 sections)
- Updated `get_first_accessible_child()` to recursively find leaf pages in nested sections
- Updated router paths in:
  - `app/routers/settings.py` (prefix changed to `/admin/settings`)
  - `app/routers/admin.py` (events to `/audit/events`, reactivation to `/todo/reactivation`)
  - `app/routers/saml.py` (all paths to `/admin/settings/identity-providers`)
- Updated 10 templates with hardcoded paths
- Updated 7 test files with new URL paths
- All 1988 tests pass

**Effort:** M
**Value:** High (UX improvement for admins)

---

## Integration Management Frontend - Phase 2: Edit, Regenerate & Deactivate

**Status:** Complete

**User Story:**
As an admin
I want to edit integration details, rotate secrets, and deactivate integrations through the web UI
So that I can manage the full lifecycle of OAuth2 clients without API calls

**Completed Work:**

**Apps Tab - Edit & Manage:**

- [x] Click client row to open detail/edit view
- [x] Edit form: Name, Description, Redirect URIs
- [x] "Regenerate Secret" with confirmation dialog, then credentials modal (same flow as create)
- [x] "Deactivate" button with confirmation (soft-delete: sets `is_active = false`)
- [x] Inactive clients shown in list with "Inactive" badge, grayed out
- [x] Option to reactivate inactive clients

**B2B Tab - Edit & Manage:**

- [x] Click client row to open detail/edit view
- [x] Edit form: Name, Description
- [x] Change service user role (select dropdown)
- [x] "Regenerate Secret" with same flow
- [x] "Deactivate" with same soft-delete flow
- [x] Inactive clients shown with badge

**Backend Changes:**

- [x] `GET /api/v1/oauth2/clients/{client_id}` endpoint for fetching single client
- [x] `PATCH /api/v1/oauth2/clients/{client_id}` endpoint for updating name, description, redirect_uris
- [x] `PATCH /api/v1/oauth2/clients/{client_id}/role` endpoint for changing B2B service user role
- [x] `POST /api/v1/oauth2/clients/{client_id}/deactivate` endpoint (sets is_active = false)
- [x] `POST /api/v1/oauth2/clients/{client_id}/reactivate` endpoint (sets is_active = true)
- [x] Deactivated clients reject OAuth2 token requests
- [x] All write operations emit event logs

**Testing:**

- [x] Full test coverage for new API endpoints
- [x] Router tests for edit, regenerate, deactivate flows
- [x] Service tests for update, deactivate, reactivate logic
- [x] Verify deactivated clients cannot authenticate

**Technical Implementation:**

- Event types: 4 new event types in `app/constants/event_types.py`
- Schemas: `ClientUpdate`, `ClientRoleUpdate` in `app/schemas/oauth2.py`
- Database layer: `update_client()`, `update_b2b_client_role()`, `deactivate_client()`, `reactivate_client()` in `app/database/oauth2.py`
- Service layer: Corresponding functions with event logging in `app/services/oauth2.py`
- API router: 5 new endpoints in `app/routers/api/v1/oauth2_clients.py`
- Token endpoint: is_active check in `app/routers/oauth2.py`
- Frontend router: 10 new routes in `app/routers/integrations.py`
- Templates: `integrations_app_detail.html`, `integrations_b2b_detail.html`
- Updated list templates with clickable rows and inactive styling
- Comprehensive tests added to `test_api_oauth2_clients.py` and `test_routers_integrations.py`

**Effort:** M
**Value:** High

---

## Integration Management Frontend - Phase 1: List & Create

**Status:** Complete

**User Story:**
As an admin
I want to view existing OAuth2 integrations and create new ones through a web UI
So that I can set up Apps and B2B service accounts without using API calls directly

**Completed Work:**

**Navigation & Page Structure:**

- [x] New "Integrations" item in Admin sub-navigation
- [x] Two sub-tabs: "Apps" and "B2B"
- [x] Accessible to Admin and Super Admin roles (matching existing API permissions)

**Database Enhancements:**

- [x] Migration adds `description TEXT` column to `oauth2_clients`
- [x] Migration adds `is_active BOOLEAN NOT NULL DEFAULT true` column to `oauth2_clients` (prep for Phase 2 soft-delete)
- [x] Existing API endpoints include `description` and `is_active` in responses
- [x] Create endpoints accept optional `description` field

**Apps Tab (Normal OAuth2 Clients):**

- [x] List view showing: Name, Client ID, Redirect URIs count, Created At, Status (active/inactive badge)
- [x] "Create App" button opens modal form
- [x] Creation form: Name (required), Description (optional), Redirect URIs (textarea, one per line)
- [x] On successful creation: credentials modal shows Client ID and Client Secret with copy buttons
- [x] Credentials displayed via session (one-time read, never in URLs)
- [x] Dismiss button: "I've saved the credentials" (no ESC/backdrop dismiss for credentials modal)

**B2B Tab (Service Accounts):**

- [x] List view showing: Name, Client ID, Service Role, Created At, Status badge
- [x] "Create B2B Client" button opens modal form
- [x] Creation form: Name (required), Description (optional), Role (select: member/admin/super_admin)
- [x] Same credentials display flow as Apps tab

**Testing:**

- [x] Router tests for all routes (list, create, auth, error handling)
- [x] Service tests for updated functions (type filter, description param)
- [x] API tests updated for new response fields
- [x] Database tests for new columns and filters

**Technical Implementation:**

- Database migration: `db-init/00026_oauth2_client_enhancements.sql`
- Database layer: `app/database/oauth2.py` with `client_type` filter, `description` param, LEFT JOIN for B2B service roles
- Service layer: `app/services/oauth2.py` with `client_type` and `description` pass-through
- Schemas: `app/schemas/oauth2.py` with `description` and `is_active` fields
- API router: `app/routers/api/v1/oauth2_clients.py` with new fields and filter
- Frontend router: `app/routers/integrations.py` with session-based credential display
- Templates: `app/templates/integrations_apps.html`, `app/templates/integrations_b2b.html`
- Pages registered in `app/pages.py`, router in `app/main.py`
- 86 new tests across 5 test files (router, service, API, database, pages)

**Effort:** M
**Value:** High

---

## Admin MFA Reset for Users

**Status:** Complete

**User Story:**
As an admin or super admin
I want to disable MFA for a user who has lost access to their authenticator
So that I can help them regain account access after out-of-band identity verification

**Completed Work:**

**Access & Permissions:**
- [x] Available to admins and super admins
- [x] Action appears on user detail page (admin view)

**Behavior:**
- [x] "Reset MFA" button disables TOTP MFA for the target user
- [x] User's next login follows standard email/password + email OTP flow
- [x] User can then re-enroll in TOTP MFA from their settings

**Notification:**
- [x] User receives email notification that their MFA was reset
- [x] Email includes: timestamp, which admin performed the action
- [x] Email does not include any action links (no "click here to re-enable")

**Event Logging:**
- [x] Action logged with: admin who performed it, target user, timestamp

**Security Considerations:**
- [x] No self-service "I lost my authenticator" flow
- [x] No in-app way for users to request MFA reset
- [x] Admins expected to verify user identity out-of-band before using this

**Implementation Details:**
- MFA section on user detail page shows contextual info based on MFA method
- Email MFA users: info display only (no reset needed)
- TOTP users: reset button shown when not on SSO, or when SSO requires platform MFA
- TOTP users on SSO without platform MFA: info only (authenticator unused)
- Email notification sent to user after reset with admin name and timestamp
- Service function `reset_user_mfa()` in `app/services/mfa.py`
- Frontend route `POST /users/{user_id}/reset-mfa` in `app/routers/users.py`
- API endpoint `POST /api/v1/users/{user_id}/mfa/reset` (pre-existing)

**Effort:** S
**Value:** Medium

---

## Dark Mode with System Preference Detection

**Status:** Complete

**User Story:**
As a user
I want the application to support dark mode that follows my system preference
So that I can use the platform comfortably in low-light environments

**Completed Work:**

**User Preference Model:**
- [x] New user setting: "Theme" with options: "System" (default), "Light", "Dark"
- [x] Setting stored in database, persists across devices
- [x] Accessible from user settings page

**Theme Detection & Application:**
- [x] When set to "System": detect `prefers-color-scheme` on page load
- [x] Theme applied on page load (no mid-session transitions)
- [x] Anonymous pages (login, error pages) follow system preference only

**Implementation:**
- [x] Tailwind dark mode classes added to all templates using Tailwind's default dark palette
- [x] Use Tailwind's `dark:` variant for all color scheme styling
- [x] JavaScript snippet in base template for system detection
- [x] All pages updated (dashboard, settings, admin pages, auth pages)

**Out of Scope:**
- Email template dark mode (email clients handle this)
- Per-tenant default theme setting

**Technical Implementation:**
- Database migration: `00025_user_theme.sql` adding theme column to users table
- Theme field in user schemas (UserProfile, UserProfileUpdate)
- Database layer: `update_user_theme()` function
- Service layer: Theme update in `update_current_user_profile()`
- Router: POST endpoint `/account/profile/update-theme`
- Tailwind config: `darkMode: 'class'`
- JavaScript: blocking script in `<head>` for FOUC prevention, localStorage sync
- All 36 templates updated with `dark:` variants
- Test suite enforcing dark mode coverage (`tests/test_templates_dark_mode.py`)

**Effort:** M
**Value:** Medium

---

## Event Detail Pane Cleanup

**Status:** Complete

**User Story:**
As an admin viewing event details
I want a clear distinction between context and additional details
So that I can quickly see the standard info and drill into extras only when relevant

**Completed Work:**

**Section 1: Context**
- [x] Always visible
- [x] Shows fields conditionally based on event source:
  - IP Address (always)
  - User Agent (always)
  - Device Type (web only, hidden for API)
  - Session ID (web only, hidden for API)
  - API Client (API only, shows client name + client_id)
- [x] No "N/A" for inapplicable fields; simply hide them

**Section 2: Details**
- [x] Only appears if event has additional event-specific fields
- [x] Shows only fields not in the Context section
- [x] Hidden entirely if no additional fields exist

**Section 3: Raw Event**
- [x] Section at the bottom
- [x] Full event as JSON (type, timestamp, user, context, details, everything)
- [x] Useful for debugging and support

**Backend: API Client Context Population:**
- [x] API client info (client_id, client_name) auto-populated in contextvar when API endpoints are called
- [x] Event logging automatically captures API client context (same pattern as web session context)

**Technical Implementation:**
- `app/utils/request_context.py`: Added API client contextvar and functions
- `app/api_dependencies.py`: Sets API client context after OAuth2 token validation
- `app/database/oauth2.py`: Added `get_client_by_id()` function
- `app/services/event_log.py`: Captures API client context in metadata
- `app/schemas/event_log.py`: Added api_client_* fields to EventLogItem
- `app/templates/admin_event_detail.html`: 3-section layout with conditional display
- `tests/test_request_context.py`: Tests for API client context

**Effort:** S
**Value:** Low

---

## Verbose Descriptions for Event Types

**Status:** Complete

**User Story:**
As an admin reviewing event logs
I want human-readable descriptions for each event type
So that I can quickly understand what each event means without consulting documentation

**Completed Work:**

**Description Display:**
- [x] Mouseover tooltip on event type in event list view
- [x] Description shown on event detail pane
- [x] Event log export includes machine-readable mapping of all event types to descriptions

**Description Content:**
- [x] One-liner description for each event type (e.g., "user.login" → "User successfully authenticated")
- [x] All existing event types have descriptions

**Implementation:**
- [x] Hardcoded map in `app/constants/event_types.py`: event_type → description
- [x] Lockfile `app/constants/event_types.lock` containing all event type keys
- [x] Test that verifies lockfile is a subset of current map keys (no deletions allowed)
- [x] Adding new event types requires manually updating the lockfile (explicit acknowledgment)

**Backwards Compatibility Guarantee:**
- [x] Event types must never be deleted or renamed
- [x] Unwanted event types can be deprecated but must remain in the map
- [x] Test enforces this by failing if any lockfile entry is missing from the map

**Technical Implementation:**
- `app/constants/event_types.py`: EVENT_TYPE_DESCRIPTIONS dict with 50+ event types
- `app/constants/event_types.lock`: Lockfile with all event type keys
- `tests/test_event_types.py`: Test verifying backwards compatibility

**Effort:** S
**Value:** Medium

---

## Replace External CDN Dependencies with Local Versions

**Status:** Complete

**User Story:**
As a platform operator
I want to eliminate external CDN and API dependencies for frontend assets and QR code generation
So that I can strengthen security posture, protect user privacy, and eliminate supply chain attack vectors

**Completed Work:**

**Tailwind CSS Migration:**

- [x] Install `tailwindcss-cli` or equivalent build tooling
- [x] Create `tailwind.config.js` with project-specific configuration
- [x] Set up PostCSS build pipeline for optimized CSS generation
- [x] Remove `<script src="https://cdn.tailwindcss.com"></script>` from `app/templates/base.html`
- [x] Replace with compiled CSS file served locally
- [x] Update CSP to remove `https://cdn.tailwindcss.com` from `script-src`
- [x] Verify all existing Tailwind styles still work correctly

**QR Code Generation (CRITICAL - Privacy Issue):**

- [x] Install `qrcode[pil]` Python package
- [x] Create server-side QR code generation function in `app/utils/qr.py`
- [x] Generate QR codes as base64-encoded data URLs
- [x] Update `app/templates/mfa_setup_totp.html` to use local QR generation instead of `https://api.qrserver.com`
- [x] Remove `https://api.qrserver.com` from CSP `script-src` and `img-src` directives
- [x] Verify TOTP setup flow works correctly with locally-generated QR codes
- [x] Test on multiple devices to ensure QR codes scan properly

**Security Improvements:**

- [x] Update CSP to remove external domains
- [x] Update security headers tests to verify stricter CSP
- [x] Document new build process in CLAUDE.md

**Technical Implementation:**

- Frontend build: Standalone Tailwind CLI (no Node.js dependency)
- QR generation: `qrcode[pil]` Python library
- Updated `app/middleware/security_headers.py` CSP configuration
- Updated relevant templates
- Added build step to Dockerfile
- Added Makefile targets (`make build-css`, `make watch-css`)

**Effort:** M
**Value:** High (Security & Privacy)

**Notes:**

- CRITICAL issue resolved: TOTP secrets no longer leak to third-party API
- Benefits: Stronger CSP without external domains, no user data leaving infrastructure, no supply chain attack risk, better performance with optimized Tailwind builds
- Eliminated two external dependencies and significantly reduced attack surface
- All 1729 tests pass

---

## SAML Upstream IdP Support - Phase 4: Provider Helpers, SLO & Certificate Management

**Status:** Complete

**User Story:**
As a super admin
I want streamlined setup experiences for common IdPs, single logout support, and certificate lifecycle management
So that I can quickly configure enterprise SSO and maintain it over time without deep SAML expertise

**Completed Work:**

**Provider-Specific Attribute Presets:**

- [x] When selecting provider type (Okta, Azure AD, Google), auto-fill default attribute mappings
- [x] Okta defaults: `email`, `firstName`, `lastName`
- [x] Azure AD defaults: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`, etc.
- [x] Google defaults: Google's SAML attribute names
- [x] Setup guide links in UI pointing to each provider's SAML app configuration docs

**Single Logout (SLO):**

- [x] Per-IdP setting: `slo_url` (optional)
- [x] `GET/POST /saml/slo` endpoint handles:
  - SP-initiated logout: When user logs out, send LogoutRequest to IdP
  - IdP-initiated logout: Process LogoutRequest from IdP (best-effort with cookie sessions)
- [x] If IdP has no SLO URL configured, logout only affects local session
- [x] SLO errors logged but don't block local logout
- [x] SLO URL field in form with note explaining its purpose

**SP Certificate Management:**

- [x] "Rotate Certificate" button on IdP list page (tenant-level action)
- [x] Generates new SP certificate with configurable grace period (default 7 days)
- [x] Warning modal explaining need to update IdP metadata
- [x] Old certificate valid during grace period (both certs in rotation window)
- [x] API endpoint for certificate rotation

**Debugging & Troubleshooting:**

- [x] SAML response viewer (super admin only): shows raw SAML XML for failed authentications
- [x] Debug log stores failed SAML authentications with decoded XML
- [x] Troubleshooting tips shown based on error type
- [x] Debug entries auto-cleaned after 24 hours

**Technical Implementation:**

- Provider-specific attribute mapping presets in `app/schemas/saml.py`
- SLO endpoints in `app/routers/saml.py` and `app/routers/auth.py`
- Certificate rotation with overlap period in `app/services/saml.py`
- SAML debug storage in `app/database/saml.py`
- Migrations: `00023_saml_certificate_rotation.sql`, `00024_saml_debug_storage.sql`

**Notes:**

- IdP-initiated SLO is "best effort" due to cookie-based sessions (cannot server-side invalidate)
- Documentation page deferred (troubleshooting tips embedded in debug detail view)

---

## Password Retention & Controlled Deactivation

**Status:** Complete

**User Story:**
As an admin
I want user passwords preserved when assigning users to IdPs and controlled reactivation flows
So that users have a recovery path if their IdP connection is severed

**Completed Work:**

**Password Retention:**

- [x] When a user is assigned to an IdP, password hash is PRESERVED (not wiped)
- [x] When a user authenticates via SAML, password hash is PRESERVED
- [x] When a domain is bound to an IdP (bulk assignment), passwords are PRESERVED
- [x] Password is NOT usable while user has an IdP assigned (IdP authentication is mandatory)

**IdP Disconnection & Deactivation:**

- [x] When a user is disconnected from an IdP (saml_idp_id → NULL):
  - User is automatically inactivated
  - All emails are unverified (existing behavior)
  - Password hash remains intact
- [x] Moving a user from one IdP to another does NOT trigger deactivation (existing behavior)

**Reactivation Flows:**

- [x] Admin reactivation (existing): Admin/Super Admin can reactivate any inactivated user
- [x] Super Admin self-reactivation (NEW):
  - Super Admins can initiate self-reactivation from login page
  - Must prove email possession (6-digit code flow)
  - After code verification, if user is inactivated super admin → auto-reactivate
  - Event logged: `super_admin_self_reactivated`
- [x] Regular users/admins cannot self-reactivate (must contact an admin)

**Password Setup on Reactivation:**

- [x] If reactivated user has a password → can immediately log in with password
- [x] If reactivated user has NO password (JIT-provisioned):
  - After reactivation, admin triggers "set password" invite email
  - User sets password via existing `/set-password` flow
  - OR admin assigns them to a new IdP

**UI Changes:**

- [x] Login page for inactivated super admins shows "Reactivate Account" option
- [x] Option only appears AFTER email possession is proven
- [x] User management page shows password status indicator (has password / no password)
- [x] Warning when disconnecting users without passwords

**Technical Implementation:**

- Removed `wipe_user_password()` calls in `app/services/saml.py`
- Modified `assign_user_idp()` to preserve password
- Modified `bind_domain_to_idp()` to preserve passwords in bulk
- Modified SAML auth flow to preserve password on first SAML login
- Added `self_reactivate_super_admin()` service function
- Added password status tracking in user detail views
- Modified `app/routers/auth.py` for super admin self-reactivation flow
- Added comprehensive unit and integration tests

**Effort:** M
**Value:** High (Security - recovery path, operational resilience)

---

## Test Suite Performance: Unit Test Pilot (Users Module)

**Status:** Complete

**User Story:**
As a developer
I want unit tests that mock their dependencies
So that the test suite runs faster and failures are isolated to specific layers

**Completed Work:**

**Infrastructure:**

- [x] Added pytest markers (`unit`, `integration`) to `pytest.ini`
- [x] Added factory fixtures to `tests/conftest.py` (`make_requesting_user`, `make_user_dict`, `make_email_dict`)
- [x] Created `tests/integration/` directory with auto-marking `conftest.py`

**Pilot Files Refactored:**

- [x] `test_services_users.py` → 44 unit tests with mocked database layer
- [x] `test_api_users.py` → 44 unit tests with mocked service layer
- [x] Original tests preserved in `tests/integration/` for regression safety

**Results:**

| Test Suite | Count | Time |
|------------|-------|------|
| Unit tests (`pytest -m unit`) | 88 | **2.42s** |
| Integration tests (`pytest -m integration`) | 95 | **7.40s** |

**Key Patterns Established:**

1. Service tests: Patch `services.<module>.database`
2. API tests: Use `app.dependency_overrides` + patch `routers.api.v1.<module>.<service>_service`
3. Authorization (403) tests kept in integration tests (dependency override exceptions don't route through handlers)

**Next Steps:** See "Complete Unit Test Refactoring" item in BACKLOG.md for remaining work.

**Effort:** M (pilot scope)
**Value:** High (established patterns for full rollout)

---

## Email Possession Verification (Anti-Enumeration)

**Status:** Complete

**User Story:**
As a platform operator
I want users to prove email possession before revealing any account information
So that attackers cannot enumerate valid email addresses or discover authentication methods

**Acceptance Criteria:**

**Email Verification Flow:**

- [x] Login page shows ONLY email input field - no "Sign in with SSO" button visible
- [x] On email submit, system sends 6-digit code to the provided email address
- [x] Code is NOT stored in database - instead, an encrypted payload is stored in a browser cookie containing:
  - The email address
  - The 6-digit code (hashed)
  - Expiration timestamp (5 minutes from send)
  - Tenant ID
- [x] User enters 6-digit code on verification page
- [x] System validates code against encrypted cookie payload
- [ ] Rate limiting: max 3 code requests per email per 15 minutes (deferred to separate security initiative)

**Post-Verification Routing:**

- [x] After successful code verification, system determines auth route:
  - User exists + has IdP assigned → redirect to IdP
  - User exists + password-only → show password form
  - User does NOT exist → show "No account found for this email" message
- [x] "No account" message is safe to show because user proved email ownership
- [x] Inactivated users see inactivation message (they proved ownership, safe to show)

**Device Trust Cookie:**

- [x] On successful verification, set long-lived "email verified" cookie (30 days, HttpOnly, Secure)
- [x] Cookie contains: encrypted email + verification timestamp
- [x] If valid cookie exists for the entered email, skip code verification step
- [x] Cookie survives browser closing (persistent, not session)
- [x] Separate cookie per email address (user may have multiple emails)

**Security Properties:**

- [x] No information leakage before email verification
- [x] Cannot tell if email exists without code
- [x] Cannot tell if user uses IdP or password without code
- [x] Cannot tell if account is inactivated without code

**Technical Implementation:**

- New endpoint: `POST /login/send-code` - sends verification code
- New endpoint: `GET /login/verify` - shows code entry form
- New endpoint: `POST /login/verify-code` - validates code, routes to auth method
- New endpoint: `POST /login/resend-code` - resends verification code
- New template: `email_verification.html` - code entry form
- Modified: `app/routers/auth.py` - restructured login flow
- New utility: `app/utils/email_verification.py` - cookie encryption/decryption
- Fernet symmetric encryption for cookie payloads
- Email template for 6-digit code
- Removed all SSO buttons from login page

**Test Coverage:**

- 29 unit tests for email_verification.py utilities
- 14 integration tests for new auth endpoints
- All existing tests updated for new behavior

**Effort:** L
**Value:** High (Security - prevents user enumeration)

---

## SAML IdP Simulator for Development

**Status:** Complete

**User Story:**
As a developer
I want a local SAML IdP simulator in the dev docker-compose
So that I can manually test and debug SAML authentication flows without external dependencies

**Acceptance Criteria:**
- [x] SimpleSAMLphp IdP simulator added to docker-compose.yml
- [x] IdP accessible at a predictable URL (e.g., https://localhost:8443 or via nginx proxy)
- [x] Documentation on how to configure the app to use the local IdP
- [x] IdP metadata URL documented for easy import into the SAML IdP configuration UI

**Technical Implementation:**
- Docker image: `kenchan0130/simplesamlphp:1.19.9`
- Ports: 8080 (HTTP), 8443 (HTTPS)
- Config files: `simplesamlphp/authsources.php`, `simplesamlphp/saml20-idp-hosted.php`
- Documentation: `docs/saml-idp-simulator.md`

**Effort:** S
**Value:** Medium

**Note:** SimpleSAMLphp was later removed from docker-compose in favor of SAMLtest.id (hosted service). See BACKLOG.md "SAML Smoketest" item for the replacement testing approach.

---

## SAML Upstream IdP Support - Phase 2: JIT Provisioning & Connection Testing

**Status:** Complete

**User Story:**
As a super admin
I want users to be automatically created when they authenticate via SAML, and I want to test my IdP configuration before enabling it
So that I can confidently deploy SSO without pre-provisioning users and catch configuration errors early

**Acceptance Criteria:**

**Just-in-Time (JIT) User Provisioning:**

- [x] Per-IdP setting: `jit_provisioning` (default: disabled)
- [x] When enabled: users authenticating via SAML who don't exist are automatically created
- [x] JIT-created users:
  - Email extracted from SAML assertion (configurable claim name)
  - First name, last name from SAML attributes (with defaults: "SAML User")
  - Role: Member (all JIT users get member role)
  - Password: NULL (SAML-only authentication)
  - MFA: Set up after first login if `require_platform_mfa` is true
  - saml_idp_id: Links user to provisioning IdP
- [x] When disabled: SAML login fails if user doesn't exist (must be pre-provisioned)
- [x] `user_created_jit` event logged with IdP and attribute details
- [x] IdP form shows JIT toggle with warning: "When enabled, users from this IdP will be automatically created"

**IdP Connection Testing:**

- [x] "Test Connection" button on IdP edit page
- [x] Initiates SAML flow in new window/popup
- [x] On success: Shows parsed assertion details (NameID, mapped attributes, raw attributes)
- [x] On failure: Shows detailed error (signature validation failed, certificate expired, etc.) with common causes
- [x] Test results do not create session or provision user
- [x] Test mode indicated via `RelayState` parameter (`__test__:{idp_id}`) to distinguish from real logins

**Technical Implementation:**

- `app/services/saml.py`: JIT provisioning logic in `authenticate_via_saml()`, `_jit_provision_user()` helper, `process_saml_test_response()` function
- `app/database/saml.py`: `set_user_idp()` function to link JIT users to IdPs
- `app/routers/saml.py`: Test connection endpoint, ACS test mode handling, JIT form field processing
- `app/schemas/saml.py`: `SAMLTestResult` schema for test response
- `app/templates/saml_idp_form.html`: JIT checkbox in settings, Test Connection button
- `app/templates/saml_test_result.html`: New template showing test results

**Testing:**

- 6 JIT provisioning tests covering creation, disabled behavior, IdP linking, verified email, default names, existing users
- 4 connection testing tests covering success, signature error, expired error, IdP not found

**Effort:** M
**Value:** High (Enterprise provisioning, Setup confidence)

---

## SAML Upstream IdP Support - Phase 3: Domain Routing & User Assignment

**Status:** Complete

**User Story:**
As a super admin
I want to link privileged domains to specific SAML IdPs and assign individual users to IdPs
So that users are automatically routed to the correct identity provider based on their email domain or admin assignment

**Acceptance Criteria:**

**Domain-to-IdP Binding:**

- [x] New `saml_idp_domain_bindings` table links privileged domains to IdPs
  - Fields: `domain_id` (FK to `tenant_privileged_domains`), `idp_id` (FK to `saml_identity_providers`)
  - Constraint: Each domain can only be bound to one IdP
- [x] In IdP form: section to select which privileged domains route to this IdP
- [x] In privileged domain settings: show which IdP (if any) the domain is bound to
- [x] `saml_domain_bound` / `saml_domain_unbound` events logged

**Per-User IdP Assignment:**

- [x] User edit form includes "Authentication Method" dropdown:
  - "Automatic (based on email domain)" - default, uses domain routing
  - List of enabled IdPs - forces user to specific IdP
  - "Password only" - user authenticates with password, not SAML
- [x] `users.saml_idp_id` column stores admin-assigned IdP (NULL = automatic routing)
- [x] `user_saml_idp_assigned` event logged when assignment changes
- [x] User list/detail shows assigned IdP or "Automatic"

**Email-First Login Flow:**

- [x] Login page changes to email-first flow:
  1. User enters email address
  2. System determines auth method based on routing priority:
     - User has `saml_idp_id` set → Redirect to that IdP
     - User's email domain bound to IdP → Redirect to domain's IdP
     - Tenant has default IdP → Redirect to default IdP
     - User has password → Show password form
     - No user exists + domain bound to IdP → Redirect to IdP (for JIT)
     - No user exists + no IdP → Show "account not found" message
  3. Appropriate flow initiated (SAML redirect or password form)
- [x] Consistent UX: all users start with email entry, then diverge based on routing

**Technical Implementation:**

- Migration: Add `saml_idp_domain_bindings` table
- Update `app/routers/auth.py` for email-first flow
- Update `app/services/saml.py` with routing logic
- Update user edit template with IdP assignment dropdown

**Dependencies:**

- SAML Phase 2 complete
- Existing `tenant_privileged_domains` table

**Effort:** M
**Value:** High (Enterprise-grade IdP routing)

---

## SAML Upstream IdP Support - Phase 1: Core Infrastructure

**Status:** Complete

**User Story:**
As a super admin
I want to configure an external SAML 2.0 identity provider for my tenant
So that users can authenticate via enterprise SSO (Okta, Azure AD, Google Workspace, etc.)

**Acceptance Criteria:**

**Database & Configuration:**

- [x] New `saml_sp_certificates` table stores one SP signing certificate per tenant
  - Fields: `tenant_id`, `certificate_pem`, `private_key_pem_enc` (encrypted), `expires_at`, `created_by`
- [x] New `saml_identity_providers` table stores IdP configurations
  - Fields: `tenant_id`, `name`, `provider_type` (okta/azure_ad/google/generic)
  - IdP metadata: `entity_id`, `sso_url`, `slo_url` (optional), `certificate_pem`
  - SP metadata: `sp_entity_id`, `sp_acs_url` (auto-generated per IdP)
  - Settings: `is_enabled`, `is_default`, `require_platform_mfa`, `jit_provisioning`
  - Attribute mapping: `attribute_mapping` (JSONB for email, first_name, last_name claim names)
- [x] Add `saml_idp_id` column to `users` table for per-user IdP override
- [x] RLS policies enforce tenant isolation on all SAML tables
- [x] `SAML_KEY_ENCRYPTION_KEY` environment variable for SP private key encryption

**SAML Endpoints:**

- [x] `GET /saml/metadata` returns SP metadata XML for the tenant
- [x] `GET /saml/login/{idp_id}` generates AuthnRequest and redirects to IdP SSO URL
- [x] `POST /saml/acs` (Assertion Consumer Service) validates SAML response and creates session
- [x] SAML signatures always validated; unsigned assertions rejected
- [x] `NotOnOrAfter` checked to prevent replay attacks

**Admin UI - IdP Management:**

- [x] New "Identity Providers" page under Admin navigation (super admin only)
- [x] List view showing: Name, Provider Type, Status (Enabled/Disabled), Default badge, Actions
- [x] "Add Identity Provider" button opens creation form
- [x] Creation/edit form includes:
  - Basic: Name, Provider Type dropdown (Okta, Azure AD, Google Workspace, Generic SAML 2.0)
  - IdP Configuration: Entity ID, SSO URL, SLO URL (optional), Certificate (paste PEM)
  - OR: Import from Metadata URL (fetches and parses IdP metadata XML)
  - Attribute Mapping: Configurable claim names for email, first_name, last_name
  - Settings: Enable/Disable toggle, Set as Default toggle
- [x] SP Metadata section displays: Entity ID, ACS URL, Download Metadata XML button
- [x] Delete IdP with confirmation dialog
- [x] Event logging for all IdP create/update/delete operations

**Basic Login Integration:**

- [x] Login page shows "Sign in with SSO" option when tenant has enabled IdPs
- [x] If tenant has exactly one enabled IdP, clicking SSO initiates that IdP flow
- [x] If tenant has multiple IdPs, show IdP selection (name + provider type icon)
- [x] After successful SAML authentication, user session created (existing session mechanism)
- [x] `user_signed_in_saml` event logged with IdP details

**Technical Implementation:**

- Library: `python3-saml` (OneLogin's well-maintained SAML library)
- New files: `app/database/saml.py`, `app/services/saml.py`, `app/routers/saml.py`, `app/schemas/saml.py`, `app/utils/saml.py`
- Templates: `saml_idp_list.html`, `saml_idp_form.html`, `saml_idp_select.html`, `saml_error.html`
- Migration: `db-init/00019_saml_identity_providers.sql`
- Background job: Daily IdP metadata URL refresh

**Testing:**

- 24 service layer tests covering SP certificate, IdP CRUD, login flow, metadata refresh
- 9 router tests covering admin UI and public SAML endpoints

**Effort:** L
**Value:** High (Enterprise SSO - Core IdP Feature)

---

## User Activity Tracking

**Status:** Complete

**User Story:**
As a platform operator
I want to track when users are actively using the system
So that I can understand usage patterns and identify inactive accounts without logging every single request

**Acceptance Criteria:**

**Sign-in Event Logging:**

- [x] Successful sign-ins logged to `event_logs` table (event_type: `user_signed_in`)
- [x] Sign-in defined as: user completing the authentication flow (not session refresh or token renewal)
- [x] Failed sign-in attempts are NOT logged (requires rate-limiting first - future scope)
- [x] Sign-in event also updates `last_activity_at` on the user record

**Last Activity Tracking:**

- [x] New `user_activity` table with `last_activity_at` timestamp (separate from users table)
- [x] Any service layer write operation updates `last_activity_at` (via `log_event`)
- [x] Any service layer read operation updates `last_activity_at` only if 3+ hours have passed (rolling window)
- [x] Activity check uses Memcached to avoid constant DB reads for the 3-hour check
- [x] Cache key pattern: `user_activity:{user_id}` with 3-hour TTL
- [x] If cache miss or expired, check DB and update if needed

**Implementation Pattern:**

- [x] Service layer tracking via `track_activity()` function
- [x] Write operations tracked automatically via `log_event()` integration
- [x] Read operations require explicit `track_activity()` calls
- [x] Synchronous updates (tiny latency, rare writes due to caching)
- [x] Memcached as new infrastructure dependency

**Technical Implementation:**

- Database migration: New `user_activity` table (FK to users, CASCADE delete)
- Memcached setup in Docker Compose
- Cache utility module (`app/utils/cache.py`)
- Activity tracking service (`app/services/activity.py`)
- Integration with event logging (`app/services/event_log.py`)
- Sign-in event logging in MFA verification flow

**Effort:** M
**Value:** High (Usage Analytics, Account Lifecycle Management)

---

## Service Layer Event Logging

**Status:** Complete

**User Story:**
As a platform operator
I want all write operations in the service layer to be logged to a database table
So that I have a complete audit trail for compliance, debugging, and future user-facing activity history

**Acceptance Criteria:**

**Core Logging:**

- [x] New `event_logs` table captures all service layer write operations
- [x] Each log entry includes: `tenant_id`, `actor_user_id`, `artifact_type`, `artifact_id`, `event_type`, `metadata` (JSON), `created_at`
- [x] Event types are descriptive strings (e.g., `user_created`, `email_updated`, `mfa_enabled`) - not DB-enforced enums
- [x] Artifact type identifies the entity (e.g., `user`, `privileged_domain`, `tenant_settings`)
- [x] Metadata field captures context-specific details as JSON (optional per event)
- [x] Logging is synchronous (write completes before service method returns)

**Actor Tracking:**

- [x] All events track the `actor_user_id` (who performed the action)
- [x] System-initiated actions (background jobs, automated processes) use a predefined UUID constant (e.g., `SYSTEM_ACTOR_ID`)
- [x] System actor UUID is defined in code, not a real user row

**Implementation Pattern:**

- [x] Logging helper/utility that service functions call after successful writes
- [x] All existing service layer write operations are instrumented
- [x] Culture: "If there is a write, there is a log" - bulk writes produce multiple log entries

**Retention:**

- [x] Logs retained indefinitely
- [x] Logs reference user UUIDs - anonymization happens on user record, not logs

**Out of Scope:**

- UI to browse/search logs
- API endpoints to query logs
- User-facing activity history display
- Read operation logging

**Effort:** M
**Value:** High (Audit/Compliance Foundation)

---

## User List Filtering & Sorting Enhancements

**Status:** Complete

**User Story:**
As an admin
I want to filter the user list by role and status, and sort by status
So that I can quickly find specific groups of users (e.g., all inactive admins)

**Acceptance Criteria:**

**Role Filtering:**

- [x] Add multi-select role filter with options: Member, Admin, Super Admin
- [x] Filter persists in URL query params (e.g., `?role=admin,super_admin`)
- [x] Role filter combines with existing text search
- [x] Clear filter option to reset role selection

**Status Filtering:**

- [x] Add multi-select status filter with options: Active, Inactivated, Anonymized
- [x] Filter persists in URL query params (e.g., `?status=active,inactivated`)
- [x] Status filter combines with existing text search and role filter
- [x] Clear filter option to reset status selection

**Status Sorting:**

- [x] Add "Status" to allowed sort fields in user list
- [x] Status sort order: Active → Inactivated → Anonymized (or reverse for desc)

**UI/UX:**

- [x] Filter controls displayed above user list table
- [x] Visual indication when filters are active
- [x] Filters and search work together (AND logic)
- [x] Pagination respects active filters
- [x] Total count updates to reflect filtered results

**API Layer:**

- [x] `list_users_raw` service function accepts optional `roles` and `statuses` filter params
- [x] `count_users` function updated to support role and status filters
- [x] Database queries efficiently filter by role and status

**Documentation (Critical):**

- [x] Document API query parameter semantics for combining search, filters, sorting, and pagination
- [x] Include examples: `?search=john&role=admin,member&status=active&sort=status&order=asc&page=2&size=25`
- [x] Document filter value formats (comma-separated for multi-select)
- [x] Document interaction between filters (AND logic) and pagination behavior
- [x] Add inline code comments explaining filter/sort query construction

**Testing (Comprehensive):**

- [x] Unit tests for service layer filter combinations (role only, status only, role+status)
- [x] Unit tests for filter + search combinations
- [x] Unit tests for filter + sort combinations (including status sorting)
- [x] Integration tests for pagination with active filters (correct counts, page boundaries)
- [x] Edge case tests: empty filters, invalid filter values, all filters active simultaneously
- [x] Test that URL query params round-trip correctly through the UI

**Effort:** S
**Value:** High

---

## API-First Architecture: RESTful API Layer with OpenAPI Specification

**Status:** Complete

**User Story:**
As a developer integrating with the identity platform
I want a comprehensive RESTful API with OAuth2 authentication and OpenAPI specification
So that I can build custom applications and integrations without relying on server-side rendered pages

**Acceptance Criteria:**

**API Coverage:**
- [x] All existing post-authentication functionality exposed via RESTful APIs
- [x] User management endpoints (CRUD operations)
- [x] User profile endpoints (view/edit profile)
- [x] Settings management endpoints (privileged domains, tenant settings)
- [x] Role and permission management endpoints
- [x] Email management endpoints (add, verify, remove, set-primary for user and admin)
- [x] MFA management endpoints (TOTP setup, email MFA, backup codes, admin reset)
- [x] Pre-authentication flows (login, registration) remain server-side rendered (excluded from API)
- [x] Email verification flows remain server-side rendered (excluded from API)

*Note: Future features (organizational structure, ad-hoc groups) will be API-first by default.*

**Authentication & Authorization:**
- [x] OAuth2 authentication for API access
- [x] Support for B2B client-credentials flow
- [x] API endpoints respect existing role-based permissions (Super Admin, Admin, User)
- [x] Token-based authentication for all API requests
- [x] Secure token storage and refresh mechanisms

**OpenAPI Specification:**
- [x] Auto-generated OpenAPI 3.x specification from FastAPI
- [x] Bare-bones spec (endpoint paths, methods, request/response schemas)
- [x] No detailed descriptions or examples required (minimal documentation)
- [x] Specification available at `/openapi.json` endpoint
- [x] Interactive API docs available at `/docs` (Swagger UI)
- [x] Specification covers all implemented API endpoints
- [x] Exclude HTML/server-rendered endpoints from OpenAPI spec (only include `/api/v1/*` routes)
- [x] Document security/authentication requirements per endpoint in OpenAPI spec

**API Testing Strategy:**
- [x] Tests cover: request/response schemas, HTTP status codes, authentication requirements
- [x] Tests verify role-based permission enforcement for each endpoint
- [x] Tests ensure tenant isolation for multi-tenant endpoints
- [x] Integration with existing pytest test suite

**Architecture:**
- [x] Existing server-side rendered pages remain untouched (no breaking changes)
- [x] New API routes organized under `/api/v1/` prefix
- [x] API responses return JSON with consistent error handling
- [x] Proper HTTP status codes for all responses
- [x] Tenant isolation maintained for all API endpoints (via `tenant_id`)

**Out of Scope:**
- SDK generation (can be done separately using OpenAPI spec)
- Rate limiting
- CORS configuration (handled at server/reverse proxy level)
- Migration of existing server-side pages to API-driven SPAs
- Detailed API documentation or examples
- GraphQL or other API paradigms
- Spec-driven testing (automated test generation, contract testing, schemathesis/dredd)
- CI/CD integration for spec-based tests

**Technical Implementation:**
- New router module: `app/routers/api/` directory structure
- API versioning: `/api/v1/` prefix for all endpoints
- OAuth2 implementation using FastAPI's security utilities
- Token management database tables (migrations required)
- Leverage existing `app/database/` modules for data access
- Update FastAPI app configuration for OpenAPI generation
- API-specific error handling and response formatting
- Spec-based testing framework setup in `tests/api/` directory
- Test configuration to load and parse OpenAPI spec
- Test fixtures for OAuth2 token generation and multi-role testing

**Dependencies:**
- FastAPI OAuth2 utilities (already available)
- Potential OAuth2 library (e.g., `authlib` or `python-jose`)
- Spec-based testing library (e.g., `schemathesis`, `dredd`, or custom pytest solution)

**Effort:** XL (3-4 weeks for complete coverage including testing)
**Value:** High (Foundation for Ecosystem Growth & Integrations)

**Notes:**
- This creates a parallel API layer alongside existing server-side pages
- Future epic can migrate pages to consume these APIs
- OpenAPI spec enables third-party SDK generation
- Spec-driven testing ensures API contract stability
- Maintains backward compatibility with current functionality
- **Detailed implementation plan:** See [docs/api-implementation-plan.md](docs/api-implementation-plan.md)

---

## User Inactivation & GDPR Anonymization

**Status:** Complete

**User Story:**
As a platform operator
I want to inactivate users (with optional GDPR anonymization)
So that I can disable access for departed users while maintaining audit trails, and comply with right-to-be-forgotten requests

**Acceptance Criteria:**

**User Inactivation:**

- [x] Add `is_inactivated` boolean column to users table (default: false)
- [x] Inactivated users cannot sign in (blocked at authentication layer)
- [x] Inactivated users retain all their data (email, name, etc.)
- [x] Admins can reactivate inactivated users
- [x] Inactivated users still appear in logs and user lists (marked as inactivated)

**GDPR Anonymization:**

- [x] Add `is_anonymized` boolean column to users table (default: false)
- [x] Anonymization = inactivation + PII scrubbed
- [x] Anonymized users have email, name, and other PII removed/replaced
- [x] Anonymized users cannot be reactivated (irreversible)
- [x] UUID is preserved - logs continue to reference the anonymized user record
- [x] Anonymized user record displays as "[Anonymized User]" or similar in UI contexts

**Admin Controls:**

- [x] Admin UI to inactivate/reactivate users
- [x] Admin UI to anonymize users (with confirmation - irreversible)
- [x] Clear visual distinction between inactivated vs anonymized users

**Audit Trail Integrity:**

- [x] Event logs retain user UUID references regardless of inactivation/anonymization
- [x] Looking up an anonymized user by UUID returns the anonymized record (not null)

**Out of Scope:**

- Self-service GDPR deletion requests
- Automated anonymization workflows
- Bulk inactivation/anonymization

**Effort:** M
**Value:** High (Compliance/GDPR Foundation)

---

## On-Prem Email Reliability & MFA Bypass

**Status:** Complete

**User Story:**
As an on-prem operator
I want flexible email delivery options and an optional MFA bypass mode
So that I can deploy in restrictive network environments where SMTP ports are blocked, and simplify local development/testing

**Context:**
On-prem and some cloud environments block outbound SMTP ports (25, 465, 587). This makes email-based features (OTP codes, invitations, notifications) non-functional. HTTP-based email APIs (Resend, SendGrid) work over port 443 and bypass these restrictions.

**Acceptance Criteria:**

**MFA Bypass Mode:**

- [x] New `BYPASS_OTP` environment variable (default: false)
- [x] When `BYPASS_OTP=true`, any valid 6-digit code (000000-999999) passes MFA verification
- [x] Bypass applies to all MFA methods: email OTP and TOTP
- [x] Backup codes are NOT bypassed (they remain functional for account recovery)
- [x] Clear warning logged at startup when bypass mode is enabled
- [x] Documentation warns this is for dev/on-prem only, never production

**Pluggable Email Backends:**

- [x] Abstract email backend interface supporting multiple providers
- [x] `EMAIL_BACKEND` environment variable to select provider: `smtp`, `resend`, `sendgrid`
- [x] SMTP backend (existing implementation, refactored)
- [x] Resend backend (HTTPS API via `resend` Python package)
- [x] SendGrid backend (HTTPS API via `sendgrid` Python package)
- [x] Backend-specific configuration: `RESEND_API_KEY`, `SENDGRID_API_KEY`
- [x] Graceful error handling with logging for all backends
- [x] All existing email functions work unchanged (interface preserved)

**Configuration Updates:**

- [x] Update `.env.dev.example` with new variables (documented, commented)
- [x] Update `.env.onprem.example` with recommended on-prem settings
- [x] Update `app/settings.py` to load new environment variables

**Out of Scope:**

- AWS SES backend (can be added later)
- Console/log backend for debugging
- Webhook-based email delivery
- Password-based authentication alternative

**Effort:** M
**Value:** High (Unblocks On-Prem Deployment)

---

## Service Layer Architecture

**Status:** Complete

**User Story:**
As a developer working on Loom
I want a service layer that sits between routes and the database layer
So that I can develop API-first and then compose server-rendered pages using the same models and operations without
duplication or HTTP overhead

**Architecture:**

```
[HTML Routes] → [Service Layer] → [Database Layer]
[API Routes]  → [Service Layer] → [Database Layer]
```

**Acceptance Criteria:**

**Service Layer Design:**

- [x] New `app/services/` directory with domain-organized modules
- [x] Service functions return Pydantic models (the API schemas from `app/schemas/`)
- [x] Service layer handles **authorization** (can this user do this action?)
- [x] Service layer handles business logic (validation, side effects like emails)
- [x] Service layer is HTTP-agnostic (no knowledge of requests/responses)
- [x] Routes handle **authentication** only (who is this user?) and inject requesting_user

**Exception Handling:**

- [x] Custom exception hierarchy in `app/services/exceptions.py`
- [x] Exceptions are HTTP-agnostic but translatable (include error code, message, optional details)
- [x] API routes translate service exceptions to HTTPException
- [x] HTML routes translate service exceptions appropriately (flash messages, error pages)

**API Routes Refactored:**

- [x] API routes become thin wrappers around service calls
- [x] API routes handle: HTTP parsing, authentication deps, response formatting
- [x] All business logic moved out of API routes into service layer

**HTML Routes Refactored:**

- [x] HTML routes call service layer (same as API)
- [x] HTML routes receive typed Pydantic models
- [x] No direct database layer calls from HTML routes

**Service Modules Created:**

- [x] `services/settings.py` - Tenant settings, privileged domains
- [x] `services/users.py` - User CRUD, profile management
- [x] `services/emails.py` - Email management (add, verify, remove, set-primary)
- [x] `services/mfa.py` - MFA setup, verification, backup codes
- [x] `services/oauth2.py` - OAuth2 clients, authorization codes, tokens

**Authorization Model:**

- **Authentication** (route layer): FastAPI dependencies identify the caller
- **Authorization** (service layer): Service checks role, ownership, tenant isolation

**Effort:** XL
**Value:** High (Enables true API-first development, eliminates duplication, improves maintainability)

---

## Admin Event Log Viewer & Export

**Status:** Complete

**User Story:**
As an admin or super admin
I want to view all system events in a paginated list and export them
So that I can audit activity, investigate issues, and maintain compliance records

**Acceptance Criteria:**

**Event Log Viewer:**

- [x] New page accessible to Admins and Super Admins only
- [x] Paginated list of events (newest first)
- [x] Columns displayed: timestamp, actor (user name), event type, artifact type, artifact ID
- [x] Clicking an event row opens a detail view showing full metadata JSON
- [x] No filtering for MVP (future enhancement)

**Export Functionality:**

- [x] "Export All Events" button triggers a background job
- [x] Export includes all events as a zipped JSON file
- [x] Email sent to initiating user when export is ready
- [x] Download available via a dedicated exports page
- [x] Exports auto-deleted after 24 hours (both DB record and file)
- [x] Worker container runs cleanup check once per hour to delete expired exports
- [x] Storage: DigitalOcean Spaces if configured, local filesystem fallback

**Background Job Infrastructure:**

- [x] New `bg_tasks` table (no RLS - system table for cross-tenant polling)
- [x] Schema: `id`, `tenant_id`, `job_type`, `payload` (JSON), `status`, `created_by`, `created_at`, `started_at`, `completed_at`, `error`
- [x] Separate worker container (same image, different entrypoint)
- [x] Worker polls every 10 seconds for pending jobs
- [x] Job handler registry: jobs only execute if a handler is registered for that `job_type`
- [x] Worker sets `SET LOCAL app.tenant_id` before executing job handlers (RLS respected in handlers)

**Dependencies:**

- Service Layer Event Logging (must exist first)

**Effort:** L
**Value:** High (Audit/Compliance)

---

## Background Jobs UI Refinement & Navigation Restructuring

**Status:** Complete

**User Story:**
As a user of the platform
I want to view and manage all my background jobs in one place
So that I can track progress, access outputs, download results, and clean up completed tasks

**Acceptance Criteria:**

**Navigation Changes:**

- [x] Merge "Settings" and "Administration" tabs into a single "Admin" menu with subsections
- [x] Move "Exports" page from admin area to User menu
- [x] Rename "Exports" to "Background Jobs"

**Background Jobs Page:**

- [x] Display job list with columns: Checkbox, Job Type, Status, Output, Download
- [x] Checkbox appears only for completed (success/failed) jobs
- [x] Status column shows: Requested / Ongoing / Completed / Failed (includes timestamp info)
- [x] Output column shows link to view output if available, otherwise "N/A"
- [x] Download column shows link to download file if available and < 24 hours old, otherwise "N/A"
- [x] Downloads older than 24 hours show "File expired" (no file existence check)
- [x] Multi-select deletion via checkboxes (only for completed jobs)
- [x] "Delete Selected" button removes checked job records
- [x] Page polls every 10 seconds while any job is in Requested/Ongoing state
- [x] Polling stops when all visible jobs are completed/failed
- [x] No email notifications sent on job completion

**Output Display:**

- [x] Clicking output link navigates to dedicated page showing raw text output
- [x] Output page shows job metadata (type, status, timestamps) above output content

**Database Changes:**

- [x] Output stored in `result` JSONB column (as `result.output`) - more flexible than separate TEXT column
- [x] Job records are NOT auto-deleted (persist indefinitely until user deletes)
- [x] Download files are cleaned up after 24 hours (existing behavior)

**Authorization:**

- [x] Users can only see and delete their own background jobs
- [x] Admins see only their own jobs (no tenant-wide job visibility)

**Technical Implementation:**

- Database migration: `00013_bg_tasks.sql` and `00014_export_files.sql`
- Service layer: `app/services/bg_tasks.py` with `list_user_jobs()`, `get_job_detail()`, `delete_jobs()`
- Router: `app/routers/account.py` with background jobs routes
- Templates: `account_background_jobs.html` and `account_job_output.html`
- Schemas: `app/schemas/bg_tasks.py` with `JobListItem`, `JobDetail`, `JobListResponse`
- Page registration: `app/pages.py` with `/account/background-jobs` hierarchy
- Auto-polling: JavaScript in template polls every 10s when `has_active_jobs` is true

**Effort:** M
**Value:** Medium (UX improvement, infrastructure foundation)

---

## Enhanced Event Log Audit Trail & Human-Readable Display

**Status:** Complete

**User Story:**
As a platform operator
I want event logs to capture comprehensive request metadata and display human-readable information
So that I can conduct thorough security investigations and understand who did what, from where, and on which accounts

**Acceptance Criteria:**

**Request Metadata Capture:**

- [x] Event logs capture IP address (remote_address) from request
- [x] Event logs capture full user agent string
- [x] Event logs parse device information from user agent (using user-agents library)
- [x] Event logs capture session ID hash (SHA-256 one-way hash for security)
- [x] IP extraction logic: X-Forwarded-For → X-Real-IP → request.client.host → null
- [x] Request metadata fields always present in metadata (even if null)
- [x] Background jobs and system events have null request metadata (no HTTP context)

**Metadata Storage & Deduplication:**

- [x] New `event_log_metadata` table with metadata_hash as primary key
- [x] Metadata hash computed via MD5 of deterministic JSON serialization
- [x] INSERT...ON CONFLICT DO NOTHING for efficient deduplication
- [x] event_logs references metadata via metadata_hash foreign key
- [x] Metadata combines 4 required request fields + optional custom event data
- [x] Hash computed on entire metadata object (request + custom fields)
- [x] Same request context reuses single metadata record
- [x] Different custom data creates different metadata records
- [x] Migration backfills existing events with system metadata (all nulls)

**Human-Readable Display:**

- [x] Event list shows artifact name when artifact_type='user'
- [x] Artifact name formatted as "First Last" from joined users table
- [x] Event detail shows actor as clickable link to user settings page
- [x] Event detail shows target user section for user artifacts (name, email, link)
- [x] Event detail displays request context section: IP, user agent, device, session hash
- [x] Event detail maintains full metadata display (request fields + custom data)

**Service & Database Layer:**

- [x] RequestingUser TypedDict includes optional request_metadata field
- [x] dependencies.py extracts request metadata using new utility module
- [x] Web routes pass Request object, API routes pass None for request_metadata
- [x] log_event() accepts request_metadata parameter
- [x] log_event() merges request_metadata + custom metadata into combined dict
- [x] log_event() computes hash on combined metadata
- [x] create_event() performs metadata deduplication and foreign key storage
- [x] list_events() and get_event_by_id() LEFT JOIN metadata and user tables
- [x] EventLogItem schema includes extracted convenience fields for templates
- [x] All ~20 service layer log_event() calls updated to pass request_metadata

**Technical Implementation:**

- Database migration: `00015_event_log_metadata.sql`
- New utility module: `app/utils/request_metadata.py`
- Updated: `app/services/types.py`, `app/dependencies.py`
- Updated: All routers (admin, users, account, settings, API v1)
- Updated: `app/services/event_log.py`, `app/database/event_log.py`
- Updated: `app/schemas/event_log.py`
- Updated: All services with log_event() calls (users, emails, settings, oauth2, bg_tasks)
- Updated: `app/templates/admin_events.html`, `app/templates/admin_event_detail.html`
- Added dependency: `user-agents = "^2.2.0"`

**Dependencies:**

- Service Layer Event Logging (required)
- User Activity Tracking (for last_activity_at in future)

**Effort:** L
**Value:** High (Security, Compliance, Audit Trail)

---

## User Activity Display & Automatic Inactivation System

**Status:** Complete

**User Story:**
As a platform operator
I want to see user activity status and automatically inactivate dormant users
So that I can maintain security hygiene and ensure only active users have access to the system

**Acceptance Criteria:**

**User List Enhancements:**

- [x] `last_activity_at` column added to user list API response
- [x] `last_activity_at` displayed in user list UI as absolute timestamp (localized to viewing user's timezone)
- [x] `last_activity_at` is sortable (ascending/descending) like existing columns
- [x] `last_login` removed from frontend user list view (retained in API for backwards compatibility)

**Tenant Inactivity Settings:**

- [x] New tenant setting: inactivity threshold with options: Indefinitely (disabled), 14 days, 30 days, 90 days
- [x] Setting added to existing `/settings/tenant-security` page
- [x] Default value: Indefinitely (no auto-inactivation)

**Automatic Inactivation:**

- [x] Daily cron job checks all active users against inactivity threshold
- [x] Comparison uses `last_activity_at`, falling back to `created_at` if null
- [x] Users exceeding threshold are set to inactive status
- [x] Upon inactivation: all OAuth tokens for that user are invalidated
- [x] Upon inactivation: all web sessions for that user are invalidated
- [x] Inactivation logged to event_logs (when event logging is available)

**Reactivation Request Flow:**

- [x] Inactivated users attempting to log in see a "Request Reactivation" option
- [x] User must complete email verification before request is submitted
- [x] New `reactivation_requests` table: user_id, requested_at, decided_by, decided_at
- [x] Upon request submission: email sent to all Admins and Super Admins in tenant
- [x] Email contains CTA linking to reactivation requests list
- [x] Reactivation requests list page (Admin/Super Admin only) shows pending requests
- [x] Admins can approve or deny each request individually
- [x] Approved: user status set to active, request removed from table, user can log in normally
- [x] Denied: request removed from table, user cannot request reactivation again via app
- [x] To track denial: add `reactivation_denied_at` timestamp column on users table
- [x] Users with `reactivation_denied_at` set cannot submit new requests (must contact org out-of-band)

**Max Session Length Change Behavior:**

- [x] When max session length setting is changed, all active sessions tenant-wide are invalidated immediately
- [x] Warning displayed before saving: "Changing this setting will immediately log out all users"
- [x] User must confirm before change takes effect

**Additional Work (Beyond Original Spec):**

- [x] Email notification to user when reactivation request is approved
- [x] Email notification to user when reactivation request is denied
- [x] Email notification to admins/super admins when a new reactivation request is submitted
- [x] Reactivation history page showing previously decided requests (approved/denied)
- [x] Full REST API for reactivation management (`/api/v1/reactivation-requests`)
  - GET list pending requests
  - GET `/history` list decided requests
  - POST `/{id}/approve` approve a request
  - POST `/{id}/deny` deny a request
- [x] Event log metadata includes user_id for all reactivation events (UUID only, no PII for GDPR compliance)
- [x] Request metadata (IP, user agent, device) captured for reactivation requests

**Dependencies:**

- User Activity Tracking (for `last_activity_at` column)
- Service Layer Event Logging (for audit trail)

**Effort:** XL
**Value:** High (Security, Compliance, Account Lifecycle)

---

## Complete Event Request Context (IP, User Agent, Device, Session)

**Status:** Complete

**User Story:**
As an administrator reviewing security events and audit logs
I want all events to include complete request context (IP address, user agent, device type, session ID)
So that I can trace security incidents, detect anomalous behavior, and maintain comprehensive audit trails

**Completed Work:**

**Contextvar-Based Automatic Context Propagation:**

- [x] Created `app/utils/request_context.py` with contextvar for request-scoped metadata
- [x] Created `app/middleware/request_context.py` to automatically extract and set context for all web requests
- [x] Added `RequestContextMiddleware` to app middleware stack in `app/main.py`
- [x] Updated `log_event()` in `app/services/event_log.py` to auto-read from contextvar
- [x] Added fail-safe: `RuntimeError` if context missing and not in system context

**Service Layer Cleanup:**

- [x] Removed `request_metadata=None` from 4 calls in `app/services/oauth2.py`
- [x] Removed `request_metadata=None` from 2 calls in `app/services/emails.py`
- [x] Removed `request_metadata=None` from 2 calls in `app/services/saml.py`
- [x] MFA service (7 calls) now automatically gets context from middleware

**System Context Escape Hatch:**

- [x] Added `system_context()` context manager for background jobs/CLI commands
- [x] Added autouse fixture in `tests/conftest.py` to wrap all tests in system context
- [x] Documented usage pattern for legitimate no-context scenarios

**Technical Implementation:**

- Middleware extracts IP, user agent, device, session hash at request start
- Contextvar propagates through async call chain automatically
- No service function signature changes needed
- All 1729 tests pass

Request metadata structure (from `app/utils/request_metadata.py`):
```python
{
    "remote_address": str,  # IP from X-Forwarded-For or X-Real-IP or client.host
    "user_agent": str,      # Full user agent string
    "device": str,          # Parsed: Mobile, Desktop, Tablet, Bot, or Unknown
    "session_id_hash": str  # SHA-256 hash of session ID (or null if no session)
}
```

**Effort:** M
**Value:** High (Security, Compliance, Audit Trail)

---

## Group System - Phase 3: User Experience

**Status:** Complete

**User Story:**
As a user
I want to see which groups I belong to
So that I understand my organizational context and access rights

**Completed Work:**

**Dashboard - My Groups:**

- [x] "My Groups" section on user dashboard
- [x] Shows all groups user is a member of (direct or via IdP)
- [x] Distinguishes between WeftID groups and IdP groups
- [x] Shows group hierarchy context (e.g., "Parent1, Parent2 > Group Name")

**Effective Membership:**

- [x] Calculate effective membership using closure table (user in child group = member of parent)
- [x] API endpoint to query effective memberships for a user (`GET /api/v1/users/{id}/effective-groups`)
- [x] API endpoint to query effective members of a group (`GET /api/v1/groups/{id}/effective-members`)

**Admin Enhancements:**

- [x] View effective members of a group (direct vs. inherited badges)
- [x] Filter/search groups (implemented in Phase 2)
- [x] Bulk user assignment to groups (multi-select form + API endpoint)

**Technical Implementation:**

- New database module: `app/database/groups/effective.py` (4 query functions using closure table)
- Added `bulk_add_group_members` to `app/database/groups/memberships.py`
- New schemas: `UserGroup`, `EffectiveMembership`, `EffectiveMember`, `BulkMemberAdd` and list variants
- New service functions: `get_my_groups`, `get_effective_memberships`, `get_effective_members`, `bulk_add_members`
- New API router: `app/routers/api/v1/users/groups.py`
- Updated dashboard, group detail page, and admin group router
- Event type: `group_members_bulk_added`
- Comprehensive tests across database, service, API, and router layers

**Effort:** S
**Value:** Medium (User visibility, API for downstream apps)

---

## SAML IdP: SP Lifecycle Management

**Status:** Complete

**Summary:** Added edit, enable/disable, and improved delete safeguards for downstream service providers. Admins can now update SP name, description, and ACS URL without recreating the SP. SPs can be temporarily disabled (rejecting SSO requests) while preserving group assignments. Delete confirmation now shows the number of group assignments that will be lost.

**Completed Work:**

**Edit SP Configuration:**

- [x] Edit SP name, description, and ACS URL from detail page form
- [x] PATCH API endpoint for programmatic updates
- [x] Event log entry for SP updates (`service_provider_updated`) with changed fields in metadata

**Enable/Disable:**

- [x] `enabled` column added to `service_providers` table (default true)
- [x] Toggle enabled/disabled from SP detail page with status badge
- [x] Disabled SPs reject SSO requests (both SP-initiated and IdP-initiated) with "Application Unavailable" error
- [x] Disabled SPs shown with muted styling and red "Disabled" badge in SP list
- [x] Event log entries for enable/disable (`service_provider_enabled`, `service_provider_disabled`)
- [x] API endpoints: `POST /enable` and `POST /disable`

**Delete with Safeguards:**

- [x] Delete confirmation dialog shows group assignment count
- [x] Cascading cleanup of group assignments and signing certificates (already existed)
- [x] Event log entry (`service_provider_deleted` already existed)

**API Endpoints:**

- [x] `PATCH /api/v1/service-providers/{sp_id}` for updates
- [x] `POST /api/v1/service-providers/{sp_id}/enable` and `/disable`
- [x] `DELETE /api/v1/service-providers/{sp_id}` (already existed)

**Not Implemented (deferred):**

- Re-import metadata (update SP config from new metadata XML or URL). Can be added later as a separate item.

**Effort:** S
**Value:** High (Unblocks production SP lifecycle management)

---

## SP List Page UX Improvements

**Status:** Complete

**Resolution:** Rewrote the SP list page to match the user list pattern. Switched to full-width layout, removed the misleading global metadata URL info box (each SP has its own metadata URL on its detail page), removed Entity ID and Actions columns, and converted Certificate and Created columns to relative dates with exact tooltips. Enhanced `format_relative_date()` to handle future dates granularly (Tomorrow, in X days/weeks/months/years) for certificate expiry display.

**Acceptance Criteria:**

- [x] Full-width table layout, consistent with user list views
- [x] Remove the "Share this URL with downstream service providers to configure SAML trust" message (incorrect; each SP has its own metadata URL)
- [x] Remove Entity ID column from the table (too long, breaks layout)
- [x] Certificate expiration column shows relative time (e.g., "in 342 days") with exact date/time on mouseover
- [x] Created column shows relative time (e.g., "3 days ago") with exact date/time on mouseover, consistent with user list views
- [x] Remove delete action from the list rows
- [x] Remove separate "Details" link. SP name is clickable and navigates to the detail view
- [x] Remaining columns: Name (clickable), Status, Groups (count), Certificate Expiry, Created

**Effort:** S

---

## SP Detail View: Tabbed Page Design

**Status:** Complete

**Resolution:** Replaced the monolithic SP detail page with a server-side tabbed layout. Six tabs (Details, Attributes, Groups, Certificates, Metadata, Disable/Delete), each with its own route, template, and data loading. Shared base template provides back link, title with enabled/disabled badge, and tab bar. Name/description editing uses WeftUtils modals. Deletion requires the SP to be disabled first (enforced in both UI and service layer). Establishes reusable tabbed page pattern for deeply nested pages.

**Acceptance Criteria:**

- [x] Page has a title (SP name) and a back-link to the SP list
- [x] Below the title, horizontal tab headers for navigation between sub-pages
- [x] Active tab is visually highlighted
- [x] Default tab is "Details" (auto-redirect from SP UUID path)
- [x] Each tab has its own route and can be linked to directly
- [x] Register all tab routes in `pages.py` as children of the SP detail page
- [x] Details tab: sharable metadata URL with copy-to-clipboard, SP metadata source URL linking to metadata tab, name/description with modal editing, read-only Entity ID/ACS URL/SLO URL/NameID Format/Created
- [x] Attributes tab: attribute mapping table with per-SP overrides, include group claims toggle
- [x] Groups tab: header shows "Groups (N)", add/remove group assignments
- [x] Certificates tab: signing certificate details with color-coded expiry warnings, rotation action, explanatory copy
- [x] Metadata tab: visible only when SP has metadata URL or stored XML, refresh/reimport workflows, explanatory copy
- [x] Disable/Delete tab: enable/disable toggle, delete gated on disabled state, red accent styling

---

## SAML E2E Test Suite

**Status:** Complete

**User Story:**
As a developer of WeftId
I want a Playwright-based E2E test suite for SAML SSO flows
So that regressions in critical auth paths are caught before deployment

**Resolution:**

Implemented a Playwright-based E2E test suite exercising real cross-tenant SAML SSO flows
using two WeftId tenants (one as IdP, one as SP). Five tests cover the full SAML lifecycle:
admin SP/IdP metadata XML import, SP-initiated SSO with JIT provisioning, IdP-initiated SSO,
and pre-existing user matching.

Enhanced `sso_testbed.py` with `--json`, `--teardown`, group-based SP access control, and
pre-existing user provisioning. Added `pytest-playwright` dependency, `test-e2e` and
`test-e2e-debug` Makefile targets, and `pytest.ini` exclusion so E2E tests run separately
from the main test suite.

**Acceptance Criteria:**

*Test infrastructure:*

- [x] `dev/sso_testbed.py`: creates two tenants (IdP and SP) with predefined subdomains, creates test users on each, returns configuration (tenant IDs, user credentials, URLs)
- [x] Pytest fixtures that call the testbed script at session start and tear down both tenants at session end
- [x] Playwright (Python) with `pytest-playwright` for browser automation
- [x] Makefile targets: `test-e2e`, `test-e2e-debug` (headed mode)

*Admin setup tests:*

- [x] As an IdP admin: register the SP tenant (import SP metadata, configure attribute mapping)
- [x] As an SP admin: register the IdP tenant (import IdP metadata, configure as identity provider)

*SSO flow tests:*

- [x] SP-initiated SSO: user starts at SP, is redirected to IdP, authenticates (email + verification code via MailDev), and is returned to SP with a valid session
- [x] IdP-initiated SSO: user starts at IdP, selects the SP, assertion is sent, user lands at SP with a valid session
- [x] Sign-in as pre-existing user: a user that already exists on the SP side authenticates via IdP and is matched to their existing SP account

---

## Branding: Custom Site Title & Nav Bar Title Visibility

**Status:** Complete

**User Story:**
As an admin
I want to replace "WeftId" with my own title in the navigation header and browser tab
So that the platform feels like my own product when my users interact with it

As an admin
I want to optionally hide the title text from the navigation bar
So that I can show only my logo without a text label, while keeping a meaningful browser tab title

**Context:**

"WeftId" currently appears in two places: the nav bar header (next to the logo) and the HTML `<title>` tag (as a suffix on every page, e.g. "Users - WeftId"). Both are hardcoded. The branding settings page already manages logo customization. This feature extends it with title customization.

The nav bar visibility toggle is independent of the custom title. An admin might want to hide the title even when using the default "WeftId" name (logo-only nav bar), or show a custom title in both places.

**Acceptance Criteria:**

- [x] New "Site Title" section on the existing branding settings page (`/admin/settings/branding`)
- [x] Text field: "Site title" with 30-character max length (default: "WeftId")
- [x] Custom title replaces "WeftId" in the nav bar header
- [x] Custom title replaces "WeftId" in the HTML `<title>` suffix on all pages (e.g. "Users - My Platform")
- [x] Toggle: "Show title in navigation bar" (default: on)
- [x] When toggled off, the title text is hidden from the nav bar but still used in `<title>`
- [x] Empty or whitespace-only title field falls back to "WeftId" (never leave `<title>` blank)
- [x] API support: `GET/PUT /api/v1/branding` includes `site_title` and `show_title_in_nav` fields
- [x] Event log entry when settings are changed (existing `branding_settings_updated` event, add new fields to metadata)
- [x] Database: add `site_title` (text, nullable) and `show_title_in_nav` (boolean, default true) columns to `tenant_branding`

**Effort:** S
**Value:** Medium (Brand consistency for white-label deployments)

---

## Enforce Input Length Limits on All Text Fields

**Status:** Complete

**User Story:**
As a platform operator
I want all user-supplied and system-generated text fields to have reasonable maximum length constraints at both the database and application validation layers
So that the system is protected against oversized payloads, resource exhaustion, and data quality issues

**Context:**

An audit of the database schema found **81 unbounded TEXT columns** across 22 tables, with **zero VARCHAR length constraints** at the database level (only 2 columns use `VARCHAR(32)` for metadata hashes). While some Pydantic schemas enforce `max_length` on input models (names, descriptions), the coverage is inconsistent and the database itself provides no backstop. This means a malicious or buggy client could insert arbitrarily large strings into any TEXT column.

**Completed Work:**

**Phase 1: Application validation (Pydantic schemas):**
- [x] All input schemas (Create, Update, Import, Establish) enforce `max_length` on every `str` field
- [x] `BrandingSettingsUpdate.site_title` enforces the documented 30-char limit
- [x] Tenant create/update schemas enforce name (255) and subdomain (63)
- [x] SP schemas enforce entity_id (2048), acs_url (2048), slo_url (2048), description (2000)
- [x] IdP schemas enforce entity_id (2048), sso_url (2048), slo_url (2048), metadata_url (2048)
- [x] OAuth2 schemas enforce client_id (255), redirect_uri (2048), code_challenge (128)
- [x] Validation errors return user-friendly messages indicating the maximum allowed length

**Phase 2: Database constraints (migration):**
- [x] Migration adds `CHECK (length(column) <= N)` or converts `TEXT` to `VARCHAR(N)` for all user-facing fields
- [x] Enum-like fields converted to `VARCHAR(50)` or appropriate size
- [x] URL fields get `CHECK (length(...) <= 2048)`
- [x] Crypto fields get `CHECK (length(...) <= 16000)`
- [x] XML/large content fields get `CHECK (length(...) <= 1000000)`
- [x] Migration verifies no existing data exceeds the new limits before applying constraints
- [x] All existing data fits within the proposed limits (pre-check query in migration)

**Phase 3: Best practices enforcement:**
- [x] CLAUDE.md best practices updated to require `max_length` on all Pydantic `str` fields
- [x] Compliance check (`scripts/compliance_check.py`) optionally flags Pydantic models without `max_length`
- [x] Reference docs updated with standard length limits for each field category

**Tests:**
- [x] Pydantic validation rejects strings exceeding max_length for each input schema
- [x] Database rejects inserts/updates exceeding column limits
- [x] All existing tests continue to pass (limits are generous enough for real data)

**Effort:** M
**Value:** High (Defense-in-depth against oversized payloads, data quality, DoS prevention)

---

## IdP-Side Certificate Rotation & Lifecycle Management

**Status:** Complete

**Summary:** Added automatic certificate lifecycle management for per-SP signing certificates. A rotation guard in `rotate_sp_signing_certificate()` prevents initiating a new rotation while one is already in progress (grace period active). A new daily background job auto-rotates certificates expiring within 90 days and cleans up previous certificates after their grace period ends. Two new event types track automated actions.

**Acceptance Criteria:**

**Rotation guard:**
- [x] `rotate_sp_signing_certificate()` rejects rotation when `rotation_grace_period_ends_at` is in the future
- [x] Raises `ValidationError` with message "Certificate rotation already in progress"
- [x] Applies regardless of whether the active rotation was manual or automatic

**Auto-rotation background job:**
- [x] New background job in `app/jobs/rotate_certificates.py` runs daily
- [x] Queries all `sp_signing_certificates` across tenants (UNSCOPED)
- [x] For certs expiring within 90 days with no active rotation: generate new cert using tenant's lifetime setting, set 90-day grace period
- [x] For certs with expired grace period: call `clear_previous_signing_certificate()` to remove old cert from database
- [x] Returns summary: `{rotated: int, cleaned_up: int, errors: list}`

**Grace period behavior:**
- [x] Manual rotation: 7-day grace period (existing behavior, unchanged)
- [x] Auto-rotation: 90-day grace period
- [x] When grace period ends, old cert removed from metadata AND database (by the background job)

**Event logging:**
- [x] `sp_signing_certificate_auto_rotated` event with metadata: `{sp_id, grace_period_days, new_expires_at}`
- [x] `sp_signing_certificate_cleanup_completed` event when expired cert is removed

**Tests:**
- [x] Rotation guard rejects during active rotation
- [x] Background job auto-rotates certs expiring within 90 days
- [x] Background job skips certs with active rotation
- [x] Background job cleans up expired previous certs
- [x] Auto-rotation uses configurable lifetime setting

**Effort:** M
**Value:** High (Automates certificate lifecycle, prevents expiry-related outages)

---

## Per-IdP SP Metadata & Trust Establishment

**Status:** Complete (implemented in commit 74ad65c, Feb 15 2026)

**User Story:**
As a super admin
I want each identity provider to have its own unique EntityID, metadata URL, and signing certificate when WeftId acts as an SP
So that I can establish trust with each IdP independently, rotate certificates per-IdP without affecting others, and avoid the chicken-and-egg problem during initial setup

**What was implemented:**

- [x] New table `saml_idp_sp_certificates` with rotation support, RLS, tenant isolation
- [x] `entity_id`, `sso_url`, `certificate_pem` nullable on `saml_identity_providers` (pending state)
- [x] `trust_established` boolean column with backfill for existing IdPs
- [x] `GET /saml/metadata/{idp_id}` (public, per-IdP SP metadata with unique EntityID, ACS URL, certificate)
- [x] Grace period includes both current and previous certificates
- [x] `POST /saml/acs/{idp_id}` per-IdP ACS endpoint (global `/saml/acs` kept for backward compatibility)
- [x] Two-step IdP creation: name only first, then metadata import/paste/manual
- [x] IdP detail page shows per-IdP metadata URL in pending state
- [x] Trust establishment via URL import, XML paste, or manual entry
- [x] API includes `sp_metadata_url`, `sp_entity_id`, `sp_acs_url`
- [x] `saml_idp_sp_certificate_created` event on cert generation
- [x] Per-IdP metadata returns correct EntityID, ACS URL, certificate (unit tests)
- [x] Two-step creation flow tested (unit + E2E)

**Remaining cleanup (not blocking):**
- Legacy `/saml/metadata` generic endpoint removed, but tenant-wide `saml_sp_certificates` table still exists (used as fallback)
- Per-IdP SP certificate rotation API endpoint not yet exposed

**Effort:** XL
**Value:** High (Enables independent per-IdP certificate management, solves chicken-and-egg)

---

## Step-by-Step SP Registration (Trust Establishment Flow)

**Status:** Complete

**Summary:** Implemented two-step SP registration where Step 1 creates the SP with just a name (generating a per-SP signing certificate immediately), and Step 2 establishes trust via metadata import (URL or XML) or manual configuration. This eliminates the metadata chicken-and-egg problem where both parties needed each other's metadata before either could configure.

**Acceptance Criteria:**

- [x] `trust_established` boolean column on `service_providers` (default `false`)
- [x] `entity_id` and `acs_url` nullable for pending SPs
- [x] Unique constraint on `entity_id` allows multiple NULLs
- [x] SSO flow checks `trust_established = true` before processing (rejects pending SPs)
- [x] Create SP with name only, eagerly generate per-SP signing certificate
- [x] SP detail page shows setup UI when `trust_established = false`
- [x] Trust established via metadata URL import, metadata XML paste, or manual config
- [x] `establish_trust_from_metadata_url()` and `establish_trust_from_metadata_xml()` service functions
- [x] Existing SPs backfilled with `trust_established = true`
- [x] Event logging for creation and trust establishment

**Effort:** M
**Value:** High (Eliminates the metadata chicken-and-egg problem, clearer admin workflow)

---

## Dynamic Attribute Declarations in SAML Metadata

**Status:** Complete

**Summary:** Made SAML metadata attribute declarations dynamic instead of hardcoded. Both IdP metadata (per-SP) and SP metadata (per-IdP) generators now accept an optional `attribute_mapping` parameter. The service layer passes the stored mapping through so metadata accurately reflects actual configured attributes. When no custom mapping exists, defaults are used (preserving existing behavior).

**Acceptance Criteria:**

**IdP metadata (per-SP):**
- [x] `generate_idp_metadata_xml()` accepts an `attribute_mapping` parameter (the SP's configured mapping)
- [x] `<saml:Attribute>` elements in IdP metadata reflect the SP's actual `attribute_mapping` values, not hardcoded defaults
- [x] When no per-SP mapping exists, fall back to default attribute URIs (current behavior)
- [x] Per-SP metadata service (`get_sp_idp_metadata_xml`) passes the SP's `attribute_mapping` to the generator
- [x] Tenant-level metadata (`get_tenant_idp_metadata_xml`) continues using defaults (no SP context)

**SP metadata (per-IdP):**
- [x] SP metadata generator emits `<md:AttributeConsumingService>` with `<md:RequestedAttribute>` elements
- [x] Requested attributes reflect the IdP's configured `attribute_mapping` (what we expect to receive)
- [x] Each `<md:RequestedAttribute>` includes `Name` (the configured attribute URI) and `FriendlyName` (the platform field label)

**Automatically kept in sync:**
- [x] No manual "regenerate metadata" step. Metadata endpoints read the current `attribute_mapping` at request time, so changes are reflected immediately.

**Effort:** S
**Value:** High (Makes metadata a living, accurate document. Enables both sides to validate configuration alignment.)

---
