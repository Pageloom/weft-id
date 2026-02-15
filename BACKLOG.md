# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## IdP List View UX Overhaul

**User Story:**
As a super admin
I want a clean, scannable identity providers list
So that I can quickly see the status of all configured IdPs without visual clutter

**Context:**

The current IdP list view has accumulated UI elements that belong elsewhere or are no longer needed. The prominent blue "share this metadata URL" box dominates the page but is only needed during IdP setup (and is better placed on the IdP detail page). The actions column duplicates options already available on the detail page. The metadata sync timestamp is shown as an absolute datetime rather than a human-friendly relative time.

**Acceptance Criteria:**

- [ ] Remove the SP metadata URL information box from the list page (this information lives on each IdP's detail page under "Share with your IdP")
- [ ] Make the list view full-width (remove max-width constraint, use the full content area)
- [ ] Show metadata sync time as relative time (e.g., "synced 2 hours ago", "synced 3 days ago") with the absolute timestamp available on hover/tooltip
- [ ] Remove the "Actions" column entirely (Edit, Toggle, Set Default, Delete are all available on the detail page)
- [ ] Each row links to the detail page (click anywhere on the row, or click the name)
- [ ] All existing tests continue to pass

**Effort:** S
**Value:** Medium (Cleaner admin experience, removes redundant UI)

---

## IdP Detail Page UX Overhaul

**User Story:**
As a super admin
I want the identity provider detail page to follow the same tabbed, structured layout as the service provider detail page
So that the admin experience is consistent across both sides of the federation

**Context:**

The current IdP detail page is a single long form with all fields editable and everything on one page. The SP detail page, by contrast, uses a tabbed layout with clear separation between read-only configuration, attribute mapping, metadata management, and destructive actions. The IdP detail page should follow the same pattern.

Key design principles from the SP detail page:
- Tabbed navigation for logical grouping
- Read-only fields for values that come from metadata (editing requires re-importing)
- Inline editing for admin-controlled fields (name, description)
- Attribute mapping as a dedicated tab with matching/unmatching indicators
- Destructive actions gated behind safety checks

**Acceptance Criteria:**

**Tab: Details & Settings**

- [ ] Name: editable inline (same modal pattern as SP detail)
- [ ] Provider Type: read-only display (Okta, Azure AD, Google Workspace, Generic SAML)
- [ ] Entity ID: read-only display
- [ ] SSO URL: read-only display
- [ ] SLO URL: read-only display (if configured)
- [ ] Settings toggles: Enabled, Default IdP, Require Platform MFA, Just-in-Time Provisioning
- [ ] Connection test button
- [ ] "Share with your IdP" section showing (in order of emphasis):
  1. SP Metadata URL (copy button, recommended)
  2. View/download metadata XML
  3. De-emphasized: raw SP Entity ID and ACS URL for manual configuration on the IdP side

**Tab: Certificates**

- [ ] List IdP certificates by creation date and expiry date (not full PEM by default)
- [ ] Each certificate expandable to reveal full PEM content on demand
- [ ] Support for multiple IdP certificates (common during IdP-side rotation)
- [ ] SP certificate information (the signing cert used for this IdP relationship)

**Tab: Attributes**

- [ ] Same UX pattern as SP attributes tab: table with columns for attribute name, what the IdP advertises (from metadata), and what WeftId maps it to
- [ ] Match/unmatch badges (green "Matched", amber "Unmatched")
- [ ] Editable mapping fields for: Email, First Name, Last Name, Groups
- [ ] Provider-specific presets (load recommended mappings for Okta, Azure AD, Google Workspace)
- [ ] Save button with reset-to-defaults option

**Tab: Metadata**

- [ ] Primary action: re-import from metadata URL (with current URL pre-filled if previously used)
- [ ] Secondary action: paste metadata XML
- [ ] Confirmation warning before re-import: "Re-importing metadata will overwrite Entity ID, SSO URL, SLO URL, and certificates. Continue?"
- [ ] Last sync status display (timestamp, success/error)
- [ ] If metadata URL is configured: manual "Refresh Now" button

**Tab: Danger Zone**

- [ ] Delete button is disabled while the IdP is enabled
- [ ] Clear messaging: "Disable this identity provider before deleting it"
- [ ] When disabled: delete button with confirmation modal
- [ ] Service layer enforces this constraint (deletion of an enabled IdP returns an error regardless of UI)

**General:**

- [ ] All existing IdP functionality preserved (no regression)
- [ ] API endpoints remain unchanged (UI-only restructuring)
- [ ] All existing tests continue to pass
- [ ] New tests for the delete-requires-disabled business logic constraint

**Effort:** L
**Value:** High (Consistent admin UX across IdP and SP management, safer operations)

---

## Fix SP Signing Certificate Rotation Grace Period

**User Story:**
As a super admin
I want certificate rotation to work without breaking SSO for the service provider
So that I can rotate certificates safely with a transition window where both old and new certificates are accepted

**Context:**

When rotating an SP's signing certificate, the system generates a new certificate and stores the previous one in `previous_certificate_pem` with a 7-day grace period timestamp. However, the IdP metadata endpoint only serves the **new** certificate. The old certificate is not included in the metadata XML, so the downstream SP has no way to trust assertions signed with the old certificate. In practice, rotation breaks SSO immediately rather than providing a grace period.

Additionally, there is no automatic cleanup of expired previous certificates. The database function `clear_previous_signing_certificate()` exists but is never called.

**Acceptance Criteria:**

- [ ] During the grace period, the IdP metadata serves **both** certificates as separate `<md:KeyDescriptor use="signing">` elements (new certificate first, previous certificate second)
- [ ] After the grace period expires, only the new certificate is served in metadata
- [ ] It must not be possible to rotate certificates during the grace period
- [ ] Background job runs periodically to clear expired previous certificates (calls `clear_previous_signing_certificate()`)
- [ ] Certificates tab copy updated to reflect the actual grace period behavior
- [ ] Tests for dual-certificate metadata generation during grace period
- [ ] Tests for single-certificate metadata after grace period expiry
- [ ] Tests for the cleanup background job

**Effort:** M
**Value:** High (Certificate rotation is currently broken in practice)

---

## Step-by-Step SP Registration (Trust Establishment Flow)

**User Story:**
As a super admin
I want to register a service provider in two steps (name first, then trust configuration)
So that I can share WeftId's metadata with the SP immediately, avoiding the chicken-and-egg problem where both parties need each other's metadata before either can configure

**Context:**

Today, SP registration requires entity_id and ACS URL upfront (whether via metadata import or manual entry). But this creates a deadlock: the SP needs WeftId's metadata to configure their side, and WeftId needs the SP's metadata to create the SP record. The admin has to configure both sides in the right order, often guessing or going back and forth.

The fix is a two-step flow. Step 1 creates the SP with just a name. WeftId immediately generates a per-SP signing certificate and makes the IdP metadata URL available. The admin can copy that URL and send it to the SP counterpart. Step 2 is establishing trust: importing the SP's metadata (preferably via URL), with manual configuration available as a de-emphasized fallback.

**Technical notes:**
- The signing certificate depends only on `tenant_id`, not on the SP's `entity_id`. Cert generation at Step 1 is safe.
- WeftId's own entity ID for the SP is derived from the SP's UUID (`/saml/idp/metadata/{sp_id}`), independent of the SP's entity_id field.
- Pending SPs (no entity_id) are invisible to SSO routing. No special rejection logic needed.

**Acceptance Criteria:**

**Data model:**

- [ ] Add `trust_established` boolean column to `service_providers` (default `false`)
- [ ] Migration backfills `trust_established = true` for all existing SPs
- [ ] Make `entity_id` and `acs_url` nullable (currently NOT NULL). Pending SPs have these as NULL.
- [ ] SSO flow checks `trust_established = true` AND `enabled = true` before processing. Pending SPs are excluded.
- [ ] Unique constraint on `entity_id` must allow multiple NULLs (Postgres does this by default)

**Step 1: Create SP (name only):**

- [ ] New "Add Service Provider" form: only a name field (required, unique per tenant)
- [ ] On submit: create SP record with `trust_established = false`, `entity_id = NULL`, `acs_url = NULL`
- [ ] Eagerly generate per-SP signing certificate (existing behavior, just decoupled from metadata)
- [ ] Redirect to the SP detail page, which shows the setup/trust establishment UI
- [ ] API: `POST /api/v1/service-providers/` accepts `name` only (entity_id and acs_url become optional)

**Step 2: SP detail page (pending state):**

- [ ] When `trust_established = false`, the SP detail page shows a "Setup" banner or state indicator
- [ ] Prominently display WeftId's metadata URL for this SP (copy button) so admin can share it with the SP
- [ ] Primary action: "Import SP Metadata" section (metadata URL import is the default/recommended option)
- [ ] Secondary action: metadata XML paste (available but not the default)
- [ ] De-emphasized action: manual configuration of entity_id, ACS URL, SLO URL (collapsed or "Advanced" label)
- [ ] Once metadata is imported or manual config is saved, set `trust_established = true`
- [ ] After trust is established, the SP detail page shows the normal view (existing behavior)

**Existing SP behavior (no regression):**

- [ ] Existing fully-configured SPs (backfilled `trust_established = true`) work exactly as before
- [ ] The SP list page shows a visual indicator for pending vs configured SPs
- [ ] All existing tests continue to pass

**Event logging:**

- [ ] `service_provider_created` event on Step 1 (name-only creation)
- [ ] `service_provider_trust_established` event when trust is established (metadata import or manual config)

**Effort:** M
**Value:** High (Eliminates the metadata chicken-and-egg problem, clearer admin workflow)

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

## Baseline Schema & Forward-Only Migration System

**User Story:**
As a developer
I want the database to be initialized from a single baseline schema with a forward-only
migration runner
So that I can set up a fresh database quickly, apply incremental changes automatically on
startup, and never worry about replaying 30+ sequential migration files

**Context:**

The current `db-init/` setup has 32 sequential SQL files that only run on the first
`docker-compose up` (PostgreSQL's `initdb.d` mechanism). After that, new migrations require
a manual `docker compose exec -T db psql ...` command, and resetting the database means
wiping the volume and replaying everything from scratch. This is fragile and error-prone.

The replacement: a single `schema.sql` baseline (consolidated from all existing migrations),
a lightweight Python migration runner (`migrate.py`), and a one-shot docker-compose service
that runs automatically before the app starts.

**Detailed technical plan:** [`.claude/references/migration-plan.md`](.claude/references/migration-plan.md)

**Acceptance Criteria:**

- [ ] `db-init/schema.sql` contains the complete current schema (roles, tables, indexes, RLS, grants)
- [ ] `db-init/migrate.py` detects fresh vs existing database and applies baseline or incremental migrations
- [ ] `schema_migrations` table tracks applied versions
- [ ] `migrate` service in docker-compose runs automatically before app/worker start
- [ ] `make migrate` runs pending migrations on a running database
- [ ] `make db-init` wipes volume and reinitializes (baseline + migrations)
- [ ] Old 32 migration files deleted (preserved in git history)
- [ ] Schema equivalence verified (`pg_dump` comparison)
- [ ] All existing tests pass
- [ ] CLAUDE.md updated with new migration workflow

**Effort:** M
**Value:** High (Eliminates manual migration steps, faster DB setup, cleaner repo)

---

## User Export (CSV)

**User Story:**
As an admin
I want to export the current filtered user list as a CSV file
So that I can use the data for auditing, compliance reporting, and operational tasks outside the platform

**Acceptance Criteria:**

**Frontend Export:**

- [ ] "Export" button on the users list page
- [ ] Exports the current filtered/searched result set (respects active search, role filters, status filters)
- [ ] Downloads as a `.csv` file with a timestamped filename (e.g., `users_2026-02-07.csv`)
- [ ] CSV columns: Name, Email, Role, Status, Auth Method, Last Login, Last Activity, Created At
- [ ] Handles large exports gracefully (streaming response, not buffered in memory)
- [ ] Export limited to admin+ role

**API Endpoint:**

- [ ] `GET /api/v1/users/export?format=csv` with same filter parameters as list endpoint
- [ ] Supports `format=csv` (default) and `format=json` for programmatic use
- [ ] Streams response for large datasets
- [ ] Admin+ authorization required

**Event Logging:**

- [ ] Export action logged as audit event (`users_exported` event type)
- [ ] Event metadata includes: format, filter criteria, row count

**Effort:** S
**Value:** High (Frequently needed for compliance and operations, low implementation cost)

---

## Branding: Custom Site Title & Nav Bar Title Visibility

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

- [ ] New "Site Title" section on the existing branding settings page (`/admin/settings/branding`)
- [ ] Text field: "Site title" with 30-character max length (default: "WeftId")
- [ ] Custom title replaces "WeftId" in the nav bar header
- [ ] Custom title replaces "WeftId" in the HTML `<title>` suffix on all pages (e.g. "Users - My Platform")
- [ ] Toggle: "Show title in navigation bar" (default: on)
- [ ] When toggled off, the title text is hidden from the nav bar but still used in `<title>`
- [ ] Empty or whitespace-only title field falls back to "WeftId" (never leave `<title>` blank)
- [ ] API support: `GET/PUT /api/v1/branding` includes `site_title` and `show_title_in_nav` fields
- [ ] Event log entry when settings are changed (existing `branding_settings_updated` event, add new fields to metadata)
- [ ] Database: add `site_title` (text, nullable) and `show_title_in_nav` (boolean, default true) columns to `tenant_branding`

**Effort:** S
**Value:** Medium (Brand consistency for white-label deployments)

