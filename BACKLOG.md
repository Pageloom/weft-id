# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Public Trust Page for IdP Configuration

**User Story:**
As a super admin
I want to share a public URL with my IdP administrator that contains all the configuration details they need
So that external IdP admins can access SP metadata, Entity ID, and ACS URL without needing an authenticated session in WeftId

**Context:**

The "Share with your IdP" section is currently buried inside the authenticated IdP detail page. External IdP administrators who need to configure their side of the federation have no way to access this information directly. The SP metadata URL, Entity ID, and ACS URL should be on a public, shareable page (similar to how `/saml/metadata` is already public).

**Acceptance Criteria:**

- [ ] New public route: `GET /pub/{idp_id}/trust` (no authentication required)
- [ ] Page is tenant-scoped (via `get_tenant_id_from_request`)
- [ ] Returns 404 if IdP does not exist or is not enabled
- [ ] Page has three sections, ordered by recommendation:
  1. **Use Metadata URL** (recommended): the SP metadata URL as a copiable link
  2. **Metadata XML**: code block display with copy button (for IdPs that don't support URL ingestion)
  3. **Manual Entry**: SP Entity ID and ACS URL as individually copiable values (last resort)
- [ ] Clean, standalone page with tenant branding (logo if configured)
- [ ] Replace the "Share with your IdP" section in the IdP details tab with a prominent link to this public page (with copy-to-clipboard for the URL)
- [ ] API: no new API endpoint needed (this is a public HTML page)
- [ ] Tests for the public route (valid IdP, disabled IdP returns 404, nonexistent IdP returns 404)

**Key files:**
- New: `app/routers/saml/public.py` (or add to `authentication.py`)
- New: `app/templates/saml_public_trust.html`
- Modify: `app/templates/saml_idp_tab_details.html` (replace "Share with your IdP" section)
- Modify: `app/pages.py` (register public route if needed)

**Effort:** S
**Value:** High (Eliminates back-and-forth when onboarding new IdPs)

---

## Multiple IdP Certificates

**User Story:**
As a super admin
I want WeftId to accept multiple signing certificates from an identity provider
So that IdP-side certificate rotation does not break SSO during the transition period

**Context:**

The `saml_identity_providers` table has a single `certificate_pem TEXT NOT NULL` column. During IdP-side certificate rotation, the IdP may start signing assertions with a new certificate while the old one is still in use by some sessions. WeftId currently can only validate against one certificate, so rotation on the IdP side breaks SSO until the admin manually updates the certificate in WeftId. Many IdPs also advertise multiple certificates in their metadata XML during rotation periods.

**Acceptance Criteria:**

**Data model:**
- [ ] New table: `idp_certificates` (id UUID, idp_id UUID, tenant_id UUID, certificate_pem TEXT, fingerprint TEXT, label TEXT nullable, is_active BOOLEAN default true, created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ nullable)
- [ ] Migration to copy existing `certificate_pem` data from `saml_identity_providers` into `idp_certificates`
- [ ] Make `certificate_pem` on `saml_identity_providers` nullable (keep for backwards compat during transition, eventually remove)
- [ ] RLS policy on `idp_certificates` matching existing tenant isolation pattern

**SAML validation:**
- [ ] Update SAML response validation to try all active certificates for an IdP (iterate until one validates or all fail)
- [ ] Validation failure message should indicate none of the certificates matched (not just "invalid signature")

**Metadata import:**
- [ ] Update metadata import to extract and store all `<KeyDescriptor use="signing">` certificates from IdP metadata XML
- [ ] Metadata refresh flow syncs certificates (adds new ones, optionally deactivates removed ones)

**Certificates tab UI:**
- [ ] List all IdP certificates with fingerprint, expiry date, active/inactive status
- [ ] Expandable PEM view per certificate
- [ ] Add certificate manually (paste PEM)
- [ ] Deactivate/activate individual certificates
- [ ] Remove individual certificates (with confirmation)
- [ ] SP certificate section remains as-is (the signing cert WeftId uses for this IdP relationship)

**Event logging:**
- [ ] `idp_certificate_added` event when a certificate is added
- [ ] `idp_certificate_deactivated` / `idp_certificate_activated` events
- [ ] `idp_certificate_removed` event when a certificate is deleted

**Key files:**
- New: `db-init/NNNNN_idp_certificates.sql`
- New or extend: `app/database/saml/idp_certificates.py`
- Modify: `app/services/saml/auth.py` (multi-cert validation in `_build_saml_settings`)
- Modify: `app/services/saml/providers.py` (metadata import certificate handling)
- Modify: `app/templates/saml_idp_tab_certificates.html`
- Modify: `app/utils/saml.py` (extract multiple certs from metadata XML)

**Effort:** L
**Value:** High (IdP-side certificate rotation currently breaks SSO)

---

## Fix and Redesign IdP Attribute Mapping

**User Story:**
As a super admin
I want the IdP attribute mapping UI to clearly show which IdP attributes are mapped to which platform fields, and let me edit mappings directly
So that I can configure attribute mapping correctly without confusion

**Context:**

The current attributes tab has multiple problems:
- The "Mapped to" column always shows "unmapped" due to a template logic bug (it compares advertised attribute names against mapping values, but the names don't match the values)
- The "Attribute Mapping" form and "Attributes Advertised by IdP" table are disconnected and confusing
- No inline editing (unlike the SP attribute mapping tab)
- "Load presets for generic" is unhelpful without context
- No way to add attributes when the IdP doesn't advertise them in metadata

The redesign splits the tab into two clear sections: an editable platform field mappings table (always shown) and a read-only reference table of advertised attributes (shown only when metadata includes attribute information).

**Acceptance Criteria:**

**Section 1: Platform Field Mappings** (always shown)
- [ ] Table with 4 rows: Email, First Name, Last Name, Groups
- [ ] Each row shows the platform field name and has an editable input for the IdP attribute name
- [ ] If IdP advertises attributes in metadata, show a dropdown populated with advertised attribute names
- [ ] If no advertised attributes, show a text input for manual entry
- [ ] Pre-fill inputs from current `attribute_mapping` values
- [ ] Presets button loads recommended mappings for known IdP types (Okta, Entra ID, Google Workspace)
- [ ] Save button persists changes via existing API endpoint
- [ ] Clear visual feedback on save (success/error)

**Section 2: Advertised Attributes** (only if metadata has attributes)
- [ ] Read-only reference table showing what the IdP declares in its metadata
- [ ] Columns: Attribute Name, Friendly Name, Mapped To
- [ ] "Mapped To" column shows which platform field (if any) uses this attribute, with green "Mapped" / gray "Unmapped" badges
- [ ] This section is informational only. All editing happens in Section 1.

**Removed:**
- [ ] Remove the separate "Attribute Mapping" form section (merged into Section 1)
- [ ] Fix the mapping comparison logic (compare mapping values against attribute names/friendly names, not the reverse)

**Key files:**
- Modify: `app/templates/saml_idp_tab_attributes.html` (full redesign)
- Modify: `app/routers/saml/admin/providers.py` (`idp_tab_attributes` handler to pass advertised attrs as dropdown options)
- Keep unchanged: `app/services/saml/providers.py` (`get_provider_presets`)
- Keep unchanged: API endpoint `/api/v1/saml/provider-presets/{provider_type}`

**Effort:** M
**Value:** High (Current attribute mapping UX is broken and confusing)

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

