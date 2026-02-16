# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Dynamic Attribute Declarations in SAML Metadata

**User Story:**
As a super admin
I want SAML metadata on both sides of the federation to reflect the actual configured attribute mappings
So that when I or an external admin imports metadata, the declared attributes match what will actually be sent or expected, enabling accurate configuration alignment

**Context:**

Metadata attribute declarations are currently disconnected from the actual attribute mappings:

- **IdP side** (us as IdP, per-SP metadata at `/saml/idp/metadata/{sp_id}`): Always emits hardcoded `SAML_ATTRIBUTE_URIS` defaults, even though each SP has its own `attribute_mapping` that may differ. An SP admin importing our metadata sees default attribute names, not the names we'll actually send.

- **SP side** (us as SP, per-IdP metadata): Does not generate `<md:RequestedAttribute>` elements at all. An upstream IdP admin importing our metadata gets no signal about which attributes we expect.

Since we already serve unique metadata per relationship (per-SP IdP metadata, per-IdP SP metadata), there's no blast radius. Changing one SP's mapping only affects that SP's metadata endpoint. Attribute declarations in metadata are advisory (not enforced at protocol level), so updating them doesn't break existing trust. It just makes the metadata more accurate.

**Acceptance Criteria:**

**IdP metadata (per-SP):**
- [ ] `generate_idp_metadata_xml()` accepts an `attribute_mapping` parameter (the SP's configured mapping)
- [ ] `<saml:Attribute>` elements in IdP metadata reflect the SP's actual `attribute_mapping` values, not hardcoded defaults
- [ ] When no per-SP mapping exists, fall back to default attribute URIs (current behavior)
- [ ] Per-SP metadata service (`get_sp_idp_metadata_xml`) passes the SP's `attribute_mapping` to the generator
- [ ] Tenant-level metadata (`get_tenant_idp_metadata_xml`) continues using defaults (no SP context)

**SP metadata (per-IdP):**
- [ ] SP metadata generator emits `<md:AttributeConsumingService>` with `<md:RequestedAttribute>` elements
- [ ] Requested attributes reflect the IdP's configured `attribute_mapping` (what we expect to receive)
- [ ] Each `<md:RequestedAttribute>` includes `Name` (the configured attribute URI) and `FriendlyName` (the platform field label)

**Depends on:** Per-IdP SP Metadata & Trust Establishment (for SP-side generation)

**Automatically kept in sync:**
- [ ] No manual "regenerate metadata" step. Metadata endpoints read the current `attribute_mapping` at request time, so changes are reflected immediately.

**Tests:**
- [ ] IdP metadata for an SP with custom mapping includes the custom attribute URIs, not defaults
- [ ] IdP metadata for an SP with no custom mapping uses defaults
- [ ] Tenant-level IdP metadata still uses defaults
- [ ] SP metadata includes `RequestedAttribute` elements matching the IdP's mapping (when per-IdP SP metadata exists)

**Key files:**
- Modify: `app/utils/saml_idp.py` (`generate_idp_metadata_xml` to accept attribute mapping)
- Modify: `app/services/service_providers/metadata.py` (pass SP's mapping to generator)
- Modify: `app/utils/saml.py` (SP metadata generation, add `RequestedAttribute` support)

**Effort:** S
**Value:** High (Makes metadata a living, accurate document. Enables both sides to validate configuration alignment.)

---

## IdP-Side Certificate Rotation & Lifecycle Management

**User Story:**
As a super admin
I want IdP signing certificates to rotate automatically before expiry and clean up expired certificates
So that I do not have to manually track and rotate certificates for each downstream SP

**Context:**

When WeftId acts as an IdP, each downstream SP gets a per-SP signing certificate (table: `sp_signing_certificates`). Dual-certificate metadata during the grace period already works. However, there is no automatic rotation, no cleanup of expired previous certificates (`clear_previous_signing_certificate()` exists but is never called), and no guard against initiating a rotation while one is already in progress.

**Acceptance Criteria:**

**Rotation guard:**
- [ ] `rotate_sp_signing_certificate()` rejects rotation when `rotation_grace_period_ends_at` is in the future
- [ ] Raises `ValidationError` with message "Certificate rotation already in progress"
- [ ] Applies regardless of whether the active rotation was manual or automatic

**Auto-rotation background job:**
- [ ] New background job in `app/jobs/` runs daily
- [ ] Queries all `sp_signing_certificates` across tenants
- [ ] For certs expiring within 90 days with no active rotation: generate new cert using tenant's lifetime setting, set 90-day grace period
- [ ] For certs with expired grace period: call `clear_previous_signing_certificate()` to remove old cert from database
- [ ] Returns summary: `{rotated: int, cleaned_up: int, errors: list}`

**Grace period behavior:**
- [ ] Manual rotation: 7-day grace period (existing behavior, unchanged)
- [ ] Auto-rotation: 90-day grace period
- [ ] In both cases: when grace period ends, old cert removed from metadata AND database simultaneously (by the background job)

**Event logging:**
- [ ] `sp_signing_certificate_auto_rotated` event with metadata: `{sp_id, grace_period_days, new_expires_at}`
- [ ] `sp_signing_certificate_cleanup_completed` event when expired cert is removed

**Tests:**
- [ ] Rotation guard rejects during active rotation
- [ ] Background job auto-rotates certs expiring within 90 days
- [ ] Background job skips certs with active rotation
- [ ] Background job cleans up expired previous certs
- [ ] Auto-rotation uses configurable lifetime setting

**Key files:**
- Modify: `app/services/service_providers/signing_certs.py` (rotation guard)
- New: `app/jobs/rotate_certificates.py` (background job)
- Register in: `app/jobs/registry.py`

**Effort:** M
**Value:** High (Automates certificate lifecycle, prevents expiry-related outages)

---

## Per-IdP SP Metadata & Trust Establishment

**User Story:**
As a super admin
I want each identity provider to have its own unique EntityID, metadata URL, and signing certificate when WeftId acts as an SP
So that I can establish trust with each IdP independently, rotate certificates per-IdP without affecting others, and avoid the chicken-and-egg problem during initial setup

**Context:**

Today, WeftId as an SP serves a single global metadata at `/saml/metadata` with one tenant-wide certificate. This means certificate rotation affects all IdPs simultaneously. Additionally, adding an IdP requires its metadata upfront, creating a chicken-and-egg problem (the IdP needs WeftId's metadata to configure, but WeftId needs the IdP's metadata to create the record).

The solution mirrors the IdP-side approach: each IdP gets a unique metadata URL (`/saml/metadata/{idp_id}`), a unique EntityID, and its own signing certificate. IdP creation becomes two-step: create with name only (get metadata URL immediately), then import IdP metadata later.

**Acceptance Criteria:**

**Data model:**
- [ ] New table `saml_idp_sp_certificates` with: `id`, `idp_id` (unique FK), `tenant_id`, `certificate_pem`, `private_key_pem_enc`, `expires_at`, `created_by`, `created_at`, rotation columns (`previous_certificate_pem`, `previous_private_key_pem_enc`, `previous_expires_at`, `rotation_grace_period_ends_at`)
- [ ] RLS policy for tenant isolation
- [ ] Make `entity_id`, `sso_url`, `certificate_pem` nullable on `saml_identity_providers` (pending IdPs have these as NULL)
- [ ] Add `trust_established` boolean column (default false), backfill true for existing IdPs
- [ ] Migration generates per-IdP certificates for all existing IdPs

**Per-IdP metadata endpoint:**
- [ ] `GET /saml/metadata/{idp_id}` (public, unauthenticated)
- [ ] Returns SP metadata with EntityID `{base_url}/saml/metadata/{idp_id}`, ACS URL `{base_url}/saml/acs/{idp_id}`, and per-IdP certificate
- [ ] During grace period, includes both current and previous certificates

**Per-IdP ACS endpoint:**
- [ ] `POST /saml/acs/{idp_id}` routes SAML response to correct IdP config
- [ ] Uses per-IdP certificate for request signing
- [ ] Existing global `/saml/acs` remains for backwards compatibility

**Two-step IdP creation (chicken-and-egg solution):**
- [ ] Step 1: Create IdP with just a name. Immediately generates per-IdP SP certificate and metadata URL
- [ ] IdP is in pending state (`trust_established = false`) until metadata is obtained
- [ ] IdP detail page shows per-IdP metadata URL (public link) that admin can share with the IdP counterpart
- [ ] Step 2: Fetch metadata from IdP's metadata URL, or import metadata XML. Sets `trust_established = true`
- [ ] After trust established, IdP detail page shows normal view

**Legacy endpoint removal:**
- [ ] Delete `/saml/metadata` endpoint entirely (no deprecation, no fallback)
- [ ] Delete tenant-wide `saml_sp_certificates` table and all related code (service, database, router)
- [ ] Remove the SP certificate rotation button from the IdP list page (rotation now happens per-IdP)

**API:**
- [ ] `GET /api/v1/saml/identity-providers/{idp_id}` includes `sp_metadata_url`, `sp_entity_id`, `sp_acs_url`
- [ ] `POST /api/v1/saml/identity-providers/{idp_id}/rotate-sp-certificate` rotates per-IdP SP cert

**Event logging:**
- [ ] `saml_idp_sp_certificate_created` on cert generation
- [ ] `saml_idp_trust_established` when metadata is imported

**Tests:**
- [ ] Per-IdP metadata returns correct EntityID, ACS URL, certificate
- [ ] Per-IdP ACS routes to correct IdP
- [ ] Two-step creation flow (name only, then metadata fetch/import)
- [ ] Migration generates certs for existing IdPs
- [ ] Legacy `/saml/metadata` endpoint is removed (returns 404 or not routed)
- [ ] No references to `saml_sp_certificates` remain in application code

**Key files:**
- New migration in `db-init/`
- New: `app/database/saml/idp_sp_certificates.py`
- New: `app/services/saml/idp_sp_certificates.py`
- Modify: `app/routers/saml/` (per-IdP metadata and ACS endpoints)
- Modify: IdP creation flow (routers, services, templates)

**Effort:** XL
**Value:** High (Enables independent per-IdP certificate management, solves chicken-and-egg)

---

## SP-Side Certificate Rotation & Lifecycle Management

**User Story:**
As a super admin
I want SP-side signing certificate rotation to serve both old and new certificates during the grace period, rotate automatically before expiry, and clean up expired certificates
So that IdP administrators can transition smoothly without SSO breaking

**Context:**

Mirrors Item 2 but for the SP side (per-IdP signing certificates from the Per-IdP SP Metadata item). Requires Per-IdP SP Metadata & Trust Establishment to be complete first.

**Depends on:** Per-IdP SP Metadata & Trust Establishment

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
- Modify: `app/services/saml/idp_sp_certificates.py` (rotation guard, from Per-IdP SP Metadata item)

**Effort:** M
**Value:** High

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

---

## Enforce Input Length Limits on All Text Fields

**User Story:**
As a platform operator
I want all user-supplied and system-generated text fields to have reasonable maximum length constraints at both the database and application validation layers
So that the system is protected against oversized payloads, resource exhaustion, and data quality issues

**Context:**

An audit of the database schema found **81 unbounded TEXT columns** across 22 tables, with **zero VARCHAR length constraints** at the database level (only 2 columns use `VARCHAR(32)` for metadata hashes). While some Pydantic schemas enforce `max_length` on input models (names, descriptions), the coverage is inconsistent and the database itself provides no backstop. This means a malicious or buggy client could insert arbitrarily large strings into any TEXT column.

**Current state of application validation:**

Fields WITH `max_length` in Pydantic schemas (partial coverage):
- User names (`first_name`, `last_name`): 255 in create/update schemas, but NOT in response schemas
- Group name: 200, description: 2000
- OAuth2 client name: 255, description: 500
- IdP name: 255
- SP name: 255
- Privileged domain: 253
- Branding mandala seed: 100
- Site title: documented as max 30 but NOT enforced in schema

Fields WITHOUT any `max_length` (sampling of high-risk gaps):
- SP `entity_id`, `acs_url`, `slo_url`, `description`, `metadata_url`
- IdP `entity_id`, `sso_url`, `slo_url`, `metadata_url`
- OAuth2 `client_id`, `redirect_uri`, `code_challenge`
- Branding `site_title` (documented limit not enforced)
- Tenant `name`, `subdomain`
- All event log string fields
- All debug entry fields

**Proposed limits by field category:**

| Category | Examples | Proposed DB Limit |
|----------|----------|-------------------|
| Short names/titles | tenant name, SP name, IdP name, group name, user first/last name, site_title | 255 |
| Descriptions | SP description, OAuth2 description, group description | 2000 |
| URLs | entity_id, sso_url, acs_url, slo_url, metadata_url, redirect_uri | 2048 |
| Enum-like fields | status, job_type, event_type, provider_type, group_type, theme, locale, tz, mfa_method | 50 |
| Hashes/fingerprints | password_hash, code_hash, token_hash, fingerprint, client_secret_hash | 512 |
| Crypto material | certificate_pem, private_key_pem_enc, secret_encrypted | 16000 |
| XML/large content | metadata_xml, saml_response_xml, saml_response_b64 | 1000000 (1MB) |
| Error text | bg_tasks.error, metadata_fetch_error, error_detail | 10000 |
| IP addresses | request_ip | 45 (IPv6 max) |
| User agent | user_agent | 1024 |
| MIME types | content_type, logo_dark_mime, logo_light_mime | 255 |
| Domain names | domain | 253 (DNS max) |
| Filenames | filename | 255 |
| Subdomains | subdomain | 63 (DNS label max) |
| Code challenge | code_challenge, code_challenge_method | 128 |

**Acceptance Criteria:**

**Phase 1: Application validation (Pydantic schemas):**
- [ ] All input schemas (Create, Update, Import, Establish) enforce `max_length` on every `str` field
- [ ] Limits match the proposed table above (or refined values after review)
- [ ] `BrandingSettingsUpdate.site_title` enforces the documented 30-char limit
- [ ] Tenant create/update schemas enforce name (255) and subdomain (63)
- [ ] SP schemas enforce entity_id (2048), acs_url (2048), slo_url (2048), description (2000)
- [ ] IdP schemas enforce entity_id (2048), sso_url (2048), slo_url (2048), metadata_url (2048)
- [ ] OAuth2 schemas enforce client_id (255), redirect_uri (2048), code_challenge (128)
- [ ] Validation errors return user-friendly messages indicating the maximum allowed length

**Phase 2: Database constraints (migration):**
- [ ] Migration adds `CHECK (length(column) <= N)` or converts `TEXT` to `VARCHAR(N)` for all user-facing fields
- [ ] Enum-like fields converted to `VARCHAR(50)` or appropriate size
- [ ] URL fields get `CHECK (length(...) <= 2048)`
- [ ] Crypto fields get `CHECK (length(...) <= 16000)`
- [ ] XML/large content fields get `CHECK (length(...) <= 1000000)`
- [ ] Migration verifies no existing data exceeds the new limits before applying constraints
- [ ] All existing data fits within the proposed limits (pre-check query in migration)

**Phase 3: Best practices enforcement:**
- [ ] CLAUDE.md best practices updated to require `max_length` on all Pydantic `str` fields
- [ ] Compliance check (`scripts/compliance_check.py`) optionally flags Pydantic models without `max_length`
- [ ] Reference docs updated with standard length limits for each field category

**Tests:**
- [ ] Pydantic validation rejects strings exceeding max_length for each input schema
- [ ] Database rejects inserts/updates exceeding column limits
- [ ] All existing tests continue to pass (limits are generous enough for real data)

**Key files:**
- Modify: `app/schemas/api.py`, `app/schemas/saml.py`, `app/schemas/service_providers.py`, `app/schemas/oauth2.py`, `app/schemas/branding.py`, `app/schemas/settings.py`, `app/schemas/groups.py`
- New migration in `db-init/`
- Modify: `CLAUDE.md` (best practices), `.claude/references/compliance-patterns.md`, `.claude/references/owasp-patterns.md`

**Effort:** M
**Value:** High (Defense-in-depth against oversized payloads, data quality, DoS prevention)

