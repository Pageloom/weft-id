# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## SP Metadata Lifecycle Management

**User Story:**
As a super admin
I want to refresh SP metadata from its original source and review what changed
So that I can keep SP configurations up to date without re-entering everything manually

**Context:**

SP metadata XML is already stored on import, but the source URL is not persisted. Admins have no way to refresh metadata or review stored XML after initial import. This item adds metadata URL persistence, a read-only XML viewer, and refresh workflows with change previews.

**Acceptance Criteria:**

- [ ] DB migration: add `metadata_url` column to service providers table
- [ ] On SP creation via metadata URL: persist the metadata URL alongside the fetched metadata XML
- [ ] On SP creation via pasted XML: persist the pasted metadata XML (already done via `metadata_xml` column)
- [ ] On manual entry: no metadata to store
- [ ] SP detail page: view the full stored metadata XML (read-only, collapsible code block)
- [ ] SP with stored metadata URL: "Refresh from URL" action that re-fetches metadata and shows a preview/diff of what would change (ACS URL, SLO URL, certificate, requested attributes, attribute mapping) before applying
- [ ] SP with stored XML but no URL: "Re-import metadata" action where admin can paste new XML and preview changes before applying
- [ ] SP with neither: no metadata refresh available, manual editing only
- [ ] API endpoints for metadata refresh and re-import

**Effort:** M
**Value:** High (Keeps SP configurations current without manual re-entry)

---

## Attribute Mapping UX Improvements

**User Story:**
As a super admin
I want clearer labels and smarter layout on the attribute mapping screen
So that I can understand how user attributes are communicated to the SP without needing SAML expertise

**Context:**

Per-SP attribute mapping from metadata was recently implemented (parsing `RequestedAttribute` elements, auto-detection, editable mapping UI, per-SP assertion URIs). The current labels use technical SAML terminology and the layout shows an empty "SP Expectation" column even when no metadata is on file.

**Acceptance Criteria:**

- [ ] Rename "Assertion Attribute Mapping" to "User Attribute Mapping" throughout the UI
- [ ] Use friendlier description: "Configure how user attributes are communicated to the service provider during sign-in." instead of technical SAML jargon
- [ ] If no SP expectations are on file, hide the "SP Expectation" column entirely rather than showing "None declared" for every row
- [ ] For each attribute row, clearly indicate whether it matches the SP's declared expectations (when metadata is on file)

**Effort:** XS
**Value:** High (Reduces admin confusion on a frequently used screen)

---

## Default Attribute Names

**User Story:**
As a super admin
I want attribute names to use friendly labels like `email` and `firstName` by default
So that attribute mapping is intuitive and matches what most service providers expect

**Context:**

Weft ID currently uses OID-based URIs (`urn:oid:0.9.2342.19200300.100.1.3`, etc.) as default attribute names. Most modern SPs expect simpler names. This change affects both the IdP assertion builder and the IdP metadata attribute declarations.

**Acceptance Criteria:**

- [ ] Change `SAML_ATTRIBUTE_URIS` in `saml_assertion.py` from OID-based URIs to friendly names: `email`, `firstName`, `lastName`, `groups`
- [ ] Update IdP metadata attribute declarations in `saml_idp.py` to match
- [ ] Existing per-SP attribute overrides continue to work (only the defaults change)

**Effort:** XS
**Value:** Medium (Better out-of-the-box experience for new SP registrations)

---

## De-emphasize Manual SP Entry

**User Story:**
As a super admin
I want metadata import to be the primary path when registering a new SP
So that I am guided toward the approach that produces better, more complete configurations

**Context:**

The current SP registration UI presents manual entry, URL import, and XML import as equal options. Metadata-based registration produces significantly better results (auto-populates ACS URL, certificates, requested attributes). Manual entry should still be available but visually secondary.

**Acceptance Criteria:**

- [ ] SP registration UI: metadata import tabs (URL and XML) are the primary/default view
- [ ] Manual entry is available but visually de-emphasized (e.g., collapsed section, secondary styling, or "Advanced" label)
- [ ] No functional changes to manual entry, only UI prominence

**Effort:** XS
**Value:** Medium (Guides admins toward metadata-based registration)

---

## Per-SP NameID Configuration

**User Story:**
As a super admin
I want to configure the NameID format for each service provider
So that each SP receives user identifiers in the format it expects

**Context:**

Currently all SPs receive emailAddress as the NameID format. Some SPs require persistent (stable opaque identifier) or transient (per-session) NameIDs. Persistent NameID requires a new database table to store stable user-SP identifier pairs.

**Acceptance Criteria:**

- [ ] Per-SP NameID format selection: emailAddress (default), persistent, transient, unspecified
- [ ] Persistent NameID: generates a stable opaque identifier per user-SP pair, stored in a new `sp_nameid_mappings` table
- [ ] Transient NameID: generates a new identifier per session (not persisted)
- [ ] DB migration: add NameID format column to service providers, create `sp_nameid_mappings` table
- [ ] SSO assertion builder uses the configured NameID format
- [ ] API support for NameID configuration on SP endpoints

**Effort:** M
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

**Effort:** XS
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

## SAML Smoketest: Manual Testing Pattern & Future Automation

**User Story:**
As a developer
I want a documented manual testing pattern for both SAML IdP and SP flows using SAMLtest.id
So that I can verify SAML integration works end-to-end without maintaining a local IdP simulator

As a platform operator
I want automated Playwright-based smoketests for SAML SSO flows
So that regressions in critical auth paths are caught before deployment

**Context:**

The project previously used SimpleSAMLphp in docker-compose for manual SAML testing, but it was removed in favor of SAMLtest.id (a free hosted SAML testing service that acts as both IdP and SP). This item establishes a manual testing pattern first, then automates it.

**Phase 1: Manual Testing Pattern (SAMLtest.id)**

- [ ] Document SP-side testing: configure SAMLtest.id as upstream IdP, verify login flow
- [ ] Document IdP-side testing: register SAMLtest.id as downstream SP, verify SSO assertion delivery
- [ ] Document metadata exchange process (upload Weft ID metadata to SAMLtest.id, download theirs)
- [ ] Verify both SP-initiated and IdP-initiated SSO flows work
- [ ] Verify per-SP signing certificates are correctly used in assertions

**Phase 2: Automated Smoketests (Playwright)**

- [ ] New `tests/e2e/` directory separate from unit/integration tests
- [ ] Playwright (Python) for browser automation with `pytest-playwright`
- [ ] Makefile targets: `test-e2e`, `test-e2e-debug`, `test-unit`
- [ ] SP-side smoketest: SAML login via SAMLtest.id IdP creates session
- [ ] IdP-side smoketest: SAMLtest.id SP receives valid assertion from Weft ID
- [ ] Auto-skip when SAMLtest.id is unreachable
- [ ] Cross-tenant test option: Tenant A as IdP serving Tenant B as SP (no external dependency)

**Dependencies:**

New dev dependencies (Phase 2 only):

- `playwright = "^1.40.0"`
- `pytest-playwright = "^0.4.0"`

Post-install: `playwright install chromium`

**Effort:** S (Phase 1), M (Phase 2)
**Value:** High (Catches SAML regressions that unit tests cannot)

**Notes:**

- SAMLtest.id is free and hosted, no local infrastructure needed
- Cross-tenant testing (Weft ID as both IdP and SP) is a good offline fallback
- Phase 1 can be done immediately; Phase 2 when SAML flows are stable

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

