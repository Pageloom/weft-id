# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Integration Management Frontend - Phase 1: List & Create

**User Story:**
As an admin
I want to view existing OAuth2 integrations and create new ones through a web UI
So that I can set up Apps and B2B service accounts without using API calls directly

**Context:**

The backend API for OAuth2 client management already exists and is fully tested:
- `GET /api/v1/oauth2/clients` (list), `POST /api/v1/oauth2/clients` (create normal), `POST /api/v1/oauth2/clients/b2b` (create B2B)
- Service layer: `app/services/oauth2.py` with event logging
- Database layer: `app/database/oauth2.py` with tenant-scoped RLS
- Schemas: `app/schemas/oauth2.py`

What's missing is the admin UI and a few backend additions (`description` and `is_active` columns).

**Acceptance Criteria:**

**Navigation & Page Structure:**

- [ ] New "Integrations" item in Admin sub-navigation
- [ ] Two sub-tabs: "Apps" and "B2B"
- [ ] Accessible to Admin and Super Admin roles (matching existing API permissions)

**Database Enhancements:**

- [ ] Migration adds `description TEXT` column to `oauth2_clients`
- [ ] Migration adds `is_active BOOLEAN NOT NULL DEFAULT true` column to `oauth2_clients` (prep for Phase 2 soft-delete)
- [ ] Existing API endpoints include `description` and `is_active` in responses
- [ ] Create endpoints accept optional `description` field

**Apps Tab (Normal OAuth2 Clients):**

- [ ] List view showing: Name, Client ID, Redirect URIs count, Created At, Status (active/inactive badge)
- [ ] "Create App" button opens modal form
- [ ] Creation form: Name (required), Description (optional), Redirect URIs (textarea, one per line)
- [ ] On successful creation: credentials modal shows Client ID and Client Secret with copy buttons
- [ ] Credentials displayed via session (one-time read, never in URLs)
- [ ] Dismiss button: "I've saved the credentials" (no ESC/backdrop dismiss for credentials modal)

**B2B Tab (Service Accounts):**

- [ ] List view showing: Name, Client ID, Service Role, Created At, Status badge
- [ ] "Create B2B Client" button opens modal form
- [ ] Creation form: Name (required), Description (optional), Role (select: member/admin/super_admin)
- [ ] Same credentials display flow as Apps tab

**Testing:**

- [ ] Router tests for all routes (list, create, auth, error handling)
- [ ] Service tests for updated functions (type filter, description param)
- [ ] API tests updated for new response fields
- [ ] Database tests for new columns and filters

**Backend Changes:**

- Database migration: `db-init/00026_oauth2_client_enhancements.sql`
- Update `app/database/oauth2.py`: add `client_type` filter and `active_only` filter to `get_all_clients`, add `description` to create functions and all SELECT/RETURNING clauses
- Update `app/services/oauth2.py`: pass through `client_type` and `description` params
- Update `app/schemas/oauth2.py`: add `description` and `is_active` fields
- Update `app/routers/api/v1/oauth2_clients.py`: include new fields in responses
- New frontend router: `app/routers/integrations.py`
- New templates: `app/templates/integrations_apps.html`, `app/templates/integrations_b2b.html`
- Register pages in `app/pages.py`, router in `app/main.py`

**Effort:** M
**Value:** High

---

## Integration Management Frontend - Phase 2: Edit, Regenerate & Deactivate

**User Story:**
As an admin
I want to edit integration details, rotate secrets, and deactivate integrations through the web UI
So that I can manage the full lifecycle of OAuth2 clients without API calls

**Context:**

Phase 1 delivers list and create functionality. This phase adds the remaining CRUD operations: editing client details, regenerating secrets, and soft-delete (deactivation). The `is_active` column is already added in Phase 1's migration.

**Acceptance Criteria:**

**Apps Tab - Edit & Manage:**

- [ ] Click client row to open detail/edit view
- [ ] Edit form: Name, Description, Redirect URIs
- [ ] "Regenerate Secret" with confirmation dialog, then credentials modal (same flow as create)
- [ ] "Deactivate" button with confirmation (soft-delete: sets `is_active = false`)
- [ ] Inactive clients shown in list with "Inactive" badge, grayed out
- [ ] Option to reactivate inactive clients

**B2B Tab - Edit & Manage:**

- [ ] Click client row to open detail/edit view
- [ ] Edit form: Name, Description
- [ ] Change service user role (select dropdown)
- [ ] "Regenerate Secret" with same flow
- [ ] "Deactivate" with same soft-delete flow
- [ ] Inactive clients shown with badge

**Backend Changes:**

- [ ] `PATCH /api/v1/oauth2/clients/{client_id}` endpoint for updating name, description, redirect_uris
- [ ] `PATCH /api/v1/oauth2/clients/{client_id}/role` endpoint for changing B2B service user role
- [ ] `PATCH /api/v1/oauth2/clients/{client_id}/deactivate` endpoint (sets is_active = false)
- [ ] `PATCH /api/v1/oauth2/clients/{client_id}/reactivate` endpoint (sets is_active = true)
- [ ] Deactivated clients reject OAuth2 token requests
- [ ] All write operations emit event logs

**Testing:**

- [ ] Full test coverage for new API endpoints
- [ ] Router tests for edit, regenerate, deactivate flows
- [ ] Service tests for update, deactivate, reactivate logic
- [ ] Verify deactivated clients cannot authenticate

**Dependencies:**

- Integration Management Frontend - Phase 1 complete

**Effort:** M
**Value:** High

---

## Organizational Structure & Grouping System

**User Story:**
As an admin or user of the identity platform
I want to organize people into flexible hierarchical structures and ad-hoc groups
So that downstream applications can bootstrap teams, channels, and access controls based on organizational context

**Acceptance Criteria:**

**Hierarchical Organizational Structure:**

- [ ] Support 1-6 levels of organizational hierarchy (hard cap at 6 levels)
- [ ] Each level has a customizable type name (e.g., "Organization", "Business Unit", "Department", "Team")
- [ ] Default level names: Organization → Business Unit → Department → Team
- [ ] Admins can rename level types (e.g., "Business Unit" → "Division")
- [ ] Each organizational unit within a level has its own name (e.g., "Engineering Department", "Platform Team")
- [ ] Organizations can skip levels (e.g., Organization → Team directly)
- [ ] Users can belong to multiple organizational units across different branches simultaneously
- [ ] All users can view the complete organizational structure
- [ ] Only Super Admins and Admins can create/edit/delete organizational units
- [ ] Only Super Admins and Admins can add/remove people to/from organizational units

**Ad-hoc Groups:**

- [ ] Any user can create ad-hoc groups (e.g., "Security Champions", "Project Phoenix")
- [ ] Group creator sets visibility: Public (visible to all) or Private (visible to members only)
- [ ] Group creator can invite and uninvite members
- [ ] Other users can invite to ad-hoc groups but cannot uninvite (unless they're admins)
- [ ] Super Admins and Admins can see all ad-hoc groups regardless of visibility
- [ ] Super Admins and Admins can manage membership and change visibility of any ad-hoc group
- [ ] Regular users see: public groups + private groups they're members of
- [ ] Ad-hoc groups transcend hierarchical boundaries (cross-functional)

**User Profile & Titles:**

- [ ] Users can have an optional "title" field (e.g., "Senior Engineer", "VP of Sales")
- [ ] All users can view their own organizational placement (units and groups)
- [ ] User profile displays: hierarchical placement(s), ad-hoc group memberships, and title
- [ ] Existing roles (Super Admin, Admin, User) remain unchanged - they control IdP permissions only

**API/Data Exposure:**

- [ ] API endpoints to query organizational structure
- [ ] API endpoints to list members of any organizational unit or group
- [ ] Enable downstream applications to consume org structure (e.g., auto-create chat channels)
- [ ] Future: Support syncing org structure from upstream IdPs (optional input) - not in MVP

**Out of Scope (for MVP):**

- Manager-employee relationship tracking
- Reporting structure and approval chains
- Org chart visualization UI
- Bulk import of organizational structure
- Syncing from upstream IdPs (Okta, Azure AD, etc.)
- Organizational unit permissions/access control within the IdP

**Technical Implementation:**

- Database migration: New tables for org units, org levels, groups, memberships
- Database schema:
    - `org_levels`: id, tenant_id, level_number (1-6), level_name, created_at
    - `org_units`: id, tenant_id, level_id, parent_unit_id, name, created_at
    - `org_memberships`: user_id, org_unit_id, joined_at
    - `groups`: id, tenant_id, name, is_public, creator_user_id, created_at
    - `group_memberships`: user_id, group_id, joined_at
- New router: `app/routers/organization.py`
- New database module: `app/database/organization.py`
- Update user profile endpoints to include org data
- UI pages for managing org structure (admin only)
- UI for creating/managing ad-hoc groups (all users)
- UI for viewing org structure (all users)

**Dependencies:**

- None (pure backend/database work)

**Effort:** XL (2-3 weeks)
**Value:** High (Core MVP Feature - Foundation for IdP)

**Notes:**

- This is foundational for the MVP identity platform
- Enables downstream applications to leverage organizational context
- Flexible enough to support various org models (flat to deeply nested)
- Balance between admin control (hierarchy) and user empowerment (ad-hoc groups)
- Data model should be extensible for future upstream IdP sync

---

## SAML Identity Provider - Phase 1: Core IdP (SP-Initiated SSO)

**User Story:**
As a super admin
I want to register downstream applications as SAML Service Providers
So that those applications can authenticate users via SSO against my tenant's identity provider

**Context:**

This is the foundational phase of making the platform act as a SAML Identity Provider. Currently the platform federates with upstream IdPs (Okta, Azure AD, etc.). This feature enables the reverse: downstream applications trust this platform as their IdP. How users actually authenticate internally (password, MFA, upstream IdP) is opaque to the downstream SP.

**Acceptance Criteria:**

**Service Provider Registration:**

- [ ] Super admin can register downstream apps (SPs) via:
  - Pasted SAML metadata XML
  - Metadata URL (fetched and parsed)
- [ ] Metadata parsing extracts: Entity ID, ACS URL(s), SP certificate (if present), NameID format
- [ ] Manual fallback: if metadata incomplete, allow manual entry of Entity ID and ACS URL
- [ ] SP has name field (required) for display purposes
- [ ] Basic SP list view (super admin only): Name, Entity ID, Created At
- [ ] Delete SP (for correcting mistakes)

**IdP Metadata Exposure:**

- [ ] Tenant-specific IdP metadata endpoint: `GET /saml/idp/metadata`
- [ ] Metadata includes: Entity ID, SSO endpoint URL, signing certificate, supported NameID formats
- [ ] Downloadable as XML file
- [ ] Copyable metadata URL for SP configuration

**SP-Initiated SSO Flow:**

- [ ] SSO endpoint: `POST/GET /saml/idp/sso` receives SAML AuthnRequest
- [ ] Parse and validate AuthnRequest (issuer must match registered SP)
- [ ] If user has no active session: redirect to login page, then return to SSO flow
- [ ] If user has active session: show consent screen
- [ ] Consent screen displays: app name, attributes being shared (email, first name, last name)
- [ ] "Continue" proceeds with assertion; "Cancel" returns to dashboard

**SAML Assertion Generation:**

- [ ] Generate signed SAML Response with Assertion
- [ ] Default attribute mappings: email, firstName, lastName (standard SAML attribute URIs)
- [ ] NameID set to user's email (format: emailAddress)
- [ ] Assertion signed with tenant's certificate (reuse existing SAML certificate infrastructure)
- [ ] POST assertion to SP's ACS URL via auto-submitting form

**Access Model (Phase 1):**

- [ ] All authenticated users in the tenant can access all registered SPs
- [ ] No per-user assignment in this phase (comes in Phase 2)

**Technical Implementation:**

- Database migration:
  - `service_providers`: id, tenant_id, name, entity_id, acs_url, certificate, metadata_xml, created_at
- New router: `app/routers/saml_idp.py` (separate from `saml.py` which handles upstream)
- New service: `app/services/saml_idp.py`
- New database module: `app/database/service_providers.py`
- SAML assertion generation using existing `python3-saml` library
- Signing with tenant's existing SAML certificate
- UI: SP registration form, SP list, consent screen

**Dependencies:**

- Existing SAML infrastructure (certificates, python3-saml library)
- Organizational Structure & Grouping System (recommended before Phase 2)

**Effort:** L
**Value:** High (Core IdP capability - enables downstream app integration)

**Notes:**

- This phase delivers a working IdP that integrators can test against
- The "all users can access all SPs" model is intentionally simple for Phase 1
- Study existing upstream IdP registration flow in `app/routers/saml.py` for patterns

---

## SAML Identity Provider - Phase 2: Dashboard & App Assignment

**User Story:**
As a user
I want to see my assigned applications on my dashboard and launch them with a single click
So that I can access my work tools without remembering individual URLs

As an admin
I want to assign applications to specific users
So that I can control which users have access to which downstream applications

**Context:**

Phase 1 established the core IdP infrastructure with SP-initiated SSO. This phase adds the user-facing experience: a "My Apps" dashboard section where users see and launch their assigned applications (IdP-initiated SSO), plus the assignment model for admins to control access.

**Acceptance Criteria:**

**App Assignment Model:**

- [ ] Super admins and admins can assign SPs to individual users
- [ ] Assignment UI: select SP, then select users to assign
- [ ] View assignments per SP (list of assigned users)
- [ ] Remove assignments
- [ ] Bulk assignment: select multiple users at once

**Access Control:**

- [ ] If an SP has any assignments: only assigned users can access it
- [ ] If an SP has no assignments: all authenticated tenant users can access it (backward compatible with Phase 1)
- [ ] SP-initiated SSO validates user has access before showing consent screen
- [ ] Unauthorized access shows clear error message

**User Dashboard - My Apps:**

- [ ] "My Apps" section on user dashboard (visible to all users)
- [ ] Shows all SPs the user has access to (direct assignment or no-assignment-means-all)
- [ ] App display: name, optional description
- [ ] Click app tile to launch (IdP-initiated SSO)
- [ ] Empty state when user has no accessible apps: "No applications available"

**IdP-Initiated SSO:**

- [ ] Launching from dashboard generates SAML Response without prior AuthnRequest
- [ ] Same consent screen as SP-initiated flow
- [ ] RelayState optional (can be configured per SP for deep linking, future enhancement)
- [ ] POST assertion to SP's ACS URL

**SP Enhancements:**

- [ ] Add description field to SPs (optional, shown in dashboard)
- [ ] Add icon/logo URL field (optional, for future dashboard display)

**Technical Implementation:**

- Database migration:
  - `sp_assignments`: id, sp_id, user_id, assigned_by, assigned_at
  - Add `description` column to `service_providers`
- Update `app/services/saml_idp.py` with assignment logic
- Update `app/database/service_providers.py` with assignment queries
- Dashboard template updates for My Apps section
- Assignment management UI (admin pages)

**Dependencies:**

- SAML IdP Phase 1 complete

**Effort:** M
**Value:** High (User-facing feature, admin control over access)

**Notes:**

- The "no assignments means all users" model provides backward compatibility
- Consider showing "Available to all" badge on unassigned SPs in admin view
- Dashboard My Apps section is the foundation for other dashboard content later

---

## SAML Identity Provider - Phase 3: Attribute Mapping & SP Management

**User Story:**
As a super admin
I want to customize attribute mappings per application and manage SP lifecycle
So that I can integrate applications with non-standard attribute requirements and maintain SPs over time

**Context:**

Phases 1 and 2 established the IdP with default attribute mappings (email, firstName, lastName). Some applications expect different attribute names or formats. This phase adds per-SP customization and operational SP management features.

**Acceptance Criteria:**

**Per-SP Attribute Mapping:**

- [ ] Default attribute mappings remain: email → standard URI, firstName → standard URI, lastName → standard URI
- [ ] Per-SP attribute mapping overrides (e.g., map `email` to `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`)
- [ ] Attribute mapping UI: list current mappings, add/edit/remove custom mappings
- [ ] Support for common IdP attribute URI formats (SAML 2.0 standard, Azure AD claims, custom)
- [ ] Preview: show what the assertion attributes will look like

**SP Management:**

- [ ] Edit SP configuration: name, description, ACS URL
- [ ] Enable/disable SPs (disabled SPs reject SSO requests with clear error)
- [ ] Re-import metadata (update SP config from new metadata XML or URL)
- [ ] Delete SP with confirmation (warns about active assignments)

**NameID Configuration:**

- [ ] Per-SP NameID format selection: emailAddress (default), persistent, transient, unspecified
- [ ] Persistent NameID generates stable opaque identifier per user-SP pair
- [ ] Transient NameID generates new identifier per session

**Error Handling & Troubleshooting:**

- [ ] Clear error messages for common SAML failures (unknown SP, disabled SP, unauthorized user)
- [ ] Event log entries for SSO attempts (success and failure) with SP name
- [ ] Super admin can view recent SSO events per SP

**Technical Implementation:**

- Database migration:
  - `sp_attribute_mappings`: id, sp_id, internal_attribute, saml_attribute_uri
  - Add `enabled`, `nameid_format` columns to `service_providers`
  - Add `persistent_nameid` table for persistent NameID storage (user_id, sp_id, nameid_value)
- Update assertion generation to use custom mappings
- SP edit/management UI
- Event logging integration

**Dependencies:**

- SAML IdP Phase 2 complete

**Effort:** M
**Value:** Medium (Flexibility for production integrations)

**Notes:**

- Attribute mapping presets for common SPs (Salesforce, ServiceNow, etc.) could be a future enhancement
- NameID format is important for applications that use it as the primary user identifier
- Consider SAML debugging tools (assertion viewer) as separate backlog item, similar to upstream SAML Phase 4

---

## Multi-Region Tenant Routing Infrastructure

**User Story:**
As a platform operator
I want to route tenant requests to their assigned datacenter based on subdomain
So that I can guarantee data residency in specific regions and enable future geographic distribution

**Acceptance Criteria:**

- [ ] Global routing layer (Cloudflare Workers or similar) intercepts all `*.pageloom.com` requests
- [ ] Routing layer queries tenant-to-region mapping to determine which datacenter hosts the tenant
- [ ] Requests are proxied/routed to the appropriate regional application instance
- [ ] Tenant-to-region mapping service is lightweight and globally accessible (e.g., Cloudflare KV, global database, or
  API)
- [ ] Each tenant is permanently assigned to one region (tenant-pinned strategy)
- [ ] Support for manually moving a tenant to a different region (updates mapping, data migration handled separately)
- [ ] All tenant data is isolated by `tenant_id` (already implemented) to enable clean regional separation
- [ ] Health checks and fallback routing if a region is unavailable
- [ ] Documentation on how to add a new region to the infrastructure
- [ ] Wildcard SSL certificate for `*.pageloom.com` configured

**Out of Scope (for this item):**

- Actual data migration tooling when moving tenants between regions
- GDPR/compliance documentation
- Multi-region database replication

**Technical Implementation:**

- Cloudflare DNS with wildcard SSL (`*.pageloom.com`)
- Cloudflare Workers for edge routing logic
- Tenant-to-region mapping store (recommend: Cloudflare KV or lightweight API)
- Regional application instances (DigitalOcean App Platform or Droplets)
- Update nginx/application configuration for region awareness
- Deployment automation for multiple regions

**Dependencies:**

- Cloudflare account with Workers capability
- Multiple DigitalOcean regions provisioned

**Effort:** XL (multi-week effort, significant infrastructure work)
**Value:** High (Scalability, Data Sovereignty)

**Notes:**

- Foundation for data residency guarantees
- Enables future compliance requirements (GDPR, etc.)
- Tenant IDs are globally unique, facilitating future tenant migrations

---

## Internationalization (i18n) Support

**User Story:**
As a platform operator
I want to serve the application in multiple languages
So that users can interact with the platform in their preferred language

**Acceptance Criteria:**

**Core Infrastructure:**

- [ ] Translation framework integrated (Babel + Flask-Babel or similar for FastAPI/Jinja2)
- [ ] Message extraction configured for Python code and Jinja2 templates
- [ ] Translation files stored in `locales/` directory using standard `.po`/`.mo` format
- [ ] English (en) as base language with all strings extracted
- [ ] At least one additional language fully translated for MVP (suggest: Spanish, French, or German)

**Language Detection & Selection:**

- [ ] User preference stored in database (`preferred_language` column on users table)
- [ ] Tenant default language setting (fallback when user has no preference)
- [ ] Browser `Accept-Language` header detection (fallback when no user/tenant preference)
- [ ] Language switcher UI component (accessible from all pages)
- [ ] Language preference persists across sessions

**Translated Content:**

- [ ] All UI text in templates (buttons, labels, headings, navigation)
- [ ] Flash messages and inline validation errors
- [ ] Email templates (subject lines and body content)
- [ ] Date/time formatting localized per locale
- [ ] Number formatting localized per locale (future: currency if needed)

**Developer Experience:**

- [ ] `make extract-messages` command to extract translatable strings
- [ ] `make compile-messages` command to compile `.po` to `.mo`
- [ ] Documentation on adding new translatable strings
- [ ] Documentation on adding a new language

**Out of Scope:**

- API response message translation (API returns English, clients handle i18n)
- User-generated content translation
- Right-to-left (RTL) language support (can be added later)
- Machine translation integration
- Translation management UI (use external tools like Weblate, POEditor)
- Pluralization rules beyond basic (singular/plural)

**Technical Implementation:**

- Database migration: Add `preferred_language` to users table, `default_language` to tenant settings
- Install `Babel` package for extraction and locale management
- Jinja2 integration with `_()` or `gettext()` function
- Middleware to set locale per request based on preference hierarchy
- Update all templates to use translation functions
- Create `locales/` directory structure
- Add extraction configuration (`babel.cfg`)

**Dependencies:**

- `Babel` package
- `python-i18n` or custom FastAPI middleware

**Effort:** L
**Value:** Medium (Expands Addressable Market)

**Notes:**

- Start with a single additional language to validate the pipeline
- Keep translation keys close to English text (not abstract keys) for maintainability
- Consider hiring professional translators for production languages

---

## Privileged Domain Verification via DNS TXT Records

**User Story:**
As a super admin
I want to verify ownership of privileged email domains via DNS TXT records
So that only domains I actually control can bypass email verification, preventing security vulnerabilities

**Acceptance Criteria:**

- [ ] Super admin can add privileged domains which are created in an "unverified" state
- [ ] System generates a unique verification token (32-char random string) for each domain
- [ ] UI displays verification instructions: "Add this TXT record to your DNS: `loom-verify=<token>`"
- [ ] "Verify Domain" button triggers on-demand DNS TXT record lookup
- [ ] When matching TXT record is found, domain is marked as verified with timestamp
- [ ] Unverified domains are visible but marked as "pending verification"
- [ ] Regular admins can view privileged domains and their verification status (read-only)
- [ ] Periodic background job re-verifies all verified domains (e.g., daily/weekly)
- [ ] If re-verification fails, domain status changes to "verification failed" (with alert/notification)
- [ ] Auto-verification of new user emails works regardless of domain verification status (future features may restrict
  this)
- [ ] Users who were previously verified remain verified even if domain verification later fails
- [ ] Database tracks: verification_token, verified (boolean), verified_at (timestamp)

**Technical Implementation:**

- Database migration: `00009_domain_verification.sql`
- DNS utility: `app/utils/dns.py` (using dnspython package)
- Update: `app/database/settings.py`
- New endpoint: verification route in settings router
- UI updates: settings template showing verification status and instructions
- Background job: domain re-verification cron task

**Dependencies:**

- `dnspython` package

**Effort:** L
**Value:** Low

---

## E2E Test Suite with Playwright (Tentative)

**Status:** Tentative - Considering for future implementation

**User Story:**
As a platform operator
I want browser-based end-to-end tests for critical authentication flows
So that I have baseline assurance that SAML SSO and other auth flows work correctly in a real browser

**Context:**

Currently the codebase has:
- Unit tests (service layer)
- Integration tests (TestClient-based)
- One "E2E-like" test file (`test_mfa_e2e.py`) using TestClient + maildev

True browser-based E2E tests would provide:
- Confidence that JavaScript interactions work (tab switching, copy-to-clipboard, form validation)
- Full SAML flow testing against SimpleSAMLphp (which is already containerized)
- Regression safety net for critical auth paths

**Acceptance Criteria:**

**Infrastructure:**

- [ ] New `tests/e2e/` directory separate from unit/integration tests
- [ ] Playwright (Python) for browser automation
- [ ] `pytest-playwright` integration
- [ ] Makefile targets: `test-e2e`, `test-e2e-debug`, `test-unit`
- [ ] Auto-skip when SimpleSAMLphp not running

**Initial Test Coverage (SAML auth flow only):**

- [ ] Successful SAML login creates session
- [ ] User not in DB shows "Account Not Found" error
- [ ] Wrong IdP credentials keeps user at IdP
- [ ] Single IdP auto-redirects (no selection page)
- [ ] SSO button appears when IdP enabled
- [ ] Disabled IdP shows error
- [ ] Invalid IdP ID shows not found
- [ ] Session persists across navigation

**Dependencies:**

New dev dependencies:
- `playwright = "^1.40.0"`
- `pytest-playwright = "^0.4.0"`

Post-install: `playwright install chromium`

**Technical Notes:**

- Uses SimpleSAMLphp container already in docker-compose
- Test users pre-configured in `simplesamlphp/authsources.php`
- Requires `ignore_https_errors=True` for self-signed dev certs
- Reuses existing `test_tenant`, `test_super_admin_user` fixtures

**Effort:** M
**Value:** Medium (Quality assurance, regression safety)

**Notes:**

- This is tentative - the dependency footprint (Playwright + browser binaries) is non-trivial
- Consider implementing when SAML Phase 2+ is complete and flows are stable
- Alternative: Continue using TestClient-based integration tests which are faster
- Could start with just SAML flow and expand to other auth flows later

---

