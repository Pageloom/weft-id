# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## Integration Management Frontend (Apps & B2B)

**User Story:**
As a super admin
I want to manage OAuth2 clients (Apps) and B2B service accounts through a web UI
So that I can configure integrations without using API calls directly

**Acceptance Criteria:**

**Navigation & Page Structure:**

- [ ] New "Integration" item in Admin navigation
- [ ] Two sub-tabs: "Apps" and "B2B"
- [ ] Super Admin only access

**Apps Tab (Normal OAuth2 Clients):**

- [ ] List view showing: Name, Client ID, Created At
- [ ] "Create App" button opens creation form
- [ ] Creation form: Name (required), Description (optional), Redirect URIs (multiple allowed)
- [ ] On successful creation: show credentials once with checkbox "I have copied the information and stored it securely" to enable proceed button
- [ ] Edit existing app: Name, Description, Redirect URIs
- [ ] Regenerate secret with confirmation, same "copied securely" checkbox flow
- [ ] Delete app with confirmation dialog

**B2B Tab (Service Accounts):**

- [ ] List view showing: Name, Client ID, Role, Created At
- [ ] "Create B2B Client" button opens creation form
- [ ] Creation form: Name (required), Description (optional), Role (member/admin/super_admin)
- [ ] On successful creation: show credentials once with same "copied securely" checkbox flow
- [ ] Edit existing B2B client: Name, Description
- [ ] Change service user role (any super admin can do this)
- [ ] Regenerate secret with confirmation, same flow
- [ ] Delete B2B client with confirmation dialog

**Credentials Display (both tabs):**

- [ ] After create or regenerate: modal shows Client ID and Client Secret
- [ ] Checkbox: "I have copied the information and stored it securely"
- [ ] Checkbox must be checked to enable "Proceed" button
- [ ] Proceeding returns to the list view

**Backend Changes Required:**

- Database migration: Add `description TEXT` column to `oauth2_clients` table
- `PATCH /api/v1/oauth2/clients/{client_id}` endpoint for updating name, description, redirect_uris
- Endpoint to update B2B service user role
- Modify create/list endpoints to include description field

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
