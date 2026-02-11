# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## SAML Identity Provider - Phase 3: Dashboard & App Assignment

**User Story:**
As a user
I want to see my assigned applications on my dashboard and launch them with a single click
So that I can access my work tools without remembering individual URLs

As an admin
I want to assign applications to specific users
So that I can control which users have access to which downstream applications

**Context:**

Phases 1 and 2 established the core IdP infrastructure with SP-initiated SSO and per-SP signing certificates. This phase
adds the user-facing experience: a "My Apps" dashboard section where users see and launch their assigned applications
(IdP-initiated SSO), plus the assignment model for admins to control access.

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

- SAML IdP Phase 2 complete (per-SP certificates)

**Effort:** M
**Value:** High (User-facing feature, admin control over access)

**Notes:**

- The "no assignments means all users" model provides backward compatibility
- Consider showing "Available to all" badge on unassigned SPs in admin view
- Dashboard My Apps section is the foundation for other dashboard content later

---

## SAML Identity Provider - Phase 4: Attribute Mapping & SP Management

**User Story:**
As a super admin
I want to customize attribute mappings per application and manage SP lifecycle
So that I can integrate applications with non-standard attribute requirements and maintain SPs over time

**Context:**

Earlier phases established the IdP with default attribute mappings (email, firstName, lastName). Some applications
expect different attribute names or formats. This phase adds per-SP customization and operational SP management
features.

**Acceptance Criteria:**

**Per-SP Attribute Mapping:**

- [ ] Default attribute mappings remain: email → standard URI, firstName → standard URI, lastName → standard URI
- [ ] Per-SP attribute mapping overrides (e.g., map `email` to
  `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`)
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

- SAML IdP Phase 3 complete

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

