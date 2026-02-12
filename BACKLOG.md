# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

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

## Tenant Mandala SVG in Navigation Header

**User Story:**
As a tenant user
I want to see a unique decorative mandala icon next to the WeftId product name
So that my tenant has a distinct visual identity within the application

**Acceptance Criteria:**
- [ ] Small SVG mandala (28-32px) appears to the left of "WeftId" in the top nav bar
- [ ] Mandala is deterministically generated from the tenant's UUID (same tenant always gets the same mandala)
- [ ] Different tenants get visually distinct mandalas
- [ ] Uses vibrant multi-color palette matching the Pageloom site repo style
- [ ] Supports light and dark mode
- [ ] Generated server-side in Python (no client-side JS dependency)
- [ ] Unit tests cover determinism, uniqueness, and valid SVG output

**Effort:** S
**Value:** Medium

---

