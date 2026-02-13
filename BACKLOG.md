# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## SAML IdP: Per-SP Entity ID in Metadata and Assertions

**User Story:**
As a super admin
I want the SAML IdP entity ID to match the per-SP metadata URL
So that downstream SPs can auto-discover metadata, validate assertions, and use the correct signing certificate without ambiguity

**Context:**

When an SP is given its per-SP metadata URL (e.g. `https://host/saml/idp/metadata/{sp_id}`), the entityID inside the metadata XML is `https://host/saml/idp/metadata` (without the SP ID). This mismatch causes problems: if an SP resolves the entityID URL to fetch metadata, it gets the tenant-level metadata with a potentially different signing certificate. The assertion Issuer also uses the tenant-level entity ID, which should match whatever metadata the SP consumed.

Three places construct the entity ID and all need updating for the per-SP case:

- `app/services/service_providers/metadata.py:94` (per-SP metadata XML generation)
- `app/services/service_providers/sso.py:135` (SAML assertion Issuer)
- `app/services/service_providers/signing_certs.py:167` (UI/API metadata URL info)

The tenant-level metadata endpoint (`/saml/idp/metadata`) is correct as-is since its URL already matches its entityID.

**Acceptance Criteria:**

- [ ] Per-SP metadata XML has `entityID="{base_url}/saml/idp/metadata/{sp_id}"`
- [ ] Tenant-level metadata XML keeps `entityID="{base_url}/saml/idp/metadata"` (unchanged)
- [ ] SAML assertion Issuer uses the per-SP entity ID when responding to an SP
- [ ] `get_sp_metadata_url_info()` returns the per-SP entity ID
- [ ] Existing tests updated to reflect per-SP entity ID
- [ ] All tests pass

**Effort:** S
**Value:** High (Fixes metadata/assertion mismatch that can break SP integrations)

---

## Group Membership UX Redesign

**User Story:**
As an admin
I want to manage group membership through a dedicated paginated member list with search and filtering
So that I can effectively manage groups of any size without silent truncation or unwieldy dropdowns

**Context:**

The current group detail page loads all members inline and uses a dropdown (capped at 100 users)
for adding members. This silently truncates results for tenants with more than 100 users and
provides no way to search, filter, or sort the member list. The existing tenant-wide user list
(`users_list.html`) provides a proven paginated pattern that should be replicated for group
membership management.

**Acceptance Criteria:**

**Group Detail Page (simplified):**

- [ ] Group detail shows member count, not the full member list
- [ ] Remove the inline member list and dropdown-based add/bulk-add forms
- [ ] Link/button to navigate to the dedicated group member list page

**Dedicated Group Member List Page:**

- [ ] Full-page paginated view of group members (modeled on users_list.html)
- [ ] Search by member name or email
- [ ] Filter by user role, status, auth method
- [ ] Sortable columns: name, email, role, status, joined date
- [ ] Per-page size selector (10, 25, 50, 100)
- [ ] Pagination controls (previous/next, page info)
- [ ] localStorage persistence for page size and filter preferences

**Add Members (from member list page):**

- [ ] "Add Members" action that opens a search/filter interface for eligible users
- [ ] Search and filter users NOT currently in the group
- [ ] Support adding single or multiple users
- [ ] Confirmation of additions with count

**Remove Members (from member list page):**

- [ ] Remove button per member row with confirmation
- [ ] Bulk remove option (select multiple, then remove)

**API Endpoints:**

- [ ] `GET /api/v1/groups/{group_id}/members` already exists (pagination supported)
- [ ] New: `GET /api/v1/groups/{group_id}/available-users?search=&role=&status=` for eligible non-members
- [ ] Existing bulk add/remove endpoints used by the new UI

**Event Logging:**

- [ ] Existing event logging for member add/remove continues to work
- [ ] No new event types needed

**Effort:** M
**Value:** High (Fixes silent data truncation, scales to any tenant size)

---

## SAML IdP: Single Logout (SLO) for Downstream SPs

**User Story:**
As a super admin
I want downstream SPs to be able to request logout from WeftId, and WeftId to propagate
logout to SPs when a user signs out
So that SSO sessions are properly terminated across all federated applications

**Context:**

The upstream SP side has full SLO support (both SP-initiated and IdP-initiated). But the
downstream IdP has no SLO capability. The IdP metadata XML has no SingleLogoutService
element. Enterprise SPs expect SLO. Without it, users remain logged into downstream SPs
after logging out of WeftId.

**Acceptance Criteria:**

**IdP Metadata:**

- [ ] Add `SingleLogoutService` element to IdP metadata (HTTP-Redirect and HTTP-POST bindings)
- [ ] SLO URL: `{base_url}/saml/idp/slo`

**SP-Initiated Logout (SP asks WeftId to log user out):**

- [ ] Handle incoming LogoutRequest at `/saml/idp/slo` (GET and POST)
- [ ] Validate LogoutRequest (issuer is a registered SP, signature if present)
- [ ] Terminate user's WeftId session
- [ ] Return LogoutResponse to SP's SLO URL
- [ ] Event log entry for SLO events

**IdP-Initiated Logout (WeftId propagates logout to SPs):**

- [ ] When user signs out from WeftId dashboard, send LogoutRequest to all SPs with active sessions
- [ ] Track which SPs have active SSO sessions per user (session store or DB)
- [ ] Best-effort delivery (don't block logout if an SP is unreachable)

**SP SLO Configuration:**

- [ ] Store SLO URL per SP (from metadata import or manual entry)
- [ ] SP detail page shows SLO URL

**Effort:** M
**Value:** High (Enterprise SP compliance, protocol completeness)

---

## SAML IdP: Include Group Membership in SSO Assertions

**User Story:**
As a super admin
I want WeftId to include a user's group memberships as attributes in SAML assertions
So that downstream SPs can use group claims for authorization decisions

**Context:**

Groups flow into WeftId from upstream IdPs (parsed and stored as IdP groups) but are not
included when WeftId issues assertions to downstream SPs. This breaks the federation bridge.
SPs that use group claims for role-based access cannot work with WeftId today.

**Acceptance Criteria:**

- [ ] Assertion includes group membership attribute (configurable attribute name, default `groups`)
- [ ] Includes both direct and inherited group memberships (via closure table)
- [ ] Configurable per SP: opt-in (some SPs don't want group claims)
- [ ] Group names sent as multi-valued attribute
- [ ] Toggle on SP detail page: "Include group memberships in assertions"
- [ ] API support for enabling/disabling group claims per SP

**Effort:** S
**Value:** Medium-High (Closes federation bridge gap)

---

## SAML Identity Provider - Phase 4: Attribute Mapping & NameID Configuration

**User Story:**
As a super admin
I want to customize attribute mappings and NameID format per application
So that I can integrate applications with non-standard attribute requirements

**Context:**

Earlier phases established the IdP with default attribute mappings (email, firstName, lastName). Some applications
expect different attribute names or formats. This phase adds per-SP customization for attribute mappings and
NameID format selection.

**Acceptance Criteria:**

**Per-SP Attribute Mapping:**

- [ ] Default attribute mappings remain: email, firstName, lastName with standard URIs
- [ ] Per-SP attribute mapping overrides (e.g., map `email` to
  `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`)
- [ ] Attribute mapping UI: list current mappings, add/edit/remove custom mappings
- [ ] Support for common IdP attribute URI formats (SAML 2.0 standard, Azure AD claims, custom)
- [ ] Preview: show what the assertion attributes will look like
- [ ] Attribute mapping presets for common SPs (Salesforce, ServiceNow, etc.)

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
    - Add `nameid_format` column to `service_providers`
    - Add `persistent_nameid` table for persistent NameID storage (user_id, sp_id, nameid_value)
- Update assertion generation to use custom mappings
- Event logging integration

**Dependencies:**

- SAML IdP Phase 3 complete

**Effort:** M
**Value:** Medium (Flexibility for production integrations)

**Notes:**

- NameID format is important for applications that use it as the primary user identifier
- Consider SAML debugging tools (assertion viewer) as separate backlog item, similar to upstream SAML Phase 4

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

