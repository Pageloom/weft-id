# Product Backlog

This document tracks planned features, improvements, and technical debt for the project.

For completed items, see [BACKLOG_ARCHIVE.md](BACKLOG_ARCHIVE.md).

---

## User Inactivation & GDPR Anonymization

**User Story:**
As a platform operator
I want to inactivate users (with optional GDPR anonymization)
So that I can disable access for departed users while maintaining audit trails, and comply with right-to-be-forgotten requests

**Acceptance Criteria:**

**User Inactivation:**

- [ ] Add `is_inactivated` boolean column to users table (default: false)
- [ ] Inactivated users cannot sign in (blocked at authentication layer)
- [ ] Inactivated users retain all their data (email, name, etc.)
- [ ] Admins can reactivate inactivated users
- [ ] Inactivated users still appear in logs and user lists (marked as inactivated)

**GDPR Anonymization:**

- [ ] Add `is_anonymized` boolean column to users table (default: false)
- [ ] Anonymization = inactivation + PII scrubbed
- [ ] Anonymized users have email, name, and other PII removed/replaced
- [ ] Anonymized users cannot be reactivated (irreversible)
- [ ] UUID is preserved - logs continue to reference the anonymized user record
- [ ] Anonymized user record displays as "[Anonymized User]" or similar in UI contexts

**Admin Controls:**

- [ ] Admin UI to inactivate/reactivate users
- [ ] Admin UI to anonymize users (with confirmation - irreversible)
- [ ] Clear visual distinction between inactivated vs anonymized users

**Audit Trail Integrity:**

- [ ] Event logs retain user UUID references regardless of inactivation/anonymization
- [ ] Looking up an anonymized user by UUID returns the anonymized record (not null)

**Out of Scope:**

- Self-service GDPR deletion requests
- Automated anonymization workflows
- Bulk inactivation/anonymization

**Effort:** M
**Value:** High (Compliance/GDPR Foundation)

---

## Service Layer Event Logging

**User Story:**
As a platform operator
I want all write operations in the service layer to be logged to a database table
So that I have a complete audit trail for compliance, debugging, and future user-facing activity history

**Acceptance Criteria:**

**Core Logging:**

- [ ] New `event_logs` table captures all service layer write operations
- [ ] Each log entry includes: `tenant_id`, `actor_user_id`, `artifact_type`, `artifact_id`, `event_type`, `metadata` (JSON), `created_at`
- [ ] Event types are descriptive strings (e.g., `user_created`, `email_updated`, `mfa_enabled`) - not DB-enforced enums
- [ ] Artifact type identifies the entity (e.g., `user`, `privileged_domain`, `tenant_settings`)
- [ ] Metadata field captures context-specific details as JSON (optional per event)
- [ ] Logging is synchronous (write completes before service method returns)

**Actor Tracking:**

- [ ] All events track the `actor_user_id` (who performed the action)
- [ ] System-initiated actions (background jobs, automated processes) use a predefined UUID constant (e.g., `SYSTEM_ACTOR_ID`)
- [ ] System actor UUID is defined in code, not a real user row

**Implementation Pattern:**

- [ ] Logging helper/utility that service functions call after successful writes
- [ ] All existing service layer write operations are instrumented
- [ ] Culture: "If there is a write, there is a log" - bulk writes produce multiple log entries

**Retention:**

- [ ] Logs retained indefinitely
- [ ] Logs reference user UUIDs - anonymization happens on user record, not logs

**Out of Scope:**

- UI to browse/search logs
- API endpoints to query logs
- User-facing activity history display
- Read operation logging

**Effort:** M
**Value:** High (Audit/Compliance Foundation)

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

**Effort:** L (4-6 hours)
**Value:** High (Security)

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

