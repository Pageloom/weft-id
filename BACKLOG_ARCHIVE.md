# Product Backlog Archive

This document contains completed backlog items for historical reference.

---

## User Activity Tracking

**Status:** Complete

**User Story:**
As a platform operator
I want to track when users are actively using the system
So that I can understand usage patterns and identify inactive accounts without logging every single request

**Acceptance Criteria:**

**Sign-in Event Logging:**

- [x] Successful sign-ins logged to `event_logs` table (event_type: `user_signed_in`)
- [x] Sign-in defined as: user completing the authentication flow (not session refresh or token renewal)
- [x] Failed sign-in attempts are NOT logged (requires rate-limiting first - future scope)
- [x] Sign-in event also updates `last_activity_at` on the user record

**Last Activity Tracking:**

- [x] New `user_activity` table with `last_activity_at` timestamp (separate from users table)
- [x] Any service layer write operation updates `last_activity_at` (via `log_event`)
- [x] Any service layer read operation updates `last_activity_at` only if 3+ hours have passed (rolling window)
- [x] Activity check uses Memcached to avoid constant DB reads for the 3-hour check
- [x] Cache key pattern: `user_activity:{user_id}` with 3-hour TTL
- [x] If cache miss or expired, check DB and update if needed

**Implementation Pattern:**

- [x] Service layer tracking via `track_activity()` function
- [x] Write operations tracked automatically via `log_event()` integration
- [x] Read operations require explicit `track_activity()` calls
- [x] Synchronous updates (tiny latency, rare writes due to caching)
- [x] Memcached as new infrastructure dependency

**Technical Implementation:**

- Database migration: New `user_activity` table (FK to users, CASCADE delete)
- Memcached setup in Docker Compose
- Cache utility module (`app/utils/cache.py`)
- Activity tracking service (`app/services/activity.py`)
- Integration with event logging (`app/services/event_log.py`)
- Sign-in event logging in MFA verification flow

**Effort:** M
**Value:** High (Usage Analytics, Account Lifecycle Management)

---

## Service Layer Event Logging

**Status:** Complete

**User Story:**
As a platform operator
I want all write operations in the service layer to be logged to a database table
So that I have a complete audit trail for compliance, debugging, and future user-facing activity history

**Acceptance Criteria:**

**Core Logging:**

- [x] New `event_logs` table captures all service layer write operations
- [x] Each log entry includes: `tenant_id`, `actor_user_id`, `artifact_type`, `artifact_id`, `event_type`, `metadata` (JSON), `created_at`
- [x] Event types are descriptive strings (e.g., `user_created`, `email_updated`, `mfa_enabled`) - not DB-enforced enums
- [x] Artifact type identifies the entity (e.g., `user`, `privileged_domain`, `tenant_settings`)
- [x] Metadata field captures context-specific details as JSON (optional per event)
- [x] Logging is synchronous (write completes before service method returns)

**Actor Tracking:**

- [x] All events track the `actor_user_id` (who performed the action)
- [x] System-initiated actions (background jobs, automated processes) use a predefined UUID constant (e.g., `SYSTEM_ACTOR_ID`)
- [x] System actor UUID is defined in code, not a real user row

**Implementation Pattern:**

- [x] Logging helper/utility that service functions call after successful writes
- [x] All existing service layer write operations are instrumented
- [x] Culture: "If there is a write, there is a log" - bulk writes produce multiple log entries

**Retention:**

- [x] Logs retained indefinitely
- [x] Logs reference user UUIDs - anonymization happens on user record, not logs

**Out of Scope:**

- UI to browse/search logs
- API endpoints to query logs
- User-facing activity history display
- Read operation logging

**Effort:** M
**Value:** High (Audit/Compliance Foundation)

---

## User List Filtering & Sorting Enhancements

**Status:** Complete

**User Story:**
As an admin
I want to filter the user list by role and status, and sort by status
So that I can quickly find specific groups of users (e.g., all inactive admins)

**Acceptance Criteria:**

**Role Filtering:**

- [x] Add multi-select role filter with options: Member, Admin, Super Admin
- [x] Filter persists in URL query params (e.g., `?role=admin,super_admin`)
- [x] Role filter combines with existing text search
- [x] Clear filter option to reset role selection

**Status Filtering:**

- [x] Add multi-select status filter with options: Active, Inactivated, Anonymized
- [x] Filter persists in URL query params (e.g., `?status=active,inactivated`)
- [x] Status filter combines with existing text search and role filter
- [x] Clear filter option to reset status selection

**Status Sorting:**

- [x] Add "Status" to allowed sort fields in user list
- [x] Status sort order: Active → Inactivated → Anonymized (or reverse for desc)

**UI/UX:**

- [x] Filter controls displayed above user list table
- [x] Visual indication when filters are active
- [x] Filters and search work together (AND logic)
- [x] Pagination respects active filters
- [x] Total count updates to reflect filtered results

**API Layer:**

- [x] `list_users_raw` service function accepts optional `roles` and `statuses` filter params
- [x] `count_users` function updated to support role and status filters
- [x] Database queries efficiently filter by role and status

**Documentation (Critical):**

- [x] Document API query parameter semantics for combining search, filters, sorting, and pagination
- [x] Include examples: `?search=john&role=admin,member&status=active&sort=status&order=asc&page=2&size=25`
- [x] Document filter value formats (comma-separated for multi-select)
- [x] Document interaction between filters (AND logic) and pagination behavior
- [x] Add inline code comments explaining filter/sort query construction

**Testing (Comprehensive):**

- [x] Unit tests for service layer filter combinations (role only, status only, role+status)
- [x] Unit tests for filter + search combinations
- [x] Unit tests for filter + sort combinations (including status sorting)
- [x] Integration tests for pagination with active filters (correct counts, page boundaries)
- [x] Edge case tests: empty filters, invalid filter values, all filters active simultaneously
- [x] Test that URL query params round-trip correctly through the UI

**Effort:** S
**Value:** High

---

## API-First Architecture: RESTful API Layer with OpenAPI Specification

**Status:** Complete

**User Story:**
As a developer integrating with the identity platform
I want a comprehensive RESTful API with OAuth2 authentication and OpenAPI specification
So that I can build custom applications and integrations without relying on server-side rendered pages

**Acceptance Criteria:**

**API Coverage:**
- [x] All existing post-authentication functionality exposed via RESTful APIs
- [x] User management endpoints (CRUD operations)
- [x] User profile endpoints (view/edit profile)
- [x] Settings management endpoints (privileged domains, tenant settings)
- [x] Role and permission management endpoints
- [x] Email management endpoints (add, verify, remove, set-primary for user and admin)
- [x] MFA management endpoints (TOTP setup, email MFA, backup codes, admin reset)
- [x] Pre-authentication flows (login, registration) remain server-side rendered (excluded from API)
- [x] Email verification flows remain server-side rendered (excluded from API)

*Note: Future features (organizational structure, ad-hoc groups) will be API-first by default.*

**Authentication & Authorization:**
- [x] OAuth2 authentication for API access
- [x] Support for B2B client-credentials flow
- [x] API endpoints respect existing role-based permissions (Super Admin, Admin, User)
- [x] Token-based authentication for all API requests
- [x] Secure token storage and refresh mechanisms

**OpenAPI Specification:**
- [x] Auto-generated OpenAPI 3.x specification from FastAPI
- [x] Bare-bones spec (endpoint paths, methods, request/response schemas)
- [x] No detailed descriptions or examples required (minimal documentation)
- [x] Specification available at `/openapi.json` endpoint
- [x] Interactive API docs available at `/docs` (Swagger UI)
- [x] Specification covers all implemented API endpoints
- [x] Exclude HTML/server-rendered endpoints from OpenAPI spec (only include `/api/v1/*` routes)
- [x] Document security/authentication requirements per endpoint in OpenAPI spec

**API Testing Strategy:**
- [x] Tests cover: request/response schemas, HTTP status codes, authentication requirements
- [x] Tests verify role-based permission enforcement for each endpoint
- [x] Tests ensure tenant isolation for multi-tenant endpoints
- [x] Integration with existing pytest test suite

**Architecture:**
- [x] Existing server-side rendered pages remain untouched (no breaking changes)
- [x] New API routes organized under `/api/v1/` prefix
- [x] API responses return JSON with consistent error handling
- [x] Proper HTTP status codes for all responses
- [x] Tenant isolation maintained for all API endpoints (via `tenant_id`)

**Out of Scope:**
- SDK generation (can be done separately using OpenAPI spec)
- Rate limiting
- CORS configuration (handled at server/reverse proxy level)
- Migration of existing server-side pages to API-driven SPAs
- Detailed API documentation or examples
- GraphQL or other API paradigms
- Spec-driven testing (automated test generation, contract testing, schemathesis/dredd)
- CI/CD integration for spec-based tests

**Technical Implementation:**
- New router module: `app/routers/api/` directory structure
- API versioning: `/api/v1/` prefix for all endpoints
- OAuth2 implementation using FastAPI's security utilities
- Token management database tables (migrations required)
- Leverage existing `app/database/` modules for data access
- Update FastAPI app configuration for OpenAPI generation
- API-specific error handling and response formatting
- Spec-based testing framework setup in `tests/api/` directory
- Test configuration to load and parse OpenAPI spec
- Test fixtures for OAuth2 token generation and multi-role testing

**Dependencies:**
- FastAPI OAuth2 utilities (already available)
- Potential OAuth2 library (e.g., `authlib` or `python-jose`)
- Spec-based testing library (e.g., `schemathesis`, `dredd`, or custom pytest solution)

**Effort:** XL (3-4 weeks for complete coverage including testing)
**Value:** High (Foundation for Ecosystem Growth & Integrations)

**Notes:**
- This creates a parallel API layer alongside existing server-side pages
- Future epic can migrate pages to consume these APIs
- OpenAPI spec enables third-party SDK generation
- Spec-driven testing ensures API contract stability
- Maintains backward compatibility with current functionality
- **Detailed implementation plan:** See [docs/api-implementation-plan.md](docs/api-implementation-plan.md)

---

## User Inactivation & GDPR Anonymization

**Status:** Complete

**User Story:**
As a platform operator
I want to inactivate users (with optional GDPR anonymization)
So that I can disable access for departed users while maintaining audit trails, and comply with right-to-be-forgotten requests

**Acceptance Criteria:**

**User Inactivation:**

- [x] Add `is_inactivated` boolean column to users table (default: false)
- [x] Inactivated users cannot sign in (blocked at authentication layer)
- [x] Inactivated users retain all their data (email, name, etc.)
- [x] Admins can reactivate inactivated users
- [x] Inactivated users still appear in logs and user lists (marked as inactivated)

**GDPR Anonymization:**

- [x] Add `is_anonymized` boolean column to users table (default: false)
- [x] Anonymization = inactivation + PII scrubbed
- [x] Anonymized users have email, name, and other PII removed/replaced
- [x] Anonymized users cannot be reactivated (irreversible)
- [x] UUID is preserved - logs continue to reference the anonymized user record
- [x] Anonymized user record displays as "[Anonymized User]" or similar in UI contexts

**Admin Controls:**

- [x] Admin UI to inactivate/reactivate users
- [x] Admin UI to anonymize users (with confirmation - irreversible)
- [x] Clear visual distinction between inactivated vs anonymized users

**Audit Trail Integrity:**

- [x] Event logs retain user UUID references regardless of inactivation/anonymization
- [x] Looking up an anonymized user by UUID returns the anonymized record (not null)

**Out of Scope:**

- Self-service GDPR deletion requests
- Automated anonymization workflows
- Bulk inactivation/anonymization

**Effort:** M
**Value:** High (Compliance/GDPR Foundation)

---

## On-Prem Email Reliability & MFA Bypass

**Status:** Complete

**User Story:**
As an on-prem operator
I want flexible email delivery options and an optional MFA bypass mode
So that I can deploy in restrictive network environments where SMTP ports are blocked, and simplify local development/testing

**Context:**
On-prem and some cloud environments block outbound SMTP ports (25, 465, 587). This makes email-based features (OTP codes, invitations, notifications) non-functional. HTTP-based email APIs (Resend, SendGrid) work over port 443 and bypass these restrictions.

**Acceptance Criteria:**

**MFA Bypass Mode:**

- [x] New `BYPASS_OTP` environment variable (default: false)
- [x] When `BYPASS_OTP=true`, any valid 6-digit code (000000-999999) passes MFA verification
- [x] Bypass applies to all MFA methods: email OTP and TOTP
- [x] Backup codes are NOT bypassed (they remain functional for account recovery)
- [x] Clear warning logged at startup when bypass mode is enabled
- [x] Documentation warns this is for dev/on-prem only, never production

**Pluggable Email Backends:**

- [x] Abstract email backend interface supporting multiple providers
- [x] `EMAIL_BACKEND` environment variable to select provider: `smtp`, `resend`, `sendgrid`
- [x] SMTP backend (existing implementation, refactored)
- [x] Resend backend (HTTPS API via `resend` Python package)
- [x] SendGrid backend (HTTPS API via `sendgrid` Python package)
- [x] Backend-specific configuration: `RESEND_API_KEY`, `SENDGRID_API_KEY`
- [x] Graceful error handling with logging for all backends
- [x] All existing email functions work unchanged (interface preserved)

**Configuration Updates:**

- [x] Update `.env.dev.example` with new variables (documented, commented)
- [x] Update `.env.onprem.example` with recommended on-prem settings
- [x] Update `app/settings.py` to load new environment variables

**Out of Scope:**

- AWS SES backend (can be added later)
- Console/log backend for debugging
- Webhook-based email delivery
- Password-based authentication alternative

**Effort:** M
**Value:** High (Unblocks On-Prem Deployment)

---

## Service Layer Architecture

**Status:** Complete

**User Story:**
As a developer working on Loom
I want a service layer that sits between routes and the database layer
So that I can develop API-first and then compose server-rendered pages using the same models and operations without
duplication or HTTP overhead

**Architecture:**

```
[HTML Routes] → [Service Layer] → [Database Layer]
[API Routes]  → [Service Layer] → [Database Layer]
```

**Acceptance Criteria:**

**Service Layer Design:**

- [x] New `app/services/` directory with domain-organized modules
- [x] Service functions return Pydantic models (the API schemas from `app/schemas/`)
- [x] Service layer handles **authorization** (can this user do this action?)
- [x] Service layer handles business logic (validation, side effects like emails)
- [x] Service layer is HTTP-agnostic (no knowledge of requests/responses)
- [x] Routes handle **authentication** only (who is this user?) and inject requesting_user

**Exception Handling:**

- [x] Custom exception hierarchy in `app/services/exceptions.py`
- [x] Exceptions are HTTP-agnostic but translatable (include error code, message, optional details)
- [x] API routes translate service exceptions to HTTPException
- [x] HTML routes translate service exceptions appropriately (flash messages, error pages)

**API Routes Refactored:**

- [x] API routes become thin wrappers around service calls
- [x] API routes handle: HTTP parsing, authentication deps, response formatting
- [x] All business logic moved out of API routes into service layer

**HTML Routes Refactored:**

- [x] HTML routes call service layer (same as API)
- [x] HTML routes receive typed Pydantic models
- [x] No direct database layer calls from HTML routes

**Service Modules Created:**

- [x] `services/settings.py` - Tenant settings, privileged domains
- [x] `services/users.py` - User CRUD, profile management
- [x] `services/emails.py` - Email management (add, verify, remove, set-primary)
- [x] `services/mfa.py` - MFA setup, verification, backup codes
- [x] `services/oauth2.py` - OAuth2 clients, authorization codes, tokens

**Authorization Model:**

- **Authentication** (route layer): FastAPI dependencies identify the caller
- **Authorization** (service layer): Service checks role, ownership, tenant isolation

**Effort:** XL
**Value:** High (Enables true API-first development, eliminates duplication, improves maintainability)

---

## Admin Event Log Viewer & Export

**Status:** Complete

**User Story:**
As an admin or super admin
I want to view all system events in a paginated list and export them
So that I can audit activity, investigate issues, and maintain compliance records

**Acceptance Criteria:**

**Event Log Viewer:**

- [x] New page accessible to Admins and Super Admins only
- [x] Paginated list of events (newest first)
- [x] Columns displayed: timestamp, actor (user name), event type, artifact type, artifact ID
- [x] Clicking an event row opens a detail view showing full metadata JSON
- [x] No filtering for MVP (future enhancement)

**Export Functionality:**

- [x] "Export All Events" button triggers a background job
- [x] Export includes all events as a zipped JSON file
- [x] Email sent to initiating user when export is ready
- [x] Download available via a dedicated exports page
- [x] Exports auto-deleted after 24 hours (both DB record and file)
- [x] Worker container runs cleanup check once per hour to delete expired exports
- [x] Storage: DigitalOcean Spaces if configured, local filesystem fallback

**Background Job Infrastructure:**

- [x] New `bg_tasks` table (no RLS - system table for cross-tenant polling)
- [x] Schema: `id`, `tenant_id`, `job_type`, `payload` (JSON), `status`, `created_by`, `created_at`, `started_at`, `completed_at`, `error`
- [x] Separate worker container (same image, different entrypoint)
- [x] Worker polls every 10 seconds for pending jobs
- [x] Job handler registry: jobs only execute if a handler is registered for that `job_type`
- [x] Worker sets `SET LOCAL app.tenant_id` before executing job handlers (RLS respected in handlers)

**Dependencies:**

- Service Layer Event Logging (must exist first)

**Effort:** L
**Value:** High (Audit/Compliance)

---

## Background Jobs UI Refinement & Navigation Restructuring

**Status:** Complete

**User Story:**
As a user of the platform
I want to view and manage all my background jobs in one place
So that I can track progress, access outputs, download results, and clean up completed tasks

**Acceptance Criteria:**

**Navigation Changes:**

- [x] Merge "Settings" and "Administration" tabs into a single "Admin" menu with subsections
- [x] Move "Exports" page from admin area to User menu
- [x] Rename "Exports" to "Background Jobs"

**Background Jobs Page:**

- [x] Display job list with columns: Checkbox, Job Type, Status, Output, Download
- [x] Checkbox appears only for completed (success/failed) jobs
- [x] Status column shows: Requested / Ongoing / Completed / Failed (includes timestamp info)
- [x] Output column shows link to view output if available, otherwise "N/A"
- [x] Download column shows link to download file if available and < 24 hours old, otherwise "N/A"
- [x] Downloads older than 24 hours show "File expired" (no file existence check)
- [x] Multi-select deletion via checkboxes (only for completed jobs)
- [x] "Delete Selected" button removes checked job records
- [x] Page polls every 10 seconds while any job is in Requested/Ongoing state
- [x] Polling stops when all visible jobs are completed/failed
- [x] No email notifications sent on job completion

**Output Display:**

- [x] Clicking output link navigates to dedicated page showing raw text output
- [x] Output page shows job metadata (type, status, timestamps) above output content

**Database Changes:**

- [x] Output stored in `result` JSONB column (as `result.output`) - more flexible than separate TEXT column
- [x] Job records are NOT auto-deleted (persist indefinitely until user deletes)
- [x] Download files are cleaned up after 24 hours (existing behavior)

**Authorization:**

- [x] Users can only see and delete their own background jobs
- [x] Admins see only their own jobs (no tenant-wide job visibility)

**Technical Implementation:**

- Database migration: `00013_bg_tasks.sql` and `00014_export_files.sql`
- Service layer: `app/services/bg_tasks.py` with `list_user_jobs()`, `get_job_detail()`, `delete_jobs()`
- Router: `app/routers/account.py` with background jobs routes
- Templates: `account_background_jobs.html` and `account_job_output.html`
- Schemas: `app/schemas/bg_tasks.py` with `JobListItem`, `JobDetail`, `JobListResponse`
- Page registration: `app/pages.py` with `/account/background-jobs` hierarchy
- Auto-polling: JavaScript in template polls every 10s when `has_active_jobs` is true

**Effort:** M
**Value:** Medium (UX improvement, infrastructure foundation)

---

## Enhanced Event Log Audit Trail & Human-Readable Display

**Status:** Complete

**User Story:**
As a platform operator
I want event logs to capture comprehensive request metadata and display human-readable information
So that I can conduct thorough security investigations and understand who did what, from where, and on which accounts

**Acceptance Criteria:**

**Request Metadata Capture:**

- [x] Event logs capture IP address (remote_address) from request
- [x] Event logs capture full user agent string
- [x] Event logs parse device information from user agent (using user-agents library)
- [x] Event logs capture session ID hash (SHA-256 one-way hash for security)
- [x] IP extraction logic: X-Forwarded-For → X-Real-IP → request.client.host → null
- [x] Request metadata fields always present in metadata (even if null)
- [x] Background jobs and system events have null request metadata (no HTTP context)

**Metadata Storage & Deduplication:**

- [x] New `event_log_metadata` table with metadata_hash as primary key
- [x] Metadata hash computed via MD5 of deterministic JSON serialization
- [x] INSERT...ON CONFLICT DO NOTHING for efficient deduplication
- [x] event_logs references metadata via metadata_hash foreign key
- [x] Metadata combines 4 required request fields + optional custom event data
- [x] Hash computed on entire metadata object (request + custom fields)
- [x] Same request context reuses single metadata record
- [x] Different custom data creates different metadata records
- [x] Migration backfills existing events with system metadata (all nulls)

**Human-Readable Display:**

- [x] Event list shows artifact name when artifact_type='user'
- [x] Artifact name formatted as "First Last" from joined users table
- [x] Event detail shows actor as clickable link to user settings page
- [x] Event detail shows target user section for user artifacts (name, email, link)
- [x] Event detail displays request context section: IP, user agent, device, session hash
- [x] Event detail maintains full metadata display (request fields + custom data)

**Service & Database Layer:**

- [x] RequestingUser TypedDict includes optional request_metadata field
- [x] dependencies.py extracts request metadata using new utility module
- [x] Web routes pass Request object, API routes pass None for request_metadata
- [x] log_event() accepts request_metadata parameter
- [x] log_event() merges request_metadata + custom metadata into combined dict
- [x] log_event() computes hash on combined metadata
- [x] create_event() performs metadata deduplication and foreign key storage
- [x] list_events() and get_event_by_id() LEFT JOIN metadata and user tables
- [x] EventLogItem schema includes extracted convenience fields for templates
- [x] All ~20 service layer log_event() calls updated to pass request_metadata

**Technical Implementation:**

- Database migration: `00015_event_log_metadata.sql`
- New utility module: `app/utils/request_metadata.py`
- Updated: `app/services/types.py`, `app/dependencies.py`
- Updated: All routers (admin, users, account, settings, API v1)
- Updated: `app/services/event_log.py`, `app/database/event_log.py`
- Updated: `app/schemas/event_log.py`
- Updated: All services with log_event() calls (users, emails, settings, oauth2, bg_tasks)
- Updated: `app/templates/admin_events.html`, `app/templates/admin_event_detail.html`
- Added dependency: `user-agents = "^2.2.0"`

**Dependencies:**

- Service Layer Event Logging (required)
- User Activity Tracking (for last_activity_at in future)

**Effort:** L
**Value:** High (Security, Compliance, Audit Trail)

---

## User Activity Display & Automatic Inactivation System

**Status:** Complete

**User Story:**
As a platform operator
I want to see user activity status and automatically inactivate dormant users
So that I can maintain security hygiene and ensure only active users have access to the system

**Acceptance Criteria:**

**User List Enhancements:**

- [x] `last_activity_at` column added to user list API response
- [x] `last_activity_at` displayed in user list UI as absolute timestamp (localized to viewing user's timezone)
- [x] `last_activity_at` is sortable (ascending/descending) like existing columns
- [x] `last_login` removed from frontend user list view (retained in API for backwards compatibility)

**Tenant Inactivity Settings:**

- [x] New tenant setting: inactivity threshold with options: Indefinitely (disabled), 14 days, 30 days, 90 days
- [x] Setting added to existing `/settings/tenant-security` page
- [x] Default value: Indefinitely (no auto-inactivation)

**Automatic Inactivation:**

- [x] Daily cron job checks all active users against inactivity threshold
- [x] Comparison uses `last_activity_at`, falling back to `created_at` if null
- [x] Users exceeding threshold are set to inactive status
- [x] Upon inactivation: all OAuth tokens for that user are invalidated
- [x] Upon inactivation: all web sessions for that user are invalidated
- [x] Inactivation logged to event_logs (when event logging is available)

**Reactivation Request Flow:**

- [x] Inactivated users attempting to log in see a "Request Reactivation" option
- [x] User must complete email verification before request is submitted
- [x] New `reactivation_requests` table: user_id, requested_at, decided_by, decided_at
- [x] Upon request submission: email sent to all Admins and Super Admins in tenant
- [x] Email contains CTA linking to reactivation requests list
- [x] Reactivation requests list page (Admin/Super Admin only) shows pending requests
- [x] Admins can approve or deny each request individually
- [x] Approved: user status set to active, request removed from table, user can log in normally
- [x] Denied: request removed from table, user cannot request reactivation again via app
- [x] To track denial: add `reactivation_denied_at` timestamp column on users table
- [x] Users with `reactivation_denied_at` set cannot submit new requests (must contact org out-of-band)

**Max Session Length Change Behavior:**

- [x] When max session length setting is changed, all active sessions tenant-wide are invalidated immediately
- [x] Warning displayed before saving: "Changing this setting will immediately log out all users"
- [x] User must confirm before change takes effect

**Additional Work (Beyond Original Spec):**

- [x] Email notification to user when reactivation request is approved
- [x] Email notification to user when reactivation request is denied
- [x] Email notification to admins/super admins when a new reactivation request is submitted
- [x] Reactivation history page showing previously decided requests (approved/denied)
- [x] Full REST API for reactivation management (`/api/v1/reactivation-requests`)
  - GET list pending requests
  - GET `/history` list decided requests
  - POST `/{id}/approve` approve a request
  - POST `/{id}/deny` deny a request
- [x] Event log metadata includes user_id for all reactivation events (UUID only, no PII for GDPR compliance)
- [x] Request metadata (IP, user agent, device) captured for reactivation requests

**Dependencies:**

- User Activity Tracking (for `last_activity_at` column)
- Service Layer Event Logging (for audit trail)

**Effort:** XL
**Value:** High (Security, Compliance, Account Lifecycle)

---
