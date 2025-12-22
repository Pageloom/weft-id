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
