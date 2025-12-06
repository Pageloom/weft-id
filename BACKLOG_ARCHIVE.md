# Product Backlog Archive

This document contains completed backlog items for historical reference.

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
