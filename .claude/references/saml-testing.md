# SAML Testing Reference

This document covers SAML-specific testing considerations for the `/test` agent.

## Coverage Threshold

**90%+ coverage for SAML router modules** is achievable through unit tests with service mocks. The router layer (tab routes, ACS error handlers, login initiation) does not contain cryptographic logic. It delegates to the service layer, so all error branches are testable by mocking service calls.

**Service-layer SAML modules** (`app/services/saml/`) may have lower coverage where the code integrates with `python3-saml` for real signature validation. These paths genuinely need E2E tests.

## What's Fully Unit-Testable (Router Layer)

SAML admin tab routes and ACS router error handlers are unit-testable with service mocks. The SAML cryptography lives in the service layer, not the routers.

- IdP CRUD operations (create, list, update, delete, enable/disable)
- Admin tab routes (details, certificates, attributes, metadata, danger)
- Tab access control checks (`has_page_access` returns False)
- ACS error handlers (ValidationError, NotFoundError, ServiceError branches)
- ACS success paths (session regeneration, MFA redirect, login completion)
- Login initiation and error handling
- Metadata endpoints (per-IdP SP metadata, public trust page)
- Trust establishment routes (URL, XML, manual)
- Certificate rotation
- SP certificate management (create, get, rotate)
- Test mode with mocked SAML responses
- Domain binding operations

## What Requires E2E Tests

Only the service-layer crypto functions truly need E2E coverage:

1. **SAML signature validation** (`services/saml/`) - The `python3-saml` library validates XML signatures, timing, audience restrictions. Cannot be mocked meaningfully.

2. **IdP-initiated Single Logout** (`services/saml/logout.py`) - Full round-trip validation (signed requests from a real IdP) requires E2E.

3. **Real metadata refresh** (`services/saml/metadata.py`) - The full update path after fetching from a real metadata URL.

4. **SAML debug cleanup** (`database/saml.py`) - Background job that cleans entries older than 24 hours.

5. **Database failure branches** - Defensive code for impossible conditions.

## E2E Test Suite

Automated E2E tests live in `tests/e2e/` using Playwright. Run with `./test-e2e`.

The test bed (`app/dev/sso_testbed.py`) provisions two cross-tenant setups:
- **IdP tenant** (`e2e-idp`) with a super admin user
- **SP tenant** (`e2e-sp`) with admin, member, and pre-existing users

Tests cover:
- SP-initiated SSO with JIT provisioning
- IdP-initiated SSO via "My Apps" dashboard
- Pre-existing user matching (no duplicate JIT creation)
- Admin XML metadata import (both IdP and SP sides)
- Basic multi-step email+password login flow
- Single Logout (SLO) flows (`tests/e2e/test_slo_flows.py`)

For manual testing, SAMLtest.id and sptest.iamshowcase.com remain available options.

## SAML IdP / Service Provider Testing

Weft ID also acts as a SAML Identity Provider, issuing assertions to registered Service Providers.

### What's Covered (Automated Tests)

- SP registration (manual entry, XML import, URL import)
- SP CRUD operations (create, list, get, update, delete)
- Per-SP signing certificate lifecycle (create, rotate, grace period)
- SSO response building and assertion signing
- Consent flow routing
- IdP metadata generation (generic and per-SP)
- Authorization checks (super_admin required for admin, admin+ for SSO)

### What Requires E2E Tests

1. **Full SSO round-trip** - SP sends AuthnRequest, user authenticates, consents, SP receives signed assertion
2. **Real SAML assertion validation** - An actual SP validating the signature, audience, timing
3. **Metadata import from live URL** - Fetching and parsing metadata from a running SP

### Key Test Files

| File | Coverage |
|------|----------|
| `tests/routers/test_saml_idp.py` | Admin UI for SP management |
| `tests/routers/test_saml_idp_sso.py` | SSO flow, consent, assertion delivery |
| `tests/routers/test_saml_idp_slo.py` | SLO flow, logout routing |
| `tests/routers/test_saml_idp_attributes.py` | SAML attribute mapping |
| `tests/services/test_service_providers.py` | SP service CRUD and certificate management |
| `tests/services/test_service_providers_sso.py` | SSO assertion building and signing |
| `tests/services/test_service_providers_slo.py` | SLO service logic |
| `tests/services/test_service_providers_nameid.py` | NameID format handling |
| `tests/api/test_service_providers.py` | API endpoints for SP management |
| `tests/utils/test_saml_idp.py` | IdP utility functions, XML parsing edge cases |

### Manual SP Testing

To manually test the SP setup flow:

1. Start Docker services (`make up`), log in as `super_admin`
2. Navigate to `/admin/settings/service-providers`, click "Add Service Provider"
3. Enter a test SP (Name: "Test App", Entity ID: `https://testapp.local/saml/metadata`, ACS URL: `https://testapp.local/saml/acs`)
4. Verify the SP appears in the list and its detail page shows IdP metadata URL
5. Visit `/saml/idp/metadata` (generic) and `/saml/idp/metadata/{sp_id}` (per-SP) to confirm valid XML
6. For full SSO testing, options include:
   - **SAMLtest.id** (free online service, can act as SP)
   - **sptest.iamshowcase.com** (free online test SP)
   - **Another Weft ID tenant** (Tenant B as SP consuming Tenant A as IdP, requires separate subdomains and manual certificate exchange)
7. Check event logs for `service_provider_created`, `sp_signing_certificate_created`, and (after SSO) `sso_assertion_issued`
