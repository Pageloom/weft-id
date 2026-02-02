# SAML Testing Reference

This document covers SAML-specific testing considerations for the `/test` agent.

## Coverage Threshold

**80%+ coverage for all SAML modules is acceptable.** Do not flag SAML coverage gaps below this threshold as issues.

The SAML modules (`app/services/saml/`, `database/saml.py`, `routers/saml/`) have intentional gaps that require true E2E tests to cover.

## Why SAML is Different

SAML authentication requires cryptographic signature validation. The `python3-saml` library validates:
- XML signatures using the IdP's certificate
- Timing constraints (NotOnOrAfter)
- Audience restrictions
- Proper SAML bindings (POST/Redirect)

You cannot mock these at the HTTP level because the library performs real cryptographic validation. Mocking the entire library defeats the purpose of testing the actual SAML flow.

## What's Covered (Sufficient)

- SP certificate management (create, get, rotate)
- IdP CRUD operations (create, list, update, delete, enable/disable)
- Admin UI endpoints (list, new, edit pages)
- Authorization checks (super_admin required)
- Test mode with mocked SAML responses
- Domain binding operations
- Metadata URL parsing

## What Requires E2E Tests

These cannot be unit/integration tested effectively:

1. **Real SAML ACS flow** (`routers/saml/authentication.py`) - Error handling in the Assertion Consumer Service requires real signed SAML assertions from an IdP

2. **IdP-initiated Single Logout** (`services/saml/logout.py`) - Requires a signed LogoutRequest from the IdP

3. **Real metadata refresh** (`services/saml/metadata.py`) - The full update path after fetching from a real metadata URL

4. **SAML debug cleanup** (`database/saml.py`) - Background job that cleans entries older than 24 hours

5. **Database failure branches** - Defensive code for impossible conditions

## E2E Test Setup

The project includes SimpleSAMLphp in docker-compose for manual testing. Automated E2E tests would need:

1. SimpleSAMLphp configured with matching certificates
2. Playwright to navigate the IdP login page
3. Handle the POST back to ACS
4. Verify session creation

This is complex and fragile. Accept the coverage gap or invest in a proper E2E test suite with the SimpleSAMLphp simulator.
