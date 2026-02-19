# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 3 | E2E test gaps (cert rotation, consent denial, access denial) |
| Low | 2 | E2E test gaps (switch account, attribute mapping) |

**Last compliance scan:** 2026-02-16 (ARCH-001, LOG-003 resolved)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## E2E: Per-SP Certificate Rotation Not Tested End-to-End

**Found in:** SAML IdP SSO flow with certificate rotation
**Severity:** Medium
**Description:** Per-SP signing certificates can be rotated with a grace period, but no E2E test verifies that SSO continues to work after rotation. Unit tests cover the rotation logic and dual-certificate metadata generation, but the full round-trip (rotate cert, SP fetches new metadata, SSO still works with new signature) is untested.
**Evidence:** `tests/e2e/` has no test referencing certificate rotation. `app/services/service_providers/signing_certs.py` and `app/jobs/rotate_certificates.py` have unit tests only.
**Impact:** A regression in certificate rotation could silently break SSO for SPs that refresh metadata after rotation.
**Suggested fix:** Add E2E test: perform SSO, rotate the per-SP signing cert, perform SSO again, verify it succeeds.

---

## E2E: Consent Denial and Error Response Not Tested

**Found in:** SAML IdP consent flow (`app/routers/saml_idp/sso.py`)
**Severity:** Medium
**Description:** The consent screen allows users to cancel SSO, which should return an error response to the SP. No E2E test covers this path. The cancel flow involves building a SAML error Response and redirecting back to the SP's ACS URL.
**Evidence:** `tests/e2e/test_sso_flows.py` only tests consent approval. No test clicks "Cancel" or verifies the SP receives an appropriate error.
**Impact:** If consent denial breaks, users would see an unhandled error instead of a graceful rejection at the SP.
**Suggested fix:** Add E2E test: initiate SSO, cancel at consent screen, verify SP receives an error response or appropriate redirect.

---

## E2E: Unauthorized User SP Access Denial Not Tested

**Found in:** SAML IdP group-based access control
**Severity:** Medium
**Description:** Group-based access gating is tested for the positive case (user in group can SSO), but no E2E test verifies that a user without SP access is denied. The consent flow should reject users who are not members of any group assigned to the SP.
**Evidence:** `tests/e2e/test_group_access.py` tests direct and inherited access. No test covers an authenticated user who lacks SP access.
**Impact:** A regression in access checking could allow unauthorized users to SSO to restricted SPs.
**Suggested fix:** Add E2E test: authenticate a user who has no group assignment for the SP, attempt SSO, verify access is denied with appropriate message.

---

## E2E: Switch Account During SSO Not Tested

**Found in:** SAML IdP consent flow (`app/routers/saml_idp/sso.py`, switch-account endpoint)
**Severity:** Low
**Description:** The consent screen has a "switch account" flow that clears the auth session while preserving the pending SSO context, then re-authenticates as a different user. This involves delicate session management across multiple redirects that cannot be meaningfully unit tested.
**Evidence:** `POST /saml/idp/consent/switch-account` endpoint exists but no E2E test exercises it.
**Impact:** If switch-account breaks, users signed into the wrong account would have no way to change without abandoning the SSO flow entirely.
**Suggested fix:** Add E2E test: initiate SSO as user A, click switch account at consent, authenticate as user B, verify SSO completes as user B.

---

## E2E: Custom Attribute Mapping in SAML Assertions Not Tested

**Found in:** SAML IdP assertion building (`app/services/service_providers/sso.py`, `app/utils/saml_assertion.py`)
**Severity:** Low
**Description:** SPs can be configured with custom attribute mappings (custom URIs for standard attributes). No E2E test verifies that configured attribute mappings actually appear in the SAML assertion consumed by the SP. Unit tests cover the mapping logic but not the full sign/deliver/parse round-trip.
**Evidence:** `tests/e2e/` has no test that configures custom attribute URIs and then verifies them in the SSO response at the SP side.
**Impact:** A regression in attribute mapping could cause SPs that depend on custom attribute URIs to fail user provisioning.
**Suggested fix:** Add E2E test: configure custom attribute mapping on SP, perform SSO, verify the SP receives the mapped attributes correctly.
