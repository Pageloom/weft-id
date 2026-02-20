# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 0 | - |
| Low | 1 | E2E test gap (attribute mapping) |

**Last compliance scan:** 2026-02-16 (ARCH-001, LOG-003 resolved)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## E2E: Custom Attribute Mapping in SAML Assertions Not Tested

**Found in:** SAML IdP assertion building (`app/services/service_providers/sso.py`, `app/utils/saml_assertion.py`)
**Severity:** Low
**Description:** SPs can be configured with custom attribute mappings (custom URIs for standard attributes). No E2E test verifies that configured attribute mappings actually appear in the SAML assertion consumed by the SP. Unit tests cover the mapping logic but not the full sign/deliver/parse round-trip.
**Evidence:** `tests/e2e/` has no test that configures custom attribute URIs and then verifies them in the SSO response at the SP side.
**Impact:** A regression in attribute mapping could cause SPs that depend on custom attribute URIs to fail user provisioning.
**Suggested fix:** Add E2E test: configure custom attribute mapping on SP, perform SSO, verify the SP receives the mapped attributes correctly.
