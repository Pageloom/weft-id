# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## High Severity

(None)

---

## Medium Severity

### SSO-001: JIT-provisioned users not added to IdP base group when IdP lacks one

**Found:** 2026-02-12 (manual SSO testbed testing)
**Component:** `app/services/saml/provisioning.py`, `app/services/groups/idp.py`
**Category:** Data integrity

**Problem:** When a user authenticates via SAML SSO and gets JIT-provisioned, `ensure_user_in_base_group()` silently skips group assignment if no base group exists for the IdP. The base group is normally created by the service layer when an IdP is added through the admin UI (`create_idp_base_group()`), but any IdP created by direct database insertion (dev scripts, migrations, API edge cases) will lack this group.

**Impact:** JIT-provisioned users end up with no group memberships. Any access policies or group-based logic that depends on the IdP base group will not apply to these users.

**Root cause:** `ensure_user_in_base_group()` in `app/services/groups/idp.py` returns silently when `get_idp_base_group_id()` returns None (lines ~400-407). There is no fallback to create the base group on demand.

**Suggested fix:** In `ensure_user_in_base_group()`, if the base group is not found, auto-create it by calling `create_idp_base_group()` before proceeding. This makes the function self-healing regardless of how the IdP record was created. The SSO testbed script (`app/dev/sso_testbed.py`) should also be updated to create the base group explicitly.

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 1 | Data integrity (SSO-001) |
| Low | 0 | - |

**Last compliance scan:** 2026-02-12 (automated + manual five-principle review)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-07 (full codebase standard scan, no critical files remain)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-06 (users.py and groups.py split into packages)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---
