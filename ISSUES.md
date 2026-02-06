# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | Refactoring |
| Medium | 1 | Test Code |
| Low | 0 | - |

**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-06 (verification scan, 2 critical service files found)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last test code audit:** 2026-02-06 (magic indices in assertions fixed)

---

## [REFACTOR] Critical File Size: services/users.py and services/groups.py

**Found in:** `app/services/users.py` (1334 lines), `app/services/groups.py` (1295 lines)
**Impact:** High
**Category:** File Structure / Claude Traversability

**Description:**
Two service files exceed the critical threshold of 1000 lines:

| File | Lines | Functions | Responsibilities |
|------|-------|-----------|------------------|
| `app/services/users.py` | 1334 | ~40 | User CRUD, state management, email handling, password management, role changes |
| `app/services/groups.py` | 1295 | ~35 | Group CRUD, membership, DAG relationships, lineage, sync operations |

**Why It Matters:**
- Files >1000 lines don't fit well in Claude's context window
- Multiple responsibilities make it hard to locate specific logic
- Higher risk of merge conflicts when multiple features touch same file

**Suggested Refactoring:**
Follow the `app/services/saml/` pattern (split into sub-packages):

For `users.py`:
- `users/crud.py` - create, read, update, delete operations
- `users/state.py` - activation, inactivation, reactivation
- `users/emails.py` - email verification, primary email changes
- `users/passwords.py` - password set, reset, change

For `groups.py`:
- `groups/crud.py` - create, read, update, delete
- `groups/membership.py` - add/remove members
- `groups/hierarchy.py` - DAG relationships, lineage management
- `groups/sync.py` - IdP sync operations

**Files Affected:** 2 service files, plus corresponding test files

---

## [TEST] Parametrization Opportunities

**Found in:** Multiple test files
**Impact:** Medium
**Category:** Test Code / Duplication

**Description:**
Several test groups have highly similar structure that could be consolidated using `pytest.mark.parametrize`:

1. `test_routers_saml_domain_binding.py:38-147` - 6 tests (bind/unbind × success/not_found/error)
2. `test_email_backends.py:6-208` - 6 tests (SMTP/Resend/SendGrid × success/failure)
3. `test_routers_integrations.py:289-351` - 3 validation error tests
4. `test_utils_saml.py:305-340` - 3 metadata fetch error tests

**Why It Matters:**
- Reduces test duplication by 50-70%
- Makes test patterns clearer
- Easier to add new cases

**Suggested Refactoring:**
Apply parametrization incrementally, starting with `test_routers_saml_domain_binding.py` as it has the clearest pattern.

**Files Affected:** 4 test files
