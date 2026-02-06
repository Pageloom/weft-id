# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## [REFACTOR] Architecture: Event Logging in Routers

**Found in:** `app/routers/auth/login.py`, `app/routers/auth/logout.py`, `app/routers/auth/onboarding.py`, `app/routers/mfa.py`
**Impact:** Low
**Category:** Coupling / Consistency

**Description:**
5 direct `log_event()` calls exist in routers:
- `auth/login.py` - login_failed (invalid credentials)
- `auth/login.py` - login_failed (inactivated user)
- `auth/logout.py` - user_signed_out
- `auth/onboarding.py` - password_set
- `mfa.py:132` - user_signed_in

Per the architectural pattern ("all writes go through service layer"), event logging should occur in services, not routers.

**Context:**
These are authentication-related events that occur during login/logout flows. The auth module may be a special case since login is inherently router-level, but this creates inconsistency.

**Suggested Refactoring:**
Option 1: Accept as special case for auth flows (login/logout are fundamentally router operations)
Option 2: Create a thin auth service that handles session creation and logging

**Files Affected:** `app/routers/auth/login.py`, `app/routers/auth/logout.py`, `app/routers/auth/onboarding.py`, `app/routers/mfa.py`

---




## [TEST] Magic Indices in Assertions

**Found in:** Multiple test files
**Impact:** Low
**Category:** Test Code / Readability

**Description:**
Tests use positional indices to access mock call arguments without clarifying what each index represents:

```python
assert call_args[0][1] == "user-123"  # What is arg index 1?
assert call_args[0][2].first_name == "NewFirst"  # What is arg index 2?
assert mock_send.call_args[0][2] == "Test Organization"  # Unclear
```

**Why It Matters:**
- Requires reading the mocked function signature to understand assertions
- Brittle if function signatures change
- Test failures don't clearly indicate what went wrong

**Suggested Refactoring:**
Use keyword argument access or named constants:

```python
# Option 1: Access by keyword args
assert mock_send.call_args.kwargs["org_name"] == "Test Organization"

# Option 2: Named constants (if positional access needed)
SEND_EMAIL_ORG_NAME_ARG = 2
assert mock_send.call_args[0][SEND_EMAIL_ORG_NAME_ARG] == "Test Organization"

# Option 3: Destructuring for clarity
_, _, org_name = mock_send.call_args[0]
assert org_name == "Test Organization"
```

**Files Affected:** Multiple test files (audit during other refactoring)

---

## [DEPS] pip: CVE-2026-1703

**Package:** pip
**Installed Version:** 25.3
**Fixed Version:** 26.0
**Severity:** Unrated (path traversal)
**Advisory:** [NVD CVE-2026-1703](https://nvd.nist.gov/vuln/detail/CVE-2026-1703)

**Description:** Limited path traversal vulnerability when pip installs a maliciously crafted wheel archive. Files may be extracted outside the installation directory, though traversal is limited to prefixes of the installation directory.

**Exploitability in This Project:** Low
This vulnerability requires installing a maliciously crafted wheel. This project uses poetry lock files with pinned versions from PyPI. Risk would only arise if a compromised package was published to PyPI with the exact name and version specified in our dependencies.

**Remediation:**
- pip is a development tool, not a runtime dependency
- Update pip in your virtual environment: `pip install --upgrade pip`
- Consider updating when Python 3.x ships with pip 26.0+

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 0 | - |
| Low | 3 | 1 architecture consistency, 1 test magic indices, 1 dependency (pip) |

**Last dependency audit:** 2026-02-06 (ecdsa fixed via sendgrid 6.12.5; pip CVE-2026-1703 low priority)
**Last refactor scan:** 2026-02-01 (full codebase deep scan)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last test code audit:** 2026-02-02 (found ~940 patch pyramids across 37 files)
