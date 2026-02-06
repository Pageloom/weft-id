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

## [TEST] Nested Patch Pyramids: Remaining Files (6 files, 45 or fewer each)

**Found in:** Multiple test files
**Impact:** Low-Medium
**Category:** Test Code / Maintainability

**Description:**
The following files have 20-45 instances each of nested `with patch()`:
- `tests/test_api_users.py` (45)
- `tests/test_routers_admin.py` (42)
- `tests/test_services_users.py` (42)
- `tests/test_utils_email.py` (31)
- `tests/test_api_groups.py` (22)
- `tests/test_email_backends.py` (20)

**Suggested Refactoring:**
Convert to flat `mocker.patch()` calls after completing higher-priority files.

**Files Affected:** 6 files listed above

---

## [TEST] Missing Test Docstrings: test_services_saml.py

**Found in:** `tests/test_services_saml.py`
**Impact:** Medium
**Category:** Test Code / Documentation

**Description:**
73 tests in this file lack docstrings explaining what they test and why.

**Evidence (examples):**
- Line 197: `test_create_identity_provider_duplicate_entity_id`
- Line 455: `test_get_idp_for_saml_login_disabled_forbidden`
- Line 569: `test_build_authn_request_disabled_idp_forbidden`
- Line 625: `test_authenticate_via_saml_user_inactivated`

**Why It Matters:**
- SAML is complex; tests need context to understand intent
- Without docstrings, test names must be self-documenting (and often aren't)
- Makes test failures harder to diagnose
- New developers struggle to understand test coverage

**Suggested Refactoring:**
Add docstrings explaining:
1. What scenario the test covers
2. What the expected behavior is
3. Why this test matters (if not obvious)

```python
# Before:
def test_authenticate_via_saml_user_inactivated():
    # ... test code

# After:
def test_authenticate_via_saml_user_inactivated():
    """SAML login should fail gracefully for inactivated users.

    When a user successfully authenticates via IdP but their WeftId account
    is inactivated, the ACS should redirect to the reactivation flow rather
    than creating a session.
    """
    # ... test code
```

**Files Affected:** `tests/test_services_saml.py` (73 tests need docstrings)

---

## [TEST] Underutilized Pytest Parametrization

**Found in:** Multiple test files
**Impact:** Medium
**Category:** Test Code / Duplication

**Description:**
Only `test_templates_dark_mode.py` effectively uses `@pytest.mark.parametrize`. Many test files have repeated test structures that could be consolidated.

**Evidence - Candidates for parametrization:**
1. **Role-based access tests**: Multiple tests checking same endpoint with different roles
2. **Status code tests**: Tests that only differ in expected status codes
3. **Validation tests**: Tests checking the same validation with different invalid inputs
4. **CRUD operation tests**: Tests following create/read/update/delete patterns

**Why It Matters:**
- Reduces test code volume significantly
- Makes test coverage intent clearer
- Easier to add new test cases
- Reduces maintenance burden

**Suggested Refactoring:**
```python
# Before (3 separate tests):
def test_endpoint_as_admin():
    # setup admin...
    assert response.status_code == 200

def test_endpoint_as_member():
    # setup member...
    assert response.status_code == 403

def test_endpoint_as_unauthenticated():
    # no auth...
    assert response.status_code == 401

# After (1 parametrized test):
@pytest.mark.parametrize("user_role,expected_status", [
    ("admin", 200),
    ("member", 403),
    (None, 401),
])
def test_endpoint_access_control(user_role, expected_status, get_user_by_role):
    user = get_user_by_role(user_role)
    # ... single test implementation
    assert response.status_code == expected_status
```

**Files to Evaluate:**
- `test_routers_users.py` (role-based access patterns)
- `test_routers_admin.py` (role-based access patterns)
- `test_api_users.py` (CRUD patterns)
- `test_services_users.py` (validation patterns)

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

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 3 | 1 test patch pyramids (6 files), 1 test docstrings, 1 test parametrization |
| Low | 2 | 1 architecture consistency, 1 test magic indices |

**Last dependency audit:** 2026-02-02 (ecdsa CVE fix available via sendgrid 6.12.5)
**Last refactor scan:** 2026-02-01 (full codebase deep scan)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last test code audit:** 2026-02-02 (found ~940 patch pyramids across 37 files)
