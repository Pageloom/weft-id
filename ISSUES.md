# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## [REFACTOR] Long Functions in User Management

**Found in:** `app/services/users.py`, `app/services/saml/auth.py`, `app/services/groups.py`
**Impact:** Medium

**Description:**
Several functions exceed 100 lines:
- `update_user()` in users.py (~130 lines)
- `process_saml_response()` in saml/auth.py (~130 lines)
- `sync_user_idp_groups()` in groups.py (~121 lines)

**Suggested Refactoring:**
Extract sub-operations into focused helper functions.

---

## [REFACTOR] File Structure: Large Router Files

**Found in:** `app/routers/`, `app/routers/api/v1/`
**Impact:** High (Claude Traversability)
**Category:** File Structure

**Description:**
Four router modules exceed 500 lines:
- ~~`app/routers/saml.py` (1241 lines)~~ ✅ Refactored (2026-02-02)
- ~~`app/routers/auth.py` (987 lines)~~ ✅ Refactored (2026-02-06)
- `app/routers/users.py` (747 lines)
- `app/routers/api/v1/users.py` (1025 lines)

**Progress:**
- **saml.py**: Split into `app/routers/saml/` package with 9 focused modules:
  - `authentication.py` (core auth flow: metadata, login, ACS)
  - `logout.py` (SLO endpoints)
  - `selection.py` (IdP selection page)
  - `admin/providers.py` (IdP CRUD)
  - `admin/debug.py` (debugging and testing)
  - `admin/domains.py` (domain binding)
  - `_helpers.py` (shared utilities)
  - `__init__.py` files for backwards compatibility
- **auth.py**: Split into `app/routers/auth/` package with 6 focused modules:
  - `login.py` (login page, password login, email verification flow)
  - `logout.py` (logout with SAML SLO)
  - `onboarding.py` (email verification link, set-password)
  - `reactivation.py` (super admin self-reactivation, reactivation requests)
  - `dashboard.py` (dashboard endpoint)
  - `_helpers.py` (shared utilities: `_get_client_ip`, `_route_after_email_verification`)

**Why It Matters:**
Routers that are too large contain many unrelated endpoints in one file. When Claude needs to modify one endpoint, it must load many irrelevant endpoints.

**Remaining Refactoring:**
- `app/routers/users.py` → split by functionality
- `app/routers/api/v1/users.py` → `users/profile.py`, `users/emails.py`, `users/mfa.py`, `users/admin.py`

**Files Affected:** 2 remaining router modules plus any imports

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

## [TEST] Nested Patch Pyramids: test_routers_auth.py

**Found in:** `tests/test_routers_auth.py`
**Impact:** High
**Category:** Test Code / Maintainability

**Description:**
This file contains **104 instances** of nested `with patch()` context managers, typically 2-3 levels deep.

**Evidence (lines 23-26):**
```python
with patch("routers.auth.get_current_user") as mock_user:
    with patch("routers.auth.get_tenant_id_from_request") as mock_tenant:
        with patch("routers.auth.templates.TemplateResponse") as mock_template:
            mock_user.return_value = None
            # ... deeply nested test logic
```

**Why It Matters:**
- Same issues as test_routers_users.py
- Auth tests are critical path tests that need to be easy to read and modify
- 3-level nesting is common throughout the file

**Suggested Refactoring:**
Same pattern as test_routers_users.py. Convert to flat `mocker.patch()` calls.

**Files Affected:** `tests/test_routers_auth.py` (104 patch calls to convert)

---

## [TEST] Nested Patch Pyramids: test_utils_storage.py

**Found in:** `tests/test_utils_storage.py`
**Impact:** Medium
**Category:** Test Code / Maintainability

**Description:**
This file contains **67 instances** of nested `with patch()` context managers testing storage utilities.

**Why It Matters:**
- Storage tests mock multiple boto3/S3 interactions
- Nesting makes it hard to trace which mock affects which behavior

**Suggested Refactoring:**
Convert to flat `mocker.patch()` calls. Consider extracting common S3 mock setup to fixtures.

**Files Affected:** `tests/test_utils_storage.py` (67 patch calls to convert)

---

## [TEST] Nested Patch Pyramids: test_routers_account.py

**Found in:** `tests/test_routers_account.py`
**Impact:** Medium
**Category:** Test Code / Maintainability

**Description:**
This file contains **59 instances** of nested `with patch()` context managers, typically 2-3 levels deep.

**Suggested Refactoring:**
Convert to flat `mocker.patch()` calls.

**Files Affected:** `tests/test_routers_account.py` (59 patch calls to convert)

---

## [TEST] Nested Patch Pyramids: test_routers_integrations.py

**Found in:** `tests/test_routers_integrations.py`
**Impact:** Medium
**Category:** Test Code / Maintainability

**Description:**
This file contains **59 instances** of nested `with patch()` context managers.

**Suggested Refactoring:**
Convert to flat `mocker.patch()` calls.

**Files Affected:** `tests/test_routers_integrations.py` (59 patch calls to convert)

---

## [TEST] Nested Patch Pyramids: test_routers_settings.py

**Found in:** `tests/test_routers_settings.py`
**Impact:** Medium
**Category:** Test Code / Maintainability

**Description:**
This file contains **51 instances** of nested `with patch()` context managers, with some tests setting up 6+ mocks but only asserting 1-2 things.

**Evidence:**
- `test_privileged_domains_with_error_param` (line 72): 6 mocks, 1 assertion
- `test_tenant_security_page_no_settings` (line 368): 6 mocks, 1 assertion

**Why It Matters:**
- Excessive mocking may indicate tests are testing implementation rather than behavior
- Review mock usage as part of conversion

**Suggested Refactoring:**
Convert to flat `mocker.patch()` calls. During conversion, evaluate whether all mocks are necessary.

**Files Affected:** `tests/test_routers_settings.py` (51 patch calls to convert)

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

## [TEST] Duplicated Auth Override Pattern

**Found in:** All router test files
**Impact:** High
**Category:** Test Code / Duplication

**Description:**
The same 3-line auth dependency override pattern is repeated **200+ times** across test files:

```python
app.dependency_overrides[get_tenant_id_from_request] = lambda: test_user["tenant_id"]
app.dependency_overrides[get_current_user] = lambda: test_user
app.dependency_overrides[require_current_user] = lambda: test_user
```

**Evidence:**
- `test_routers_account.py`: 43 instances
- `test_routers_auth.py`: ~30 instances
- Pattern repeated in every router test file

**Why It Matters:**
- Violates DRY principle severely
- If auth dependency structure changes, 200+ places need updating
- Obscures actual test setup with boilerplate

**Suggested Refactoring:**
Extract to shared fixtures in `conftest.py`:

```python
# tests/conftest.py
@pytest.fixture
def override_auth(request):
    """Fixture that returns a function to set up auth overrides."""
    def _override(user):
        from dependencies import get_current_user, get_tenant_id_from_request, require_current_user
        app.dependency_overrides[get_tenant_id_from_request] = lambda: str(user["tenant_id"])
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[require_current_user] = lambda: user
    return _override

@pytest.fixture
def authenticated_client(test_user, override_auth):
    """Returns a TestClient with auth already configured."""
    override_auth(test_user)
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()
```

**Reference:** `test_routers_groups.py` already uses helper functions `_setup_admin_overrides()` and `_setup_member_overrides()`. This pattern should be promoted to shared fixtures.

**Files Affected:** All router test files (~15 files, 200+ instances total)

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
| High | 3 | 1 file structure (2/4 routers done), 1 test patch pyramid (high volume), 1 test auth duplication |
| Medium | 8 | 1 long functions, 5 test patch pyramids (medium volume), 1 test docstrings, 1 test parametrization |
| Low | 2 | 1 architecture consistency, 1 test magic indices |

## Test Code Refactoring Priority

Patch pyramid refactoring should proceed in this order:

| Priority | File | Patch Count | Notes |
|----------|------|-------------|-------|
| ~~1~~ | ~~`test_routers_users.py`~~ | ~~218~~ | ✅ Completed 2026-02-02 |
| 1 | `test_routers_auth.py` | 104 | Critical path tests |
| 2 | `test_utils_storage.py` | 67 | |
| 3 | `test_routers_account.py` | 59 | |
| 4 | `test_routers_integrations.py` | 59 | |
| 5 | `test_routers_settings.py` | 51 | Review mock necessity during conversion |
| 6 | Remaining 6 files | 20-45 each | Lower priority |

**Reference implementations:** `tests/test_routers_groups.py` (2026-02-02), `tests/test_routers_users.py` (2026-02-02)

**Last dependency audit:** 2026-02-02 (ecdsa CVE fix available via sendgrid 6.12.5)
**Last refactor scan:** 2026-02-01 (full codebase deep scan)
**Last router refactor:** 2026-02-06 (auth.py split into focused modules)
**Last test code audit:** 2026-02-02 (found ~940 patch pyramids across 37 files)
