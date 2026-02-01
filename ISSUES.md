# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Dependency Vulnerabilities

Dependency audit performed: 2026-01-31

**Status:** Two vulnerabilities found. One requires update, one is transitive with no fix available.

---

## [DEPS] python-multipart: CVE-2026-24486 - Path Traversal (Resolved)

**Package:** python-multipart
**Status:** Resolved (2026-02-01) - Updated to version 0.0.22

---

## [DEPS] ecdsa: CVE-2024-23342 - Minerva Timing Attack (Transitive)

**Package:** ecdsa
**Installed Version:** 0.19.1
**Fixed Version:** None (no planned fix)
**Severity:** High (CVSS: 7.4)
**Advisory:** https://github.com/advisories/GHSA-wj6h-64fc-37mp

**Description:**
The python-ecdsa library is vulnerable to the Minerva timing attack on P-256 curve operations. Using the sign_digest() API and timing signatures, an attacker can leak the internal nonce which may allow private key discovery after analyzing hundreds to thousands of signing operations.

**Why No Fix:**
The ecdsa maintainers consider side-channel attacks out of scope because implementing side-channel-free code in pure Python is impossible. The package is intended for non-security-critical uses.

**Exploitability in This Project:**
Low - This is a transitive dependency of sendgrid, which uses it for internal token signing. The attacker would need to:
1. Control timing measurements of sendgrid API calls
2. Gather hundreds of timing samples
3. Have a way to recover sendgrid's signing key (not user-facing)

**Remediation Options:**
1. Accept the risk (sendgrid's internal use is not directly exploitable)
2. Replace sendgrid with resend (this project already has resend as primary email backend)
3. Monitor for sendgrid updates that switch to pyca/cryptography

---

## [DEPS] python-multipart: CVE-2024-24762 - Content-Type Header ReDoS (Resolved)

**Package:** python-multipart
**Installed Version:** 0.0.18
**Vulnerable Versions:** < 0.0.7
**Fixed Version:** 0.0.7+
**Severity:** High (CVSS: 7.5)
**Advisory:** https://github.com/advisories/GHSA-2jv5-9r88-3w3p

**Description:**
When using form data, python-multipart uses a Regular Expression to parse the HTTP Content-Type header. An attacker could send a custom-made Content-Type option that causes the RegEx to consume CPU resources and stall indefinitely, blocking the main event loop and preventing all request handling.

**Exploitability in This Project:**
Not Affected - Version 0.0.18 is newer than the fixed version 0.0.7.

**Status:** Safe - current version includes the fix.

---

## [DEPS] jinja2: Recent Security Updates

**Package:** jinja2
**Installed Version:** 3.1.6
**Fixed Versions:** 3.1.3 (XSS), 3.1.5 (RCE), 3.1.6 (Sandbox)
**Severity:** Safe (Current)
**Advisory:** https://github.com/advisories/GHSA-cpwx-vrp4-4pq7

**Description:**
Jinja2 has had several security updates:
- CVE-2024-22195 (XSS, fixed 3.1.3)
- CVE-2024-56201 (Arbitrary code via filename, fixed 3.1.5)
- CVE-2025-27516 (Sandbox breakout via attr filter, fixed 3.1.6)

**Exploitability in This Project:**
Not Affected - Version 3.1.6 includes all security fixes.

**Status:** Safe - using latest patched version.

---

## [DEPS] pydantic: CVE-2024-3772 - Email Validation ReDoS (Not Affected)

**Package:** pydantic
**Installed Version:** 2.12.0
**Vulnerable Versions:** 2.0.0 - 2.3.x, < 1.10.13
**Fixed Version:** 2.4.0+
**Severity:** Medium (CVSS: 5.8)
**Advisory:** https://github.com/advisories/GHSA-mr82-8j83-vxmv

**Description:**
Regular expression denial of service (ReDoS) vulnerability in Pydantic's email validation. Malicious email strings can trigger catastrophic backtracking in the regex engine, causing prolonged CPU consumption.

**Exploitability in This Project:**
Not Affected - Version 2.12.0 is newer than the fixed version 2.4.0.

**Status:** Safe - current version includes the fix.

---

## [DEPS] fastapi: No Known Vulnerabilities

**Package:** fastapi
**Installed Version:** 0.115.14
**Latest Version:** 0.128.0
**Severity:** Safe

**Description:**
No CVEs found for the core FastAPI framework. Related ecosystem packages (fastapi-sso, fastapi-users, fastapi-admin) have had vulnerabilities, but these are separate packages not used in this project.

**Status:** Safe - consider updating to latest for bug fixes.

---

## [DEPS] uvicorn: No Recent Vulnerabilities

**Package:** uvicorn
**Installed Version:** 0.32.1
**Latest Version:** 0.40.0
**Severity:** Safe

**Description:**
Historical CVE-2020-7695 (HTTP response splitting) was fixed in 0.11.7. No new CVEs found for 2024-2025.

**Status:** Safe - consider updating to latest for improvements.

---

## [DEPS] psycopg: No Direct Vulnerabilities

**Package:** psycopg (v3)
**Installed Version:** 3.2.10
**Severity:** Safe

**Description:**
No direct CVEs found for psycopg3. Note: PostgreSQL server-side vulnerabilities (CVE-2025-1094, CVE-2024-10977) may affect applications - ensure PostgreSQL server is patched.

**Status:** Safe - ensure PostgreSQL server is up to date.

---

## [DEPS] argon2-cffi, pyotp, itsdangerous, python3-saml: No Known Vulnerabilities

**Packages:**
- argon2-cffi 23.1.0
- pyotp 2.9.0
- itsdangerous 2.2.0
- python3-saml 1.16.0

**Severity:** Safe

**Description:**
No CVEs found in vulnerability databases for these packages at their installed versions. Note: python3-saml should be monitored given the high number of SAML-related vulnerabilities in other implementations (ruby-saml, samlify).

**Status:** Safe - continue monitoring for new advisories.

---

## [DEPS] Other Production Dependencies: No Known Vulnerabilities

**Packages:**
- resend 2.19.0 - No CVEs (email service SDK)
- sendgrid 6.12.4 - Transitive ecdsa dependency has CVE-2024-23342 (see above)
- pymemcache 4.0.0 - No CVEs found
- email-validator 2.3.0 - No CVEs (actually helps mitigate Python email module issues)
- babel 2.17.0 - No CVEs (Python i18n, not JavaScript Babel)
- argh 0.31.3 - No CVEs found

**Status:** Safe

---

# Security Findings

Security assessment performed: 2026-01-25

---

# Refactoring Opportunities

Refactoring analysis performed: 2026-02-01 (Services Layer Deep Scan)

---

## [REFACTOR] Duplication: Authorization Helpers Repeated Across Services (Resolved)

**Found in:** 9 files in `app/services/`
**Impact:** High
**Category:** Duplication
**Status:** Resolved (2026-02-01)

**Description:**
The `_require_admin()` helper function is duplicated 9 times across service modules with 3 inconsistent variants. Similarly, `_require_super_admin()` is duplicated 3 times with 2 variants.

**Evidence:**
```
_require_admin() found in:
- settings.py:36 (with required_role)
- bg_tasks.py:19 (simple)
- groups.py:47 (with required_role)
- emails.py:34 (with required_role)
- users.py:40 (with event logging)
- event_log.py:171 (simple)
- exports.py:19 (simple)
- reactivation.py:31 (with required_role)
- mfa.py:51 (with event logging)

_require_super_admin() found in:
- settings.py:46 (with required_role)
- saml.py:75 (with event logging)
- users.py:63 (with event logging)
```

**Why It Matters:**
- Bug risk: Changes to authorization logic must be made in 12 places
- Inconsistency: Some variants log authorization failures, some don't
- Inconsistency: Some include `required_role` kwarg, some don't

**Suggested Refactoring:**
Create centralized authorization helpers in `app/services/auth.py`:

```python
# app/services/auth.py
from services.types import RequestingUser
from services.exceptions import ForbiddenError
from services.event_log import log_event

def require_admin(user: RequestingUser, log_failure: bool = False) -> None:
    """Raise ForbiddenError if user is not admin or super_admin."""
    if user["role"] not in ("admin", "super_admin"):
        if log_failure:
            log_event(
                tenant_id=user["tenant_id"],
                actor_user_id=user["id"],
                event_type="authorization_denied",
                artifact_type="system",
                artifact_id=user["tenant_id"],
                metadata={"required_role": "admin", "actual_role": user["role"]},
            )
        raise ForbiddenError(
            message="Admin access required",
            code="admin_required",
            required_role="admin",
        )

def require_super_admin(user: RequestingUser, log_failure: bool = False) -> None:
    """Raise ForbiddenError if user is not super_admin."""
    # Similar implementation
```

Then update all service files to import from `services.auth`.

**Files Affected:** 9 service files (settings.py, bg_tasks.py, groups.py, emails.py, users.py, event_log.py, exports.py, reactivation.py, mfa.py, saml.py)

**Resolution:**
Created `app/services/auth.py` with centralized `require_admin()` and `require_super_admin()` functions that support optional logging. Updated 8 service files to use these functions (event_log.py kept local copy to avoid circular import). Reduced duplication from 12 function definitions to 3 (auth.py + event_log.py fallback).

---

## [REFACTOR] Abstraction: God Module - saml.py

**Found in:** `app/services/saml.py`
**Impact:** High
**Category:** Abstraction (God Module)

**Description:**
The `saml.py` service module has grown to 2,658 lines with 45 functions, handling many distinct responsibilities. This makes the module difficult to navigate, understand, and maintain.

**Evidence:**
```bash
$ wc -l app/services/saml.py
2658 app/services/saml.py

$ grep -c "^def " app/services/saml.py
45
```

The module handles:
1. SP Certificate management (generate, rotate, get)
2. IdP CRUD operations (create, update, delete, list)
3. IdP metadata import/refresh from URL or XML
4. SAML request building (AuthnRequest)
5. SAML response processing and validation
6. JIT user provisioning
7. Domain-to-IdP binding management
8. User IdP assignment
9. SP-initiated logout
10. IdP-initiated logout request handling
11. Authentication routing logic
12. Debug entry storage and retrieval

**Why It Matters:**
- Cognitive overload when working on any SAML feature
- High risk of unintended side effects when modifying code
- Testing is more complex due to many interdependencies
- Difficult to onboard new developers to this area

**Suggested Refactoring:**
Split into focused sub-modules under `app/services/saml/`:

```
app/services/saml/
├── __init__.py          # Re-exports for backwards compatibility
├── certificates.py      # SP certificate management (~100 lines)
├── providers.py         # IdP CRUD operations (~400 lines)
├── metadata.py          # Metadata import/refresh (~300 lines)
├── auth.py              # Request building, response processing (~500 lines)
├── provisioning.py      # JIT provisioning logic (~150 lines)
├── domains.py           # Domain binding management (~300 lines)
├── logout.py            # Logout flows (~300 lines)
├── routing.py           # Auth routing logic (~200 lines)
└── debug.py             # Debug entry storage (~100 lines)
```

The `__init__.py` can re-export all public functions to maintain backwards compatibility.

**Files Affected:** saml.py would become a package with ~10 sub-modules

---

## [REFACTOR] Complexity: Long Functions in User Management

**Found in:** `app/services/users.py:587-717`, `app/services/saml.py:1235-1365`
**Impact:** Medium
**Category:** Complexity (Long Methods)

**Description:**
Several functions exceed 100 lines, making them harder to understand and test in isolation.

**Evidence:**
```
- update_user() in users.py:587-717 (~130 lines)
- process_saml_response() in saml.py:1235-1365 (~130 lines)
- sync_user_idp_groups() in groups.py:1086-1207 (~121 lines)
```

**Why It Matters:**
- Functions doing multiple distinct tasks are harder to test
- Increased cognitive load when reading the code
- Higher chance of bugs in edge cases

**Suggested Refactoring:**
Extract sub-operations into focused helper functions:

For `update_user()`:
```python
def update_user(...) -> UserDetail:
    _require_admin(requesting_user)
    user = _get_user_or_raise(tenant_id, user_id)
    _validate_role_change(requesting_user, user, user_update.role)
    changes = _apply_user_updates(tenant_id, user_id, user, user_update)
    _log_user_changes(tenant_id, requesting_user["id"], user_id, changes)
    return _fetch_user_detail(tenant_id, user_id)
```

**Files Affected:** users.py, saml.py, groups.py

---

# Technical Debt

## Service Layer Architecture: Groups Router Bypasses Service Layer (Resolved)

**Status:** Resolved (2026-02-01)

**Resolution:**
- Added three service functions to `app/services/groups.py`: `list_available_users_for_group()`, `list_available_parents()`, `list_available_children()`
- Removed `import database` from the router
- Router now calls service functions with proper authorization and activity tracking
- Added 7 unit tests for the new service functions

---

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 0 | - |
| High | 1 | Refactoring (God module) |
| Medium | 1 | Refactoring (Long functions) |
| Low | 0 | - |

## Dependency Audit Summary (2026-02-01)

| Severity | Count | Packages |
|----------|-------|----------|
| Critical | 0 | - |
| High | 1 | ecdsa (transitive, no fix available) |
| Medium | 0 | - |
| Low | 0 | - |

### Packages Requiring Attention

1. **ecdsa** - Transitive via sendgrid, no fix available (timing attack, low exploitability)

### Packages Confirmed Safe
Most production dependencies are at versions that include fixes for known CVEs. Recent CVEs in the Python ecosystem (CVE-2026-21226 Azure Core, CVE-2025-68668 n8n, CVE-2025-68664 LangChain) do not affect this project.

**Priority Remediation Order:**
1. ~~XSS in users_list.html (Critical - immediate exploit)~~ **RESOLVED**
2. ~~CSRF protection (High - easy to exploit)~~ **RESOLVED**
3. ~~Rate limiting (High - enables brute force)~~ **RESOLVED**
4. ~~Session fixation (High - account takeover)~~ **RESOLVED**
5. ~~OAuth2 state validation (High - OAuth CSRF)~~ **RESOLVED**
6. ~~Default secret keys (High - production misconfiguration)~~ **RESOLVED**
7. ~~BYPASS_OTP risk (Medium - MFA bypass in production)~~ **RESOLVED**
8. ~~Logging gaps (High - compliance/detection)~~ **RESOLVED**
9. ~~Security headers (Medium - defense in depth)~~ **RESOLVED**
10. ~~OpenAPI debug endpoints exposed (Medium - information disclosure)~~ **RESOLVED**
11. ~~CSP unsafe-inline (Low - defense in depth)~~ **RESOLVED**
12. ~~user-agents unmaintained (Low - replaced with ua-parser)~~ **RESOLVED**
13. ~~CSRF backstop test (Low - added static analysis test)~~ **RESOLVED**
