# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## [DEPS] ecdsa: CVE-2024-23342 - Minerva Timing Attack (Transitive)

**Package:** ecdsa (transitive via sendgrid)
**Installed Version:** 0.19.1
**Severity:** High (CVSS: 7.4)
**Advisory:** https://github.com/advisories/GHSA-wj6h-64fc-37mp

**Description:**
The python-ecdsa library is vulnerable to the Minerva timing attack on P-256 curve operations. The maintainers consider side-channel attacks out of scope because implementing side-channel-free code in pure Python is impossible.

**Exploitability in This Project:**
Low. This is a transitive dependency of sendgrid used for internal token signing. Exploitation requires controlling timing measurements of sendgrid API calls and gathering hundreds of samples.

**Remediation Options:**
1. Accept the risk (sendgrid's internal use is not directly exploitable)
2. Replace sendgrid with resend (this project already has resend as primary email backend)
3. Monitor for sendgrid updates that switch to pyca/cryptography

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

## [REFACTOR] File Structure: Large Database Layer Files

**Found in:** `app/database/`
**Impact:** High (Claude Traversability)
**Category:** File Structure

**Description:**
Four database modules exceed 500 lines, making them harder for Claude to efficiently work with:
- `app/database/saml.py` (1112 lines)
- `app/database/users.py` (1003 lines)
- `app/database/groups.py` (936 lines)
- `app/database/oauth2.py` (842 lines)

**Why It Matters:**
Claude reads entire files into a limited context window. Files >500 lines make it harder to understand a concept without loading irrelevant code. The database layer should mirror the services layer structure.

**Suggested Refactoring:**
Follow the pattern used for `app/services/saml/` and split each large database module into focused sub-modules:
- `app/database/saml/` with files like `providers.py`, `auth.py`, `metadata.py`
- `app/database/users/` with files like `core.py`, `emails.py`, `lifecycle.py`

**Files Affected:** 4 database modules plus any imports

---

## [REFACTOR] File Structure: Large Router Files

**Found in:** `app/routers/`, `app/routers/api/v1/`
**Impact:** High (Claude Traversability)
**Category:** File Structure

**Description:**
Four router modules exceed 500 lines:
- `app/routers/saml.py` (1241 lines)
- `app/routers/auth.py` (987 lines)
- `app/routers/users.py` (747 lines)
- `app/routers/api/v1/users.py` (1025 lines)

**Why It Matters:**
Routers that are too large contain many unrelated endpoints in one file. When Claude needs to modify one endpoint, it must load many irrelevant endpoints.

**Suggested Refactoring:**
Split large routers by functionality:
- `app/routers/saml.py` → `saml/login.py`, `saml/logout.py`, `saml/acs.py`, `saml/metadata.py`
- `app/routers/auth.py` → `auth/login.py`, `auth/password.py`, `auth/verification.py`
- `app/routers/api/v1/users.py` → `users/profile.py`, `users/emails.py`, `users/mfa.py`, `users/admin.py`

**Files Affected:** 4 router modules plus any imports

---

## [REFACTOR] Dead Code: Unused Converter Functions

**Found in:** `app/routers/api/v1/users.py:45-109, 182-190`
**Impact:** Medium
**Category:** Dead Code

**Description:**
Four converter functions are defined but never called:
- `_user_to_profile()` (lines 45-59)
- `_user_to_summary()` (lines 62-75)
- `_user_to_detail()` (lines 78-108)
- `_email_to_info()` (lines 182-190)

These functions exist because the services layer now returns Pydantic schemas directly, making router-level conversion unnecessary.

**Evidence:**
```bash
grep -rn "_user_to_profile\|_user_to_summary\|_user_to_detail\|_email_to_info" app --include="*.py" | grep -v "def "
# Returns nothing - functions are never called
```

**Suggested Refactoring:**
Delete the unused functions (~60 lines total).

**Files Affected:** `app/routers/api/v1/users.py`

---

## [REFACTOR] Architecture: Event Logging in Routers

**Found in:** `app/routers/auth.py`, `app/routers/mfa.py`
**Impact:** Low
**Category:** Coupling / Consistency

**Description:**
5 direct `log_event()` calls exist in routers:
- `auth.py:571` - login_failed (invalid credentials)
- `auth.py:603` - login_failed (inactivated user)
- `auth.py:676` - user_signed_out
- `auth.py:943` - password_set
- `mfa.py:132` - user_signed_in

Per the architectural pattern ("all writes go through service layer"), event logging should occur in services, not routers.

**Context:**
These are authentication-related events that occur during login/logout flows. The auth module may be a special case since login is inherently router-level, but this creates inconsistency.

**Suggested Refactoring:**
Option 1: Accept as special case for auth flows (login/logout are fundamentally router operations)
Option 2: Create a thin auth service that handles session creation and logging

**Files Affected:** `app/routers/auth.py`, `app/routers/mfa.py`

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 3 | 1 dependency (transitive), 2 file structure |
| Medium | 2 | 1 long functions, 1 dead code |
| Low | 1 | Architecture consistency |

**Last dependency audit:** 2026-02-01 (all direct dependencies are at safe versions)
**Last refactor scan:** 2026-02-01 (full codebase deep scan)
