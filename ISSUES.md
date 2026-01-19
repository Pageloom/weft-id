# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## [BUG] SAML Router Route Ordering Bug - Phase 4 Endpoints Partially Unreachable

**Found in:** `app/routers/saml.py`
**Severity:** High
**Description:** FastAPI route ordering bug prevents two SAML Phase 4 endpoints from being reached. The parameterized route `/admin/identity-providers/{idp_id}` is defined (line 742) before the literal routes `/admin/identity-providers/rotate-certificate` (line 1029) and `/admin/identity-providers/debug` (line 1134). This causes FastAPI to match "rotate-certificate" and "debug" as `idp_id` values, routing requests to the wrong handler.

**Evidence:**
- `POST /admin/identity-providers/rotate-certificate` returns 422 Unprocessable Entity with validation errors for `name`, `sso_url`, `certificate_pem` (fields from `update_idp` handler)
- `GET /admin/identity-providers/debug` fails similarly (matched as `idp_id="debug"`)
- Route order in file: `{idp_id}` at line 742, `rotate-certificate` at line 1029, `debug` at line 1134
- Note: `/admin/identity-providers/debug/{entry_id}` works because it has 4 path segments vs 3 for `{idp_id}`

**Impact:**
- Certificate rotation feature is completely inaccessible via web UI
- Debug log list feature is inaccessible via web UI
- Debug detail view WORKS (different path depth)

**Root Cause:** FastAPI matches routes in definition order. Literal paths must be defined BEFORE parameterized paths to take precedence.

**Suggested Fix:**
Move these routes BEFORE line 742 (before `{idp_id}` routes):
1. `/admin/identity-providers/rotate-certificate` (currently at line 1029)
2. `/admin/identity-providers/debug` (currently at line 1134)

Note: `/admin/identity-providers/debug/{entry_id}` does NOT need to be moved (different segment count).

**Files to modify:**
- `app/routers/saml.py` - Reorder route definitions

**Verification:**
After fixing, remove `@pytest.mark.xfail` from these 4 tests in `tests/test_routers_saml.py`:
1. `test_rotate_certificate_as_super_admin_success`
2. `test_rotate_certificate_no_existing_cert_shows_error`
3. `test_debug_list_as_super_admin_success`
4. `test_debug_list_shows_entries`

Then run: `poetry run pytest tests/test_routers_saml.py -k "rotate_certificate or debug_list" -v`
All 4 tests should pass after the fix.

---

# Dependency Vulnerabilities

Dependency audit performed: 2026-01-17

**Status:** All dependencies secure. No known CVEs affecting current versions.

---

## [DEPS] python-multipart: CVE-2024-24762 - Content-Type Header ReDoS

**Package:** python-multipart
**Installed Version:** 0.0.9
**Vulnerable Versions:** < 0.0.7
**Fixed Version:** 0.0.7+
**Severity:** High (CVSS: 7.5)
**Advisory:** https://github.com/advisories/GHSA-2jv5-9r88-3w3p

**Description:**
When using form data, python-multipart uses a Regular Expression to parse the HTTP Content-Type header. An attacker could send a custom-made Content-Type option that causes the RegEx to consume CPU resources and stall indefinitely, blocking the main event loop and preventing all request handling.

**Exploitability in This Project:**
Not Affected - Version 0.0.9 is newer than the fixed version 0.0.7.

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

## [DEPS] user-agents: Unmaintained Package Warning

**Package:** user-agents
**Installed Version:** 2.2.0
**Last Updated:** 2020 (>4 years ago)
**Severity:** Low
**Source:** https://github.com/selwin/python-user-agents

**Description:**
Package has not received updates in over 4 years. May not correctly parse modern user agent strings and could have undiscovered vulnerabilities. The package is still functional but is not actively maintained.

**Exploitability in This Project:**
Low - Used only for display/logging purposes, not security decisions.

**Remediation:**
- Consider alternative: `ua-parser` (actively maintained)
- Or accept risk if functionality is non-critical

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
- sendgrid 6.12.4 - No Python SDK CVEs (WordPress plugin CVEs don't apply)
- pymemcache 4.0.0 - No CVEs found
- email-validator 2.3.0 - No CVEs (actually helps mitigate Python email module issues)
- babel 2.17.0 - No CVEs (Python i18n, not JavaScript Babel)
- argh 0.31.3 - No CVEs found

**Status:** Safe

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 0 | - |
| High | 0 | - |
| Medium | 4 | Headers, Exceptions, SAML XSS, SQL patterns |

## Dependency Audit Summary (2026-01-17)

| Severity | Count | Packages |
|----------|-------|----------|
| Critical | 0 | - |
| High | 0 | - |
| Medium | 0 | - |
| Low | 1 | user-agents (unmaintained) |
| Safe | All | All production dependencies |

### Packages Requiring Attention
1. **user-agents** - Unmaintained, consider replacement with `ua-parser` when convenient

### Packages Confirmed Safe
All production dependencies are at versions that include fixes for known CVEs. Recent CVEs in the Python ecosystem (CVE-2026-21226 Azure Core, CVE-2025-68668 n8n, CVE-2025-68664 LangChain) do not affect this project.

**Priority Remediation Order:**
1. ~~XSS in users_list.html (Critical - immediate exploit)~~ **RESOLVED**
2. ~~CSRF protection (High - easy to exploit)~~ **RESOLVED**
3. ~~Rate limiting (High - enables brute force)~~ **RESOLVED**
4. ~~Session fixation (High - account takeover)~~ **RESOLVED**
5. ~~OAuth2 state validation (High - OAuth CSRF)~~ **RESOLVED**
6. ~~Default secret keys (High - production misconfiguration)~~ **RESOLVED**
7. ~~BYPASS_OTP risk (Medium - MFA bypass in production)~~ **RESOLVED**
8. ~~Logging gaps (High - compliance/detection)~~ **RESOLVED**
9. Security headers (Medium - defense in depth)
10. Other Medium items
