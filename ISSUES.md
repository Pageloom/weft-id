# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

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

# Technical Debt

## [CLEANUP] RequestingUser.request_metadata field is superfluous

**Severity:** Low (cleanup)
**Category:** Technical Debt

**Description:**
The `request_metadata` field in `RequestingUser` (defined in `app/services/types.py`) and the explicit passing pattern `request_metadata=requesting_user.get("request_metadata")` in `log_event()` calls are now superfluous.

Event request context (IP address, user agent, device, session) is handled automatically by:
1. `RequestContextMiddleware` sets a contextvar for ALL web requests
2. `log_event()` auto-reads from the contextvar if `request_metadata` not explicitly passed
3. `RuntimeError` is raised if context is missing and not in `system_context()`

**Evidence:**
- ~33 occurrences of `request_metadata=requesting_user.get("request_metadata")` across service files
- `RequestingUser` TypedDict has `request_metadata: NotRequired[dict[str, Any] | None]` field
- `build_requesting_user()` in `app/dependencies.py` populates this field

**Impact:**
- Unnecessary boilerplate code
- Confusing for developers (two ways to pass context)
- Extra work in `build_requesting_user()` to populate unused field

**Suggested Fix:**
1. Remove `request_metadata` field from `RequestingUser` TypedDict
2. Remove all `request_metadata=requesting_user.get("request_metadata")` arguments from `log_event()` calls
3. Simplify `build_requesting_user()` to not extract request metadata
4. Rely entirely on the contextvar mechanism

**Files to modify:**
- `app/services/types.py` - Remove field from TypedDict
- `app/dependencies.py` - Simplify `build_requesting_user()`
- `app/services/*.py` - Remove explicit `request_metadata` arguments (~33 occurrences)

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 0 | - |
| High | 0 | - |
| Medium | 0 | - |
| Low | 1 | Technical Debt (RequestingUser.request_metadata cleanup) |

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
