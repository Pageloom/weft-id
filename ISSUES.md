# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Dependency Vulnerabilities

Dependency audit performed: 2026-01-31

**Status:** Two vulnerabilities found. One requires update, one is transitive with no fix available.

---

## [DEPS] python-multipart: CVE-2026-24486 - Path Traversal

**Package:** python-multipart
**Installed Version:** 0.0.18
**Vulnerable Versions:** < 0.0.22
**Fixed Version:** 0.0.22
**Severity:** High (CVSS: 8.6)
**Advisory:** https://github.com/advisories/GHSA-wp53-j4wj-2cfg

**Description:**
A path traversal vulnerability exists when using non-default configuration options UPLOAD_DIR and UPLOAD_KEEP_FILENAME=True. An attacker can write uploaded files to arbitrary locations on the filesystem by crafting a malicious filename that begins with `/`.

**Exploitability in This Project:**
Low - This project does not use UPLOAD_DIR or UPLOAD_KEEP_FILENAME configurations. The multipart parsing is only used for form data (CSRF tokens), not file uploads.

**Remediation:**
Update to version 0.0.22 or later: `poetry update python-multipart`

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

# Technical Debt

## [TD-001] Inline JavaScript Event Handlers Blocked by CSP

**Severity:** High
**Discovered:** 2026-01-31
**Category:** Security / UX

**Description:**
Many templates use inline JavaScript event handlers (e.g., `onclick="window.location='...'"`, `onclick="showModal()"`). These are blocked by the Content Security Policy which uses nonces for script execution. Only `<script nonce="...">` blocks execute; inline event attributes are silently ignored.

**Impact:**
- Buttons and clickable elements fail silently (no error shown to user)
- Modal dialogs don't open
- Table row clicks don't navigate
- Form validation doesn't trigger

**Affected Templates (partial list):**
- `integrations_apps.html` - Create App button, modal interactions
- `integrations_b2b.html` - Create B2B Client button, modal interactions
- `saml_idp_list.html` - various action buttons
- `saml_idp_form.html` - Test Connection, form interactions
- Any template with `onclick=`, `onsubmit=`, `onchange=` attributes

**Root Cause:**
CSP nonce-based script execution was implemented to replace `unsafe-inline`, but inline event handlers were not migrated to use event listeners attached from nonce-protected script blocks.

**Remediation:**
1. Audit all templates for inline event handlers: `grep -r "onclick=\|onsubmit=\|onchange=\|onkeydown=" app/templates/`
2. For each handler, either:
   - Replace with `<a href="...">` tags where navigation is the goal
   - Move logic to `<script nonce="{{ csp_nonce }}">` block and attach via `addEventListener`
3. Add a lint/test to prevent future inline handlers

**Workaround Applied:**
`integrations_apps.html` and `integrations_b2b.html` table rows were converted to use anchor tags with a details icon column.

---

No other technical debt items.

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 0 | - |
| High | 1 | Technical Debt (TD-001: Inline JS handlers) |
| Medium | 0 | - |
| Low | 0 | - |

## Dependency Audit Summary (2026-01-31)

| Severity | Count | Packages |
|----------|-------|----------|
| Critical | 0 | - |
| High | 2 | python-multipart, ecdsa (transitive) |
| Medium | 0 | - |
| Low | 0 | - |

### Packages Requiring Attention

1. **python-multipart** - Update to 0.0.22 (path traversal, low exploitability in this project)
2. **ecdsa** - Transitive via sendgrid, no fix available (timing attack, low exploitability)

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
