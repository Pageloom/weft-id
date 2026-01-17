# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## [BUG] KeyError in list_domain_bindings Service Function

**Found in:** `app/services/saml.py:1598`, `app/database/saml.py:562`
**Severity:** High
**Description:** The `list_domain_bindings` service function crashes with `KeyError: 'idp_id'` when called.

**Evidence:**
The service function at `app/services/saml.py:1593-1599` tries to access `row["idp_id"]`:
```python
items = [
    DomainBinding(
        id=str(row["id"]),
        domain_id=str(row["domain_id"]),
        domain=row["domain"],
        idp_id=str(row["idp_id"]),  # <-- KeyError here
        created_at=row["created_at"],
```

But the database query at `app/database/saml.py:562` only returns:
```sql
select db.id, db.domain_id, pd.domain, db.created_at
from saml_idp_domain_bindings db
```

The `idp_id` column is not selected.

**Impact:** Any attempt to list domain bindings for an IdP will crash the application with a KeyError. This affects the SAML IdP admin pages.

**Root Cause:** Database query was not updated when the service layer was created, or the service function added a field that the query doesn't provide.

**Suggested fix:**
Add `db.idp_id` to the SELECT in `app/database/saml.py:562`:
```sql
select db.id, db.domain_id, pd.domain, db.idp_id, db.created_at
```

**Files to modify:**
- `app/database/saml.py:562` - Add `db.idp_id` to the SELECT clause

---

## [SECURITY] Missing Security Headers

**Found in:** `app/main.py` (no security header middleware)
**Severity:** Medium
**OWASP Category:** A05:2021 - Security Misconfiguration

**Description:** Standard HTTP security headers are not configured.

**Missing Headers:**
- `Content-Security-Policy` - Prevents XSS
- `X-Frame-Options` - Prevents clickjacking
- `X-Content-Type-Options` - Prevents MIME sniffing
- `Strict-Transport-Security` - Enforces HTTPS
- `Referrer-Policy` - Controls referrer leakage

**Impact:** Increased attack surface for XSS, clickjacking, and other client-side attacks.

**Remediation:** Add security headers middleware:
```python
from starlette.middleware import Middleware
# Add headers via middleware or use secure-headers library
```

---

## [SECURITY] Raw Exceptions Exposed in OAuth2 Clients API

**Found in:** `app/routers/api/v1/oauth2_clients.py:87-88, 124-125`
**Severity:** Medium
**OWASP Category:** A02:2021 - Cryptographic Failures (Information Disclosure)

**Description:** Generic exceptions are caught and converted directly to HTTP response details, potentially exposing internal implementation details.

**Evidence:**
```python
except Exception as e:
    raise HTTPException(status_code=400, detail=str(e))
```

**Impact:** May leak SQL errors, database structure, or internal logic to attackers.

**Remediation:** Use `translate_to_http_exception()` from `utils/service_errors.py` for consistent, safe error handling.

---

## [SECURITY] Reflected XSS in SAML relay_state Parameter

**Found in:** `app/templates/saml_idp_select.html:24`, `app/routers/saml.py:389-391`
**Severity:** Medium
**OWASP Category:** A03:2021 - Injection

**Description:** The `relay_state` parameter is reflected into URLs without proper URL encoding.

**Evidence:**
```html
<a href="/saml/login/{{ idp.id }}{% if relay_state %}?relay_state={{ relay_state }}{% endif %}">
```

**Attack Scenario:** Attacker crafts URL with `relay_state=javascript:alert('XSS')` or URL with special characters.

**Remediation:** Use `{{ relay_state | urlencode }}` in templates or validate/sanitize relay_state server-side.

---

## [SECURITY] SQL f-string Patterns (Defense in Depth)

**Found in:** `app/database/_core.py:107, 123`, `app/database/users.py:300-324`, `app/database/saml.py:290-317`
**Severity:** Medium (Mitigated)
**OWASP Category:** A03:2021 - Injection

**Description:** Several database functions use f-strings to construct SQL queries. While currently mitigated by input validation, this pattern is fragile.

**Locations:**
1. `SET LOCAL app.tenant_id` uses f-string (mitigated by UUID validation)
2. Dynamic collation in ORDER BY (mitigated by router validation)
3. Dynamic SET clause field names in SAML update (mitigated by field whitelist)

**Impact:** If validation is bypassed or new code paths added without validation, SQL injection becomes possible.

**Remediation:** Refactor to use parameterized queries where possible. Document why f-strings are necessary (e.g., SET LOCAL doesn't support parameters) with clear security notes.

---

# Dependency Vulnerabilities

Dependency audit performed: 2026-01-08

---

## [DEPS] cryptography: CVE-2024-26130 - NULL Pointer Dereference (Not Affected)

**Package:** cryptography
**Installed Version:** 41.0.7
**Vulnerable Versions:** 38.0.0 - 42.0.3
**Fixed Version:** 42.0.4+
**Severity:** High (CVSS: 7.5)
**Advisory:** https://nvd.nist.gov/vuln/detail/cve-2024-26130

**Description:**
If `pkcs12.serialize_key_and_certificates` is called with both a certificate whose public key did not match the provided private key and an `encryption_algorithm` with `hmac_hash` set, then a NULL pointer dereference would occur, crashing the Python process.

**Exploitability in This Project:**
Not Affected - Version 41.0.7 is below the vulnerable range (38.0.0-42.0.3). This CVE affects versions 38.0.0+ but the fix is in 42.0.4.

**Status:** Monitor only - current version is safe from this specific CVE.

---

## [DEPS] cryptography: CVE-2024-12797 - Vulnerable OpenSSL in Wheels (Not Affected)

**Package:** cryptography
**Installed Version:** 41.0.7
**Vulnerable Versions:** 42.0.0 - 44.0.0
**Fixed Version:** 44.0.1+
**Severity:** Medium (OpenSSL TLS/DTLS RPK issue)
**Advisory:** https://nvd.nist.gov/vuln/detail/CVE-2024-12797

**Description:**
pyca/cryptography's wheels include a statically linked copy of OpenSSL. Versions 42.0.0-44.0.0 bundle vulnerable OpenSSL versions affected by CVE-2024-12797, which affects TLS and DTLS connections using Raw Public Keys (RPKs).

**Exploitability in This Project:**
Not Affected - Version 41.0.7 is below the vulnerable range (42.0.0+).

**Status:** No action required for current version.

---

## [DEPS] cryptography: Outdated Version Advisory

**Package:** cryptography
**Installed Version:** 41.0.7
**Latest Stable:** 44.0.1+
**Severity:** Low (Informational)

**Description:**
The installed version 41.0.7 is significantly behind the current release. While not vulnerable to the specific CVEs above, newer versions contain security improvements, bug fixes, and updated OpenSSL bundled libraries.

**Recommendation:**
Consider updating version constraint to `cryptography = "^44.0.1"` for latest security patches. Note: Major version upgrades may have breaking changes - review changelog.

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
| High | 1 | KeyError in list_domain_bindings |
| Medium | 4 | Headers, Exceptions, SAML XSS, SQL patterns |

## Dependency Audit Summary (2026-01-08)

| Severity | Count | Packages |
|----------|-------|----------|
| Critical | 0 | - |
| High | 0 | - |
| Medium | 0 | - |
| Low | 1 | user-agents (unmaintained) |
| Safe | 18 | All other production dependencies |

### Packages Requiring Attention
1. **cryptography** - Consider upgrade to 44.0.1+ (informational, not vulnerable)
2. **user-agents** - Unmaintained, consider replacement with `ua-parser`

### Packages Confirmed Safe
All production dependencies are at versions that include fixes for known CVEs.

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
