# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## [SECURITY] Session ID Not Regenerated After Authentication

**Found in:** `app/routers/mfa.py:93`, `app/routers/auth.py:184, 427`
**Severity:** High
**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Description:** After successful authentication (including MFA verification), the session ID is not regenerated. Only the `user_id` is written to the existing session.

**Attack Scenario:** Session fixation attack:
1. Attacker creates session and obtains session ID
2. Attacker tricks victim into using that session ID (via URL or cookie injection)
3. Victim authenticates
4. Attacker now has authenticated access via the known session ID

**Evidence:**
```python
# Line 93 in mfa.py
request.session["user_id"] = pending_user_id
request.session["session_start"] = int(__import__("time").time())
# Missing: session.regenerate() or equivalent
```

**Impact:** Account takeover via session fixation.

**Remediation:** Regenerate session ID after successful authentication. Clear old session data and create new session cookie.

---

## [SECURITY] OAuth2 State Parameter Not Validated (CSRF)

**Found in:** `app/routers/oauth2.py:29, 104, 120, 179`
**Severity:** High
**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Description:** The OAuth2 `state` parameter is accepted and echoed back but never validated server-side. No session-based state storage or verification.

**Attack Scenario:** OAuth2 CSRF attack:
1. Attacker initiates OAuth flow with their own account
2. Attacker intercepts redirect with authorization code
3. Attacker tricks victim into clicking the redirect URL
4. Victim's session gets linked to attacker's account

**Evidence:**
```python
return RedirectResponse(
    url=f"{redirect_uri}?code={code}" + (f"&state={state}" if state else ""),
    status_code=303,
)
```
No session-based state validation found.

**Impact:** Account linking attacks, unauthorized OAuth grants.

**Remediation:** Generate state with `secrets.token_urlsafe(32)`, store in session, validate on callback before issuing tokens.

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

## [SECURITY] Default Secret Keys in Settings

**Found in:** `app/settings.py:39-44`
**Severity:** High
**OWASP Category:** A05:2021 - Security Misconfiguration

**Description:** Secret keys have insecure default values that could be used if environment variables are not set.

**Evidence:**
```python
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", "dev-secret-key-change-in-production")
MFA_ENCRYPTION_KEY = os.environ.get("MFA_ENCRYPTION_KEY", "dev-mfa-key-change-in-production-must-be-base64")
SAML_KEY_ENCRYPTION_KEY = os.environ.get("SAML_KEY_ENCRYPTION_KEY", "dev-saml-key-change-in-production-must-be-base64")
```

**Impact:** If deployed without proper environment config, session forgery and MFA/SAML encryption compromise.

**Remediation:** Remove default values or raise explicit error if not set in production. Add startup check that fails if secrets are default values and `IS_DEV=False`.

---

## [SECURITY] Failed Login Attempts Not Logged

**Found in:** `app/utils/auth.py:23-68`, `app/routers/auth.py:136-162`
**Severity:** High
**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures

**Description:** Failed login attempts (invalid credentials, inactive user) return error responses but are not logged to the event log.

**Impact:**
- Cannot detect brute force attacks
- No audit trail for security investigations
- Compliance gap for security monitoring requirements

**Remediation:** Add `log_event()` calls for failed authentication attempts with metadata (email attempted, failure reason, IP address).

---

## [SECURITY] Logout Events Not Logged

**Found in:** `app/routers/auth.py:204-208`
**Severity:** Medium
**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures

**Description:** User logout clears the session but does not create an audit log entry.

**Evidence:**
```python
@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)
```

**Impact:** Cannot track user session lifecycle for security audits.

**Remediation:** Add `log_event(tenant_id, user_id, "user", user_id, "user_signed_out", ...)` before clearing session.

---

## [SECURITY] Password Changes Not Logged

**Found in:** `app/services/users.py:1128`, `app/routers/auth.py:384-439`
**Severity:** High
**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures

**Description:** Password updates via `update_password()` and the `/set-password` endpoint do not emit event logs.

**Impact:** Cannot detect unauthorized password changes or track password lifecycle for compliance.

**Remediation:** Add `log_event()` for password changes: `password_set` (initial), `password_changed` (update).

---

## [SECURITY] Authorization Failures Not Logged

**Found in:** `app/services/mfa.py:51-58`, `app/services/saml.py:67-74`, `app/services/users.py:607-609`
**Severity:** Medium
**OWASP Category:** A09:2021 - Security Logging and Monitoring Failures

**Description:** When `ForbiddenError` is raised (unauthorized access attempts), no audit log is created.

**Impact:** Cannot detect privilege escalation attempts or unauthorized access patterns.

**Remediation:** Wrap authorization failures with `log_event()` calls or add logging in the `_require_admin()` and `_require_super_admin()` helper functions.

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

## [SECURITY] BYPASS_OTP Feature Risk

**Found in:** `app/settings.py:37`, `app/utils/mfa.py:53-55`
**Severity:** Medium
**OWASP Category:** A07:2021 - Identification and Authentication Failures

**Description:** The `BYPASS_OTP` setting allows any 6-digit code to pass MFA verification. While intended for development, accidental production enablement is catastrophic.

**Evidence:**
```python
if settings.BYPASS_OTP and len(code) == 6 and code.isdigit():
    return True  # Accepts ANY 6-digit code
```

**Impact:** Complete MFA bypass if accidentally enabled in production.

**Remediation:** Add startup check that prevents application from starting if `BYPASS_OTP=True` and `IS_DEV=False`. Or remove the feature entirely.

---

## Summary

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 0 | - |
| High | 6 | Session, OAuth2, Secrets, Logging |
| Medium | 6 | Headers, Exceptions, SAML XSS, SQL patterns, MFA bypass, Auth logging |

**Priority Remediation Order:**
1. ~~XSS in users_list.html (Critical - immediate exploit)~~ **RESOLVED**
2. ~~CSRF protection (High - easy to exploit)~~ **RESOLVED**
3. ~~Rate limiting (High - enables brute force)~~ **RESOLVED**
4. Session fixation (High - account takeover)
5. OAuth2 state validation (High - OAuth CSRF)
6. Security headers (Medium - defense in depth)
7. Logging gaps (High - compliance/detection)
8. Other Medium items
