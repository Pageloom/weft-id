# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 2 | Security |
| Low | 1 | Security |

**Last security scan:** 2026-03-21 (focused: 30-day changes, password lifecycle + group assertion scope)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-08 (structural IA review, 2 direct fixes, 6 issues resolved)

---

## [SECURITY] Missing rate limiting on password change endpoints

**Found in:** `app/routers/account.py:204`, `app/routers/api/v1/users/password.py:16`
**Severity:** Medium
**OWASP Category:** A07:2021 - Identification and Authentication Failures
**Description:** The password change form (POST `/account/password`) and API endpoint (PUT `/api/v1/users/me/password`) have no rate limiting. An attacker with a hijacked session or stolen Bearer token could brute-force the current password via repeated submissions.
**Attack Scenario:** Attacker steals a session cookie (e.g., via XSS on a different site sharing the domain, or physical access). They submit password change requests with candidate current passwords at high speed. No rate limit slows the attack.
**Impact:** Current password disclosure, full account takeover.
**Remediation:** Add rate limiting to both endpoints, keyed by user ID. Suggested limit: 5 attempts per 15 minutes. The existing `check_rate_limit` utility can be reused.

---

## [SECURITY] Content injection via unvalidated query parameters in flash messages

**Found in:** `app/templates/set_password.html:27`, `app/templates/settings_password.html:43`, `app/templates/forced_password_reset.html:36`, `app/templates/reset_password.html:36`, `app/templates/forgot_password.html:27`
**Severity:** Medium
**OWASP Category:** A03:2021 - Injection
**Description:** Several password-related templates render `{{ error }}` or `{{ success }}` as a final fallthrough branch when the value doesn't match known constants. These values originate from query parameters (`?error=...`, `?success=...`). Jinja2 autoescape prevents XSS, but an attacker can craft URLs with arbitrary text that displays in success/error banners (e.g., `?success=Your+account+has+been+compromised`).
**Attack Scenario:** Attacker sends a phishing link like `https://tenant.example.com/set-password?success=Contact+support+at+evil.com+to+verify+your+identity`. The victim sees a legitimate-looking success message on the real site.
**Impact:** Social engineering, phishing via content injection on trusted domain.
**Remediation:** Replace fallthrough `{{ error }}` branches with a generic message like "An unexpected error occurred." Only render known, hardcoded message strings.

---

## [SECURITY] Response schemas missing max_length on group_assertion_scope

**Found in:** `app/schemas/settings.py:95`, `app/schemas/service_providers.py:93`
**Severity:** Low
**OWASP Category:** A05:2021 - Security Misconfiguration
**Description:** The `TenantSecuritySettings` and `SPConfig` response schemas declare `group_assertion_scope` as a bare `str` (or `str | None`) without `max_length`. The project standard requires all str fields to have `max_length`. The database CHECK constraint prevents invalid values, and these are response-only schemas, so the risk is minimal. Using `Literal` types (as the corresponding input schemas do) would be more consistent.
**Remediation:** Change response schema types to `Literal["all", "trunk", "access_relevant"]` to match input schemas, or add `max_length=50`.

---

