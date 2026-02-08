# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## Medium Severity

### ISSUE-001: Email MFA code not auto-sent on IDP/SAML sign-in

**Category:** UX Bug
**Found:** 2026-02-08
**File:** `app/routers/saml/authentication.py:302-308`

**Problem:** When a user signs in via SAML/IDP and has email-based MFA enabled, no verification email is sent automatically. The user lands on `/mfa/verify` with an empty inbox and must manually click "Send code to my email."

**Root cause:** The SAML ACS handler stores pending MFA session data and redirects to `/mfa/verify` but does not call `create_email_otp()` or `send_mfa_code_email()`. The password login flow (`app/routers/auth/login.py:495-501`) does auto-send.

**Fix:** Add email OTP creation and sending logic to the SAML MFA block in `authentication.py`, matching the password login behavior. Requires importing `create_email_otp`, `send_mfa_code_email`, and `emails_service`.

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 1 | UX Bug |
| Low | 0 | - |

**Last compliance scan:** 2026-02-08 (automated + manual five-principle review)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-07 (full codebase standard scan, no critical files remain)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-06 (users.py and groups.py split into packages)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---
