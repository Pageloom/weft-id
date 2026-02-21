# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 0 | - |
| Low | 1 | Security (A01) |

**Last security scan:** 2026-02-21 (full OWASP assessment, first review. 5 of 6 issues resolved.)
**Last compliance scan:** 2026-02-21 (all clear, scanner now cross-references migrations)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## [SECURITY] SSO consent flow not bound to authenticated user

**Found in:** `app/routers/saml_idp/sso.py:127-138`
**Severity:** Low
**OWASP Category:** A01:2021 - Broken Access Control
**Description:** The pending SSO context (`pending_sso_sp_id`, etc.) is stored in the session without recording which `user_id` initiated it. If a session were reused by a different user, they could complete another user's SSO flow. Session regeneration on login prevents this in practice.
**Remediation:** Store `pending_sso_user_id` in session and validate it matches on consent.

---
