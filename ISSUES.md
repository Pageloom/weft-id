# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 0 | |
| Low | 1 | Security (on feature branch) |

**Last security scan:** 2026-03-21 (focused: 30-day changes, password lifecycle + group assertion scope)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-08 (structural IA review, 2 direct fixes, 6 issues resolved)

---

## [SECURITY] Response schemas missing max_length on group_assertion_scope

**Found in:** `app/schemas/settings.py:95`, `app/schemas/service_providers.py:93`
**Severity:** Low
**OWASP Category:** A05:2021 - Security Misconfiguration
**Description:** The `TenantSecuritySettings` and `SPConfig` response schemas declare `group_assertion_scope` as a bare `str` (or `str | None`) without `max_length`. The project standard requires all str fields to have `max_length`. The database CHECK constraint prevents invalid values, and these are response-only schemas, so the risk is minimal. Using `Literal` types (as the corresponding input schemas do) would be more consistent.
**Remediation:** Change response schema types to `Literal["all", "trunk", "access_relevant"]` to match input schemas, or add `max_length=50`.

---

