# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 1 | Security |
| Low | 1 | Security (on feature branch) |

**Last security scan:** 2026-03-21 (deep: full codebase, all OWASP categories)
**Last compliance scan:** 2026-03-19 (1 low: SendGrid client missing timeout)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)
**Last copy review:** 2026-03-08 (structural IA review, 2 direct fixes, 6 issues resolved)

---

## [SECURITY] LIKE wildcard injection in search queries

**Found in:** `app/database/users/listing.py:23-31`, `app/database/groups/memberships.py:22-29`, `app/database/groups/listing.py:18-19,51-52`, `app/database/users/saml_assignment.py:123,131`, `app/database/saml/security.py:63,98`
**Severity:** Medium
**OWASP Category:** A03:2021 - Injection
**Description:** User-supplied search terms are wrapped with `%` for ILIKE/LIKE queries without escaping literal `%` and `_` characters. An authenticated admin searching for `user_1` would match `usera1`, `userb1`, etc. because `_` is a single-character wildcard in SQL LIKE. Similarly, `%` in search input acts as a multi-character wildcard. This affects user search, group search, group member search, and domain binding lookups.
**Attack Scenario:** An authenticated admin enters a search term containing `%` or `_`. Instead of a literal match, SQL interprets these as wildcards, returning unintended results. The impact is limited to incorrect search results (no data exfiltration or privilege escalation) since all queries are parameterized and tenant-scoped.
**Evidence:**
```python
# In _build_search_clauses():
params[param_name] = f"%{token}%"  # token not escaped for LIKE wildcards
```
**Impact:** Incorrect search results. No data breach or privilege escalation (requires admin role, queries are parameterized and tenant-scoped).
**Remediation:** Escape `%` and `_` in search terms before wrapping with wildcards:
```python
def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

params[param_name] = f"%{escape_like(token)}%"
```

---

## [SECURITY] Response schemas missing max_length on group_assertion_scope

**Found in:** `app/schemas/settings.py:95`, `app/schemas/service_providers.py:93`
**Severity:** Low
**OWASP Category:** A05:2021 - Security Misconfiguration
**Description:** The `TenantSecuritySettings` and `SPConfig` response schemas declare `group_assertion_scope` as a bare `str` (or `str | None`) without `max_length`. The project standard requires all str fields to have `max_length`. The database CHECK constraint prevents invalid values, and these are response-only schemas, so the risk is minimal. Using `Literal` types (as the corresponding input schemas do) would be more consistent.
**Remediation:** Change response schema types to `Literal["all", "trunk", "access_relevant"]` to match input schemas, or add `max_length=50`.

---

