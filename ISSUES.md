# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | - |
| Medium | 5 | Activity tracking (4), SQL column length (1) |
| Low | 0 | - |

**Last compliance scan:** 2026-02-21 (rglob fix revealed 4 track_activity gaps, SQL length checker added)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## Activity Logging: Missing track_activity() in 4 read functions

**Found in:** `app/services/service_providers/crud.py:972`, `app/services/service_providers/crud.py:1072`, `app/services/service_providers/group_assignments.py:27`, `app/services/saml/idp_sp_certificates.py:80`
**Severity:** Medium
**Principle Violated:** Activity Logging
**Description:** Four read-only service functions with `RequestingUser` parameter do not call `track_activity()` at the start. These functions are: `preview_sp_metadata_refresh`, `preview_sp_metadata_reimport`, `count_sp_group_assignments`, `get_idp_sp_certificate_for_display`.
**Impact:** User activity is not tracked for these operations, which means read activity on SP metadata previews, group assignment counts, and IdP SP certificate views is invisible to audit.
**Suggested fix:** Add `track_activity(requesting_user["tenant_id"], requesting_user["id"])` after the authorization check in each function.

---

## SQL Column Length: user_emails.email missing CHECK constraint

**Found in:** `db-init/schema.sql:183`
**Severity:** Medium
**Principle Violated:** Input Length Validation (SQL)
**Description:** The `email` column in `user_emails` (type `citext`) has no `CHECK (length(email) <= N)` constraint. The application validates email length via Pydantic `EmailStr` with `max_length=320`, but there is no database-level backstop.
**Impact:** If application validation is bypassed (e.g., direct database insert, future code change), arbitrarily long values could be stored.
**Suggested fix:** Add migration: `ALTER TABLE user_emails ADD CONSTRAINT chk_user_emails_email_length CHECK ((length(email) <= 320));`

---
