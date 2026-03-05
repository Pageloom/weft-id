# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 2 | Deprecation, Schema |
| Low | 0 | |

**Last security scan:** 2026-02-26 (targeted: CSRF on session-cookie API calls, 1 new issue)
**Last compliance scan:** 2026-02-21 (all clear, scanner now cross-references migrations)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)

---

## Starlette TemplateResponse Deprecated Call Signature

**Severity:** Medium
**Category:** Deprecation
**Found:** 2026-03-05

**Problem:**
All 90 `TemplateResponse` calls across 26 router files use the old Starlette signature `TemplateResponse(name, context)`. Starlette now expects `TemplateResponse(request, name, context)`. The old form still works but emits a `DeprecationWarning` and will break in a future Starlette release.

The warning is currently suppressed in `pytest.ini` to keep test output clean.

**Scope:**
- 90 call sites across 26 files in `app/routers/`
- Tests that mock `TemplateResponse` and assert on `call_args[0][0]` as the template name will also need updating (the template name moves to `call_args[0][1]`)

**Fix:**
1. Change all `templates.TemplateResponse("name.html", context)` to `templates.TemplateResponse(request, "name.html", context)`
2. Update all test assertions that check `mock_tmpl.call_args[0][0]` to check `call_args[0][1]` instead
3. Remove the `ignore:The \`name\` is not the first parameter anymore` filter from `pytest.ini`

**Effort:** S (mechanical find-and-replace, no logic changes)

---

## Audit schema.sql for Changes That Belong in Migrations Only

**Severity:** Medium
**Category:** Schema
**Found:** 2026-03-05

**Problem:**
`db-init/schema.sql` represents the initial database state before any migrations are applied. Schema changes should only go in migration files under `db-init/migrations/`. If a migration's changes were also added to `schema.sql`, a fresh database (which applies the baseline then runs all migrations) would either fail (duplicate column) or silently mask drift between the two sources of truth.

This needs an audit: compare each migration file against `schema.sql` to identify any columns, constraints, or tables that appear in both the baseline and a migration.

**Fix:**
1. For each migration in `db-init/migrations/`, check whether its changes (columns, constraints, indexes) also appear in `schema.sql`
2. Remove any duplicated changes from `schema.sql` so it reflects only the pre-migration state
3. Verify a clean `make db-init` (baseline + all migrations) still produces the correct schema

**Effort:** S (audit and remove duplicates)

