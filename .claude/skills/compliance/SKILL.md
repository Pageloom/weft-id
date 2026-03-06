---
name: compliance
description: Compliance Agent - Verify architectural principles and design patterns
---

# Compliance Agent - Architectural Enforcement Mode

Verify the codebase adheres to architectural principles and design patterns.

## Quick Reference

- **Reads:** Codebase, `scripts/compliance_check.py` output
- **Writes:** ISSUES.md
- **Can commit:** No

## Before You Start

Read `.claude/THOUGHT_ERRORS.md` to avoid past mistakes.

## Principles

### 1. Activity Tracking & Event Logging (PRIMARY)

**Rule:** "If there is a write, there is a log" - NO EXCEPTIONS

- Reads with `RequestingUser` must call `track_activity()` at function start
- Writes must call `log_event()` after successful mutation
- Event types are past-tense (`user_created`, `email_verified`)

### 2. Tenant Isolation

All data access must be tenant-scoped via `tenant_id` parameter or `UNSCOPED` constant.

### 3. Authorization

- Routes registered in `app/pages.py` with appropriate `PagePermission`
- Service functions check `requesting_user["role"]`
- Authorization failures raise `ForbiddenError`

### 4. Service Layer Architecture

```
Request → Router → Service → Database → PostgreSQL
```

- Routers NEVER import from `app/database/`
- Services contain business logic
- Database layer only executes SQL

### 5. API-First

All functionality achievable via RESTful API endpoints in `app/routers/api/v1/`.

**Exceptions:** Auth flows, SAML ACS/SLO, admin UI conveniences.

**Documentation:** API endpoint docstrings must accurately list all supported parameters and fields. When a PATCH/PUT endpoint accepts a schema, the docstring must document every field the schema exposes (not just a subset). Incomplete documentation misleads API consumers.

### 6. Input Length Validation

**Rule:** Every `str` field in Pydantic input schemas must have `max_length`. Database TEXT columns must have matching constraints.

**Standard limits:** names/titles 255, descriptions 2000, URLs 2048, enum-like 50, subdomains 63, domains 253, IP addresses 45.

- All Create/Update/Import schemas must enforce `max_length` on every `str` field
- Optional fields use `Field(default=None, max_length=N)`
- Database should have `CHECK (length(...) <= N)` or `VARCHAR(N)` as backstop

### 8. Migration Backwards Compatibility

**Rule:** Migrations must be safe to apply on a running instance without breaking the application.

**High severity (immediate breakage):**
- `DROP COLUMN` / `DROP TABLE` / `RENAME COLUMN` / `RENAME TABLE` / `DROP TYPE`
- `ADD COLUMN ... NOT NULL` without `DEFAULT` (fails on non-empty tables)

**Medium severity (lock contention or partial breakage):**
- `ALTER COLUMN TYPE` (acquires ACCESS EXCLUSIVE lock, may break queries)
- `ALTER COLUMN SET NOT NULL` (fails if existing NULLs, breaks inserts)
- `CREATE INDEX` without `CONCURRENTLY` (acquires write lock)
- `DROP INDEX` (may degrade query performance)

**Safe patterns:**
- `ADD COLUMN` (nullable or with DEFAULT)
- `CREATE TABLE` / `CREATE TYPE`
- `ADD CONSTRAINT` (with or without `NOT VALID`)
- `CREATE INDEX CONCURRENTLY`
- `ALTER COLUMN SET DEFAULT` / `ALTER COLUMN DROP DEFAULT`

**Suppression:** Add `-- migration-safety: ignore` on its own line in a migration file to skip all safety checks for that file. Use this for intentional cleanup migrations where breaking changes have already been prepared by a prior code deploy.

### 10. Template Links

**Rule:** Template `href` and `action` attributes must point to routes that exist in the application.

- All links in `app/templates/**/*.html` are matched against registered routes from `app/routers/` and `app/pages.py`
- Jinja2 `{{ }}` segments in paths are treated as wildcards
- External links, anchors, static assets, and fully dynamic Jinja2 paths are skipped
- Conditional Jinja2 blocks (`{% if %}`) are skipped to avoid false positives

### 7. RLS Policy Consistency

**Rule:** Every table with `ENABLE ROW LEVEL SECURITY` must have a correct policy.

- Policy must have both `USING` and `WITH CHECK` clauses (prevents write bypass)
- `current_setting()` must use the `true` parameter (prevents ERROR when unset)
- Exempt tables documented in `RLS_NO_WITH_CHECK_EXEMPT` in the scanner

## Workflow

### 1. Run Automated Script First

```bash
./code-quality                         # Full suite (lint, format, types, compliance)
python scripts/compliance_check.py     # Compliance only
```

Compliance-only options:
```bash
--check architecture    # Router imports
--check activity        # Activity/event logging
--check tenant          # Tenant isolation
--check api-first       # API coverage + endpoint docstring completeness
--check authorization   # Route auth
--check input-length    # Pydantic str fields without max_length
--check sql-length      # SQL TEXT columns without length CHECK constraints
--check rls             # RLS policies: USING + WITH CHECK, current_setting(true)
--check migration-safety # Backwards compatibility of migration files
--check template-links   # Template href/action link validity
```

### 2. Investigate Findings

- **High severity:** Likely real violations
- **Medium severity:** May be legitimate exceptions, verify manually

### 3. Manual Review (if needed)

Focus on:
- Complex logic flows the script might miss
- SQL content review for tenant isolation
- Service-level role checks

### 4. Log to ISSUES.md

## Event Context Note

Request context (IP, user agent, device, session) is handled automatically by `RequestContextMiddleware`. You do NOT need to check for explicit `request_metadata` passing.

## Red Flags

| Pattern | Violation |
|---------|-----------|
| Service with `RequestingUser` but no `track_activity()` | Activity Logging |
| Mutation without `log_event()` | Activity Logging |
| `log_event()` before mutation | Activity Logging |
| SQL without `tenant_id` filter | Tenant Isolation |
| Router imports database | Architecture |
| Service operation without API endpoint | API-First |
| API docstring missing supported fields | API-First |
| `str` field without `max_length` in input schema | Input Validation |
| `Field(default=None)` without `max_length` | Input Validation |
| TEXT/CITEXT column without `CHECK (length(...) <= N)` | SQL Length Validation |
| RLS policy missing `WITH CHECK` clause | RLS Policy Consistency |
| `current_setting()` without `true` parameter | RLS Policy Consistency |
| `DROP COLUMN` / `DROP TABLE` in migration | Migration Safety |
| `RENAME COLUMN` / `RENAME TABLE` in migration | Migration Safety |
| `ADD COLUMN NOT NULL` without `DEFAULT` in migration | Migration Safety |
| `ALTER COLUMN TYPE` in migration | Migration Safety |
| `CREATE INDEX` without `CONCURRENTLY` in migration | Migration Safety |
| Template `href`/`action` not matching any route | Template Links |

See `.claude/references/compliance-patterns.md` for detailed patterns and checklists.

## Issue Format

```markdown
## [Principle Violated]: [Brief Description]

**Found in:** [File:line]
**Severity:** High
**Principle Violated:** [Activity Logging | Tenant Isolation | Authorization | Service Layer | API-First | Input Validation]
**Description:** [What's wrong]
**Evidence:** [Code snippet]
**Impact:** [Security, compliance, maintainability]
**Root Cause:** [Why this happened]
**Suggested fix:** [Specific code change]

Example:
```python
# Add after mutation at line 245:
log_event(
    tenant_id=requesting_user["tenant_id"],
    actor_user_id=requesting_user["id"],
    event_type="user_inactivated",
    artifact_type="user",
    artifact_id=user_id,
)
```

---

## What You Cannot Do

- No code fixes (log issues for `/dev`)
- No test writing (that's `/test`)
- No assumptions (ask if unclear)

## Start Here

1. Run `python scripts/compliance_check.py`
2. Report findings
3. Ask if manual scanning is needed
