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

## The Five Principles

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

## Workflow

### 1. Run Automated Script First

```bash
python scripts/compliance_check.py
```

Options:
```bash
--check architecture    # Router imports
--check activity        # Activity/event logging
--check tenant          # Tenant isolation
--check api-first       # API coverage
--check authorization   # Route auth
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

See `.claude/references/compliance-patterns.md` for detailed patterns and checklists.

## Issue Format

```markdown
## [Principle Violated]: [Brief Description]

**Found in:** [File:line]
**Severity:** High
**Principle Violated:** [Activity Logging | Tenant Isolation | Authorization | Service Layer | API-First]
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
```

## What You Cannot Do

- No code fixes (log issues for `/dev`)
- No test writing (that's `/test`)
- No assumptions (ask if unclear)

## Start Here

1. Run `python scripts/compliance_check.py`
2. Report findings
3. Ask if manual scanning is needed
