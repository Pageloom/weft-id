# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## High Severity

### LOG-002: Silent audit log loss from invalid actor_user_id

**Found in:** `app/services/service_providers/slo.py:98`, `app/jobs/inactivate_idle_users.py:130`
**Severity:** High
**Principle Violated:** Activity Logging
**Description:** Two call sites pass `actor_user_id="system"` (a plain string) instead of `SYSTEM_ACTOR_ID` (`"00000000-0000-0000-0000-000000000000"`). The `event_logs.actor_user_id` column is `UUID NOT NULL`, so `"system"` fails Postgres UUID validation. Because `log_event()` swallows exceptions, these audit events are silently discarded.
**Evidence:**
```python
# slo.py:98
actor_user_id="system",

# inactivate_idle_users.py:130
actor_user_id="system",  # System action (no real user)
```
**Impact:** SLO events (`slo_sp_initiated`) and auto-inactivation events (`user_auto_inactivated`) are never recorded in the audit log. This is a compliance gap for security-relevant operations.
**Root Cause:** The `SYSTEM_ACTOR_ID` constant was not imported/used in these newer modules. The correct pattern exists in `app/services/groups/idp.py`.
**Suggested fix:**
```python
# In both files, import and use the constant:
from app.services.event_log import SYSTEM_ACTOR_ID, log_event

# Replace actor_user_id="system" with:
actor_user_id=SYSTEM_ACTOR_ID,
```

---

## Medium Severity

### API-002: Group parent management missing from API

**Found in:** `app/routers/api/v1/groups.py`
**Severity:** Medium
**Principle Violated:** API-First
**Description:** The web UI exposes parent relationship management (add parent, remove parent) but the API only provides read access to parents and write access via the child direction.
**Evidence:**
```
Web UI:
  POST /{group_id}/parents/add          -> app/routers/groups/relationships.py:83
  POST /{group_id}/parents/{pid}/remove -> app/routers/groups/relationships.py:111

API:
  GET  /api/v1/groups/{group_id}/parents   (read only)
  POST /api/v1/groups/{group_id}/children  (add child - opposite direction)
  DELETE /api/v1/groups/{group_id}/children/{cid} (remove child)
```
**Impact:** API consumers cannot manage parent relationships from the child's perspective. They must know the parent group ID and use the children endpoint, which is a different mental model from the web UI.
**Root Cause:** Parent management endpoints were added to the web UI but not mirrored in the API layer.
**Suggested fix:** Add two API endpoints:
```python
# POST /api/v1/groups/{group_id}/parents
# DELETE /api/v1/groups/{group_id}/parents/{parent_group_id}
```

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | Activity Logging |
| Medium | 1 | API-First |
| Low | 0 | - |

**Last compliance scan:** 2026-02-14 (LOG-002 and API-002 found)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---
