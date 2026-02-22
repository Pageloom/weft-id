# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 0 | |
| Low | 1 | Unbounded Input |

**Last security scan:** 2026-02-22 (7-day incremental, groups graph view, 1 new issue)
**Last compliance scan:** 2026-02-21 (all clear, scanner now cross-references migrations)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)

---

## [SECURITY] Unbounded Input: No payload size constraint on graph layout positions

**Found in:** `app/schemas/groups.py:355`, `db-init/migrations/0003_group_graph_layouts.sql:8`
**Severity:** Low
**OWASP Category:** Unbounded Input / Resource Exhaustion

**Description:** The `positions` field in `GroupGraphLayout` is an unconstrained `dict` with no maximum size validation. There is also no corresponding `CHECK` constraint on the `positions jsonb` column in the database.

**Attack Scenario:** An authenticated admin sends a large JSON payload to `PUT /api/v1/groups/graph/layout`. The server deserializes it into memory and stores it in JSONB without any size limit. On subsequent reads the full payload is fetched back. A sufficiently large payload (e.g., 1-10 MB) would cause excessive memory use on write and read cycles.

**Evidence:**
```python
# app/schemas/groups.py:355
positions: dict = Field(default_factory=dict, description="Node positions keyed by node ID")
# No max size, no key count limit, no value shape validation
```
```sql
-- db-init/migrations/0003_group_graph_layouts.sql:8
positions jsonb NOT NULL DEFAULT '{}'
-- No CHECK constraint on size (compare: node_ids has CHECK (length(...) <= 65535))
```

**Impact:** Admin-only resource exhaustion. Memory pressure on API server and database on reads. Low exploitability (requires admin session).

**Remediation:** Add a Pydantic model validator that limits the positions dict to a maximum number of keys (e.g., 10,000) and validates that each value is `{"x": float, "y": float}`. Optionally add a DB CHECK on `length(positions::text) <= 524288` (512 KB) consistent with the `node_ids` CHECK pattern.

---
