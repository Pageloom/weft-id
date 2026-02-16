# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | Compliance |
| Medium | 1 | Compliance |
| Low | 0 | - |

**Last compliance scan:** 2026-02-16 (ARCH-001, LOG-003 found)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---

## ARCH-001: Router imports directly from database layer [HIGH]

**Found:** 2026-02-16 | **Source:** compliance_check.py

`app/routers/dev.py:8` imports `from database.users.core import get_user_by_email`, bypassing the service layer.

**Fix:** Route the call through an existing service function or create one. Routers must never import from `app/database/` directly.

---

## LOG-003: Missing track_activity in branding service [MEDIUM]

**Found:** 2026-02-16 | **Source:** compliance_check.py

`app/services/branding.py:458` function `randomize_mandala` accepts `RequestingUser` but does not call `track_activity()`.

**Fix:** Add `track_activity(requesting_user['tenant_id'], requesting_user['id'])` at function start.

---
