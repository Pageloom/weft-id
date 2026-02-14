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

## Medium Severity

### SEC-001: Uploaded SVG content is not sanitized

**Found in:** `app/services/branding.py`
**Severity:** Medium
**Principle Violated:** Security (input validation)
**Description:** SVG uploads are validated for dimensions (square viewBox) and size (256 KB) but the XML content is stored and served without sanitization. SVG files can contain `<script>` tags, event handlers (`onload`, `onerror`), external resource references (`<image href="http://...">`), and XXE entity declarations. The raw SVG is served at `/branding/logo/{slot}` with `Content-Type: image/svg+xml`.
**Mitigating factors:**
- Upload requires admin role
- Logos are rendered via `<img>` tags in templates, which blocks script execution in modern browsers
- Direct navigation to the logo URL would allow script execution, but requires knowing the tenant hostname
**Impact:** An admin could upload a malicious SVG that executes JavaScript when the logo URL is visited directly (not via `<img>` tag). Risk is limited by the admin-only upload requirement.
**Suggested fix:** Sanitize SVG content on upload using an XML allowlist approach. Parse the SVG, strip all elements and attributes not on a whitelist of safe drawing primitives (path, circle, rect, line, polygon, g, defs, fill, stroke, viewBox, etc.). Reject SVGs containing `<script>`, event handler attributes, or external references.

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 1 | Activity Logging |
| Medium | 2 | API-First, Security |
| Low | 0 | - |

**Last compliance scan:** 2026-02-14 (LOG-002 and API-002 found)
**Last dependency audit:** 2026-02-06 (pip CVE-2026-1703 accepted as low priority dev tool risk)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-07 (parametrization applied to duplicated test patterns)

---
