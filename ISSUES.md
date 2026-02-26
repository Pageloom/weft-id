# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 1 | CSRF |
| Low | 1 | Unbounded Input |

**Last security scan:** 2026-02-26 (targeted: CSRF on session-cookie API calls, 1 new issue)
**Last compliance scan:** 2026-02-21 (all clear, scanner now cross-references migrations)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-12 (standard full scan, 4 prior items resolved, 2 new)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)

---

## [SECURITY] CSRF: Session-cookie API calls lack CSRF validation

**Found in:** `app/middleware/csrf.py:24-25`, `app/api_dependencies.py:78-85`
**Severity:** Medium
**OWASP Category:** A01:2021 - Broken Access Control / CSRF

**Description:** The CSRF middleware blanket-exempts all `/api/*` paths under the assumption that API routes use Bearer token authentication only. However, `get_current_user_api` now also accepts session cookie authentication as a fallback. The frontend JavaScript makes state-changing API requests with `credentials: 'same-origin'` but without any `X-CSRF-Token` header, meaning session-cookie-authenticated API calls have no CSRF protection at the application layer.

The comment in `csrf.py` reflects the original design intent ("API routes use Bearer token authentication"), but that assumption no longer holds.

**Attack Scenario:** A victim with an active session visits an attacker-controlled page on the same site or registrable domain. The malicious page makes a `fetch()` call to (for example) `DELETE /api/v1/groups/{id}/parents/{parentId}` or `POST /api/v1/groups/{childId}/parents`. Because `SameSite=lax` (Starlette default) does not block same-site subresource requests, and because the API exemption bypasses all token validation, the request succeeds with the victim's session cookie.

The primary risk vectors are:
1. Any XSS on the same hostname allows same-origin API mutation with no CSRF barrier.
2. If the app is deployed on a shared base domain (e.g., multiple tenants under `.company.com`) and cookies are ever broadened to the parent domain, cross-tenant CSRF becomes possible.
3. Users on legacy browsers without `SameSite` support (IE11, pre-2020 browsers) are fully vulnerable to cross-origin CSRF.

**Evidence:**

```python
# app/middleware/csrf.py:24-25 — blanket API exemption
CSRF_EXEMPT_PATHS = [
    "/api/",  # All API routes — comment says "Bearer only" but session cookie auth is now also supported
    ...
]
```

```python
# app/api_dependencies.py:78-85 — session cookie accepted without CSRF check
# Fall back to session cookie
user = auth.get_current_user(request, tenant_id)
if user:
    return user
```

```javascript
// app/templates/groups_list.html:1154-1156 — DELETE with no CSRF header
fetch('/api/v1/groups/' + childId + '/parents/' + parentId, {
  method: 'DELETE',
  credentials: 'same-origin'   // no X-CSRF-Token
})

// app/templates/groups_list.html:1197-1201 — POST with no CSRF header
fetch('/api/v1/groups/' + childId + '/parents', {
  method: 'POST',
  credentials: 'same-origin',
  headers: {'Content-Type': 'application/json'},  // no X-CSRF-Token
  body: JSON.stringify({parent_group_id: parentId})
})

// app/templates/settings_branding_global.html:243-246, 269-273 — POST with no CSRF header
fetch('/api/v1/branding/mandala/randomize', { method: 'POST', credentials: 'same-origin' })
fetch('/api/v1/branding/mandala/save', { method: 'POST', credentials: 'same-origin', ... })
```

**Impact:** An attacker can forge state-changing API requests (create/delete group relationships, modify branding, save graph layouts, etc.) on behalf of any authenticated user who visits a malicious page. Impact scales with the victim's role — admin can affect tenant-wide data.

**Remediation:**

1. **Expose the CSRF token in `base.html`** via a meta tag so JavaScript can read it:
   ```html
   <meta name="csrf-token" content="{{ csrf_token() }}">
   ```

2. **Add a `WeftUtils.apiFetch(url, options)` helper** in `static/js/utils.js` that automatically reads the meta tag and injects `X-CSRF-Token` into the request headers for any non-GET method. This becomes the standard way to call the API from templates, replacing bare `fetch()`.

3. **Validate the CSRF token in `api_dependencies.py`** when the request is authenticated via session cookie (not Bearer token). For non-GET methods, compare `request.headers.get("X-CSRF-Token")` against `request.session.get("_csrf_token")` using `secrets.compare_digest`. Raise HTTP 403 if missing or invalid.

4. **Update all existing frontend `fetch()` calls** that use session cookie auth to use `WeftUtils.apiFetch()` instead:
   - `app/templates/groups_list.html` (lines 457, 1154, 1197)
   - `app/templates/settings_branding_global.html` (lines 243, 269)

5. **Update documentation and skills** to prevent regression:
   - `CLAUDE.md`: Add a "CSRF Tokens for API Fetch Calls" subsection under the WeftUtils section explaining `WeftUtils.apiFetch()` and add a Best Practices item (#12) that state-changing `fetch()` calls must use `WeftUtils.apiFetch()`.
   - `.claude/references/owasp-patterns.md`: Expand CSRF section (#7) with the app-specific pattern (meta tag, `api_dependencies.py` check, `WeftUtils.apiFetch()`).
   - `.claude/skills/security/SKILL.md`: Add a CSRF checklist item — "Frontend fetch() calls to state-changing API endpoints include X-CSRF-Token header; bare fetch() with credentials is a red flag."
   - `.claude/skills/dev/SKILL.md`: Add a note that bare `fetch()` calls to state-changing API endpoints are a violation — use `WeftUtils.apiFetch()`.

Bearer-token-authenticated API clients (OAuth2, integrations) are unaffected — the CSRF check applies only on the session-cookie code path.

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
