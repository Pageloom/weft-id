# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

## OAuth2 Authorization Page Crashes Due to Missing nav Context

**Found in:** `app/routers/oauth2.py:92-103`

**Severity:** High

**Description:** The OAuth2 authorization page (`GET /oauth2/authorize`) crashes with a Jinja2 `UndefinedError` when accessed by an authenticated user. The template extends `base.html` which expects a `nav` context variable, but the router doesn't provide it.

**Evidence:**
- Router at `app/routers/oauth2.py:92-103` returns `TemplateResponse` with `user` but no `nav`
- Template at `app/templates/oauth2_authorize.html:1` extends `base.html`
- `base.html:25` iterates over `nav.top_level_items` when `user` is present
- Error: `jinja2.exceptions.UndefinedError: 'nav' is undefined`

**Impact:**
- OAuth2 authorization code flow is completely broken for the web UI
- Users cannot authorize third-party applications
- Any authenticated user visiting `/oauth2/authorize` will see a 500 error

**Root Cause:** The OAuth2 router passes `user` to the template context (triggering the nav bar to render) but doesn't provide the `nav` context that `base.html` requires.

**Suggested fix:** Add navigation context to the template response using the same pattern as other authenticated pages. Looking at how other routers handle this:

```python
from pages import get_nav_context

return templates.TemplateResponse(
    "oauth2_authorize.html",
    {
        "request": request,
        "client": client,
        "user": user,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "nav": get_nav_context(user, request.url.path),  # Add this
    },
)
```

**Files to Modify:**
- `app/routers/oauth2.py` - Add `nav` context to both authorize_page (line 92) and error responses

---

## OAuth2 Error Page Also Missing nav Context

**Found in:** `app/routers/oauth2.py:49-56, 60-67, 71-78, 82-89, 144-151`

**Severity:** High

**Description:** All error template responses in the OAuth2 router are missing the `nav` context. While these don't crash currently (because they don't pass `user`), they should be fixed for consistency and to handle cases where we might want to show user context.

**Evidence:**
- Multiple `TemplateResponse` calls to `oauth2_error.html` without `nav` context
- Template extends `base.html` which conditionally renders nav

**Impact:**
- Inconsistent template context patterns
- Potential future crashes if `user` is added to error pages

**Suggested fix:** Either:
1. Add `nav` context to error responses (consistent pattern)
2. Create a minimal base template for OAuth2 flows that doesn't require nav

**Files to Modify:**
- `app/routers/oauth2.py` - Add `nav` context to all TemplateResponse calls

---

## Invalid artifact_id in delete_jobs Event Logging

**Found in:** `app/services/bg_tasks.py:173`

**Severity:** Medium

**Description:** The `delete_jobs` function logs an event with `artifact_id="bulk_delete"`, but the `event_logs.artifact_id` column is a UUID NOT NULL field. This causes the event logging to silently fail with error: `invalid input syntax for type uuid: "bulk_delete"`.

**Evidence:**
- Schema at `db-init/00011_event_log.sql:29`: `artifact_id UUID NOT NULL`
- Service code at `app/services/bg_tasks.py:173`: `artifact_id="bulk_delete"`
- Test error: `ERROR services.event_log:event_log.py:108 Failed to log event: invalid input syntax for type uuid: "bulk_delete"`

**Impact:**
- Bulk job deletions are NOT logged to the audit trail
- Violates "if there is a write, there is a log" principle
- Silent failure - no exception raised to caller

**Root Cause:** The `artifact_id` parameter accepts a string but expects a valid UUID. For bulk operations, the code incorrectly uses a descriptive string instead of a UUID.

**Suggested fix:** Use one of the job IDs as the artifact_id (e.g., the first one), or use a sentinel UUID for bulk operations. Options:

1. **Use first job ID as artifact_id** (recommended):
   ```python
   artifact_id=job_ids[0] if job_ids else None,
   ```
   Skip logging if no jobs deleted.

2. **Use sentinel UUID** for bulk operations:
   Define a `BULK_DELETE_ARTIFACT_ID` constant UUID and use it consistently.

**Files to Modify:**
- `app/services/bg_tasks.py` - Fix artifact_id parameter

---

