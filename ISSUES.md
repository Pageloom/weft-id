# Issues

This file tracks quality issues found by the tester agent. The goal is to keep this file empty.

For resolved issues, see [ISSUES_ARCHIVE.md](ISSUES_ARCHIVE.md).

---

# Summary

| Severity | Count | Categories |
|----------|-------|------------|
| High | 0 | |
| Medium | 0 | |
| Low | 2 | Unbounded Input, Pagination |

**Last security scan:** 2026-02-26 (targeted: CSRF on session-cookie API calls, 1 new issue)
**Last compliance scan:** 2026-02-21 (all clear, scanner now cross-references migrations)
**Last dependency audit:** 2026-02-23 (all clear; werkzeug upgraded to 3.1.6, pip upgraded to 26.0.1)
**Last refactor scan:** 2026-02-27 (deep scan of new branding code, 3 new issues; crud.py, branding double-read, _make_png duplication resolved 2026-02-27)
**Last router refactor:** 2026-02-06 (all 4 large routers split into packages)
**Last service refactor:** 2026-02-13 (service_providers.py split into package)
**Last test code audit:** 2026-02-21 (database integration test gap analysis, 6 issues logged)

---

## [BUG] Pagination: Page size selector missing on groups list; users list size change unreliable

**Found in:** `app/templates/groups_list.html`, `app/templates/users_list.html`
**Severity:** Low
**Description:** Two related but distinct pagination issues affect list views.

### Issue 1 — Groups list has no page size selector

`groups_list.html` renders prev/next pagination controls and the router (`app/routers/groups/listing.py:48`) accepts a `size` query parameter, but the template exposes no UI control to change the page size. Pagination links also don't carry the `size` parameter (`groups_list.html:279,285`), so the value resets to the server default (25) on every page turn.

**Evidence:**
```python
# app/routers/groups/listing.py:48
size: Annotated[int, Query(ge=10, le=100)] = 25,  # accepted but never surfaced in UI
```
```html
<!-- groups_list.html:279,285 — no &size= in links -->
<a href="?page={{ pagination.page - 1 }}&view={{ view }}{% if search %}&search={{ search }}{% endif %}">
```
No `<select id="page-size">` exists anywhere in `groups_list.html`.

### Issue 2 — Users list page size change is unreliable when saved filters are present

`users_list.html` has a localStorage restore block (lines 307–346) that runs on every page load. It checks `needsSizeRestore` (size not in URL and saved size differs from default 25) and `needsFilterRestore` (saved filters not reflected in URL) and, if either is true, immediately redirects.

The bug: when the user changes the page size, the `change` handler (line 349) saves the new size to localStorage and navigates to a URL that includes `?size=<new>`. On that page load the URL has `size`, so `needsSizeRestore` is false. However, if `needsFilterRestore` is also true (saved filters), the restore block fires and redirects to `/users/list?page=1&size=<effectivePageSize>...`. `effectivePageSize` at that point is read from localStorage — which was just updated to the new value by the `change` handler, so it should be consistent. But there is a race: if the page is slow or a previous session left a stale size in localStorage from a different browser tab, `effectivePageSize` can diverge from what the user just picked, and the redirect lands on a different page size than selected.

Additionally, the restore redirect hardcodes the base path as `/users/list` (line 334) rather than using a relative URL, which is fragile if the route ever changes.

**Evidence:**
```javascript
// users_list.html:307–346 — restore block runs before change listener is attached
let effectivePageSize = '{{ pagination.page_size }}';
const savedSize = localStorage.getItem(PAGE_SIZE_KEY);  // may be stale from another tab
if (savedSize && ...) effectivePageSize = savedSize;
const needsSizeRestore = !urlParams.has('size') && effectivePageSize !== '25';
if (needsSizeRestore || needsFilterRestore) {
    let url = '/users/list?page=1&size=' + effectivePageSize + ...;  // hardcoded path
    window.location.href = url;  // second redirect that can override the user's choice
}
```

**Impact:** Users on the groups list cannot change how many groups are shown per page. Users on the users list may find their selected page size ignored when active filters are saved in localStorage.

**Suggested fix:**
- Groups list: add a `<select id="page-size">` matching the pattern in `users_list.html`, and include `&size={{ pagination.page_size }}` in the prev/next pagination links.
- Users list: The restore block should only fire when there is no `size` param in the URL AND no filter params in the URL. It should not redirect when the current URL already reflects the user's explicit choices. Consider combining size and filter restoration into a single, unconditional redirect only on a "bare" visit (no query params at all).

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

