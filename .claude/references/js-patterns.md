# JavaScript Patterns

## Target Standard: ES2020

All JavaScript in this project targets ES2020. This includes:

- `const` and `let` — never `var`
- Arrow functions for callbacks and anonymous functions
- Method shorthand in object literals (`{ method() {} }` not `{ method: function() {} }`)
- Template literals for string interpolation (`` `Hello ${name}` `` not `'Hello ' + name`)
- Destructuring assignments (`const { a, b } = obj`)
- Optional chaining (`?.`)
- Nullish coalescing (`??`)
- Default function parameters (`function foo(x = 0)`)
- `Array.includes()` instead of `indexOf() !== -1`

## Template Data Isolation

Server-rendered values must never appear directly in `<script>` bodies. Instead:

1. Place all server-side values in a `<script type="application/json">` block **before** the script tag:

```html
<script type="application/json" id="page-data">
{
  "tenantId": {{ user.tenant_id | string | tojson }},
  "sortField": {{ sort_field | tojson }},
  "pageSize": {{ pagination.page_size }},
  "search": {{ search | tojson if search else 'null' }}
}
</script>
```

2. Read the data at the top of the inline script:

```html
<script nonce="{{ csp_nonce }}">
const { tenantId, sortField, pageSize, search } = JSON.parse(
    document.getElementById('page-data').textContent
);
```

**Why**: Keeps script bodies free of Jinja2 `{{ }}` expressions, making them easier to
read, lint, and eventually extract to external files.

**Exceptions**:
- The `nonce` attribute itself (`nonce="{{ csp_nonce }}"`) must remain in the tag.
- Template block tags (`{% if %}`, `{% for %}`, `{% endif %}`) may still gate whether a
  script block renders, but values inside the script body must come from the page-data block.
- `<script type="application/json">` blocks do not need a nonce (they are not executed).

### Naming Convention

Use camelCase keys in page-data JSON blocks (e.g., `tenantId`, `sortField`). This matches
JS conventions and avoids the mismatch of `sort_field` in Python vs. JavaScript contexts.

### Multiple Page-Data Blocks

If a template extends a base and both need page-data, use distinct IDs
(e.g., `id="page-data"` and `id="page-data-graph"`). The base template's data should use
a base-specific ID.

## CSP Rules

This project uses CSP with nonces:

- No inline event handlers (`onclick`, `onsubmit`, `onchange`, etc.) — use `addEventListener`
- All `<script>` tags that execute JS must have `nonce="{{ csp_nonce }}"`
- External script `<script src="...">` tags also need the nonce attribute
- `<script type="application/json">` blocks are data-only and do **not** need a nonce

**Symptoms of a CSP violation**: Buttons don't work, modals don't open, no console errors.

## WeftUtils

Common UI patterns are in `WeftUtils` (`static/js/utils.js`). Check before writing custom JS:

- `WeftUtils.confirm(msg, callback, options)` — confirmation modal (replaces `window.confirm`)
- `WeftUtils.showModal(id)` / `WeftUtils.hideModal(id)` — modal open/close
- `WeftUtils.copyToClipboard(text, el)` — clipboard copy with visual feedback
- `WeftUtils.stickyActionBar(id)` — sticky bulk-action bar (sticks to bottom when scrolled out of view)
- `WeftUtils.detectTimezone()` / `WeftUtils.detectLocale()` — locale detection
- `WeftUtils.apiFetch(url, options)` — `fetch()` wrapper with CSRF token injection

**Always use `WeftUtils.apiFetch()`** for state-changing API calls (POST/PUT/PATCH/DELETE).
Bare `fetch()` without the CSRF header will fail with 403 on session-cookie-authenticated
endpoints. Bearer-token clients are unaffected (they handle CSRF differently).

## Examples

### Converting ES5 to ES2020

```javascript
// Before (ES5)
var result = [];
items.forEach(function(item) {
    if (item.active) {
        result.push(item.name + ' (' + item.id + ')');
    }
});

// After (ES2020)
const result = items
    .filter(item => item.active)
    .map(item => `${item.name} (${item.id})`);
```

### State-Changing API Call

```javascript
// Correct: use WeftUtils.apiFetch
WeftUtils.apiFetch('/api/v1/groups/' + groupId + '/members', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_ids: selectedIds }),
}).then(resp => {
    if (resp.ok) window.location.reload();
});

// Wrong: bare fetch() will fail with 403
fetch('/api/v1/groups/...', { method: 'DELETE', credentials: 'same-origin' });
```
