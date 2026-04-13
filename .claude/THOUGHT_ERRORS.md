# Thought Errors

This file documents common mistakes Claude makes in this project. Review this before starting work to avoid repeating them. Entries should be reviewed every session; add new mistakes at the end.

## Adding New Thought Errors

When you make a mistake that causes wasted effort or confusion, add it here:

1. Describe what you did wrong
2. Describe what you should have done
3. Add any relevant context

This helps prevent the same mistakes in future sessions.

---

## Running Tests

**Wrong:** `pytest` or `poetry run pytest` (script not found)
**Right:** `poetry run python -m pytest` or use `./test` shorthand script

Tests must be run via poetry to use the correct virtual environment. The pytest executable is not created by Poetry, so we must invoke it as a Python module.

## Running Code Quality Checks

**Wrong:** `ruff check` directly, or assuming pyright is available
**Right:** `make check` (or `make fix` to auto-fix lint/format)

This runs lint (ruff), format check (ruff), type check (mypy), and compliance check in one go. It matches the CI workflow exactly. Individual tools can still be run via poetry (e.g. `poetry run ruff check`, `poetry run mypy app/`), but the script is the standard way.

## Test Environment

The test environment sets `IS_DEV=true` in `tests/conftest.py`. This is required because production validation would otherwise fail with default secret values.

---

## Test Assertions with UUIDs

**Wrong:** `assert call_kwargs["artifact_id"] == test_user["id"]`
**Right:** `assert call_kwargs["artifact_id"] == str(test_user["id"])`

Test fixtures often use UUID objects while function parameters are strings. Always convert to string when comparing IDs across boundaries.

---

## Mocking TestClient Sessions

**Wrong:** `with patch.object(client, "cookies", {...})` - fails because cookies is a read-only property
**Right:** `with patch("starlette.requests.Request.session", {...})`

Mock at the request level, not the client level.

---

## Router Database Imports

**Wrong:** Adding `import database` to routers for quick lookups
**Right:** Add a service layer function that wraps the database call

Project architecture: "Routers: HTTP/template layer only. Never import database modules directly."

---

## Restarting Containers After Code Changes

**Wrong:** `make restart-app` when changing background job code
**Right:** Restart the worker container for changes to `app/jobs/`

Background jobs run in a separate worker container. Changes to job handlers require restarting the worker container, not the app container.

---

## Running pip-audit

**Wrong:** `poetry run pip-audit` (command not found)
**Right:** `poetry run python -m pip_audit`

Like pytest, pip-audit must be run as a Python module. The script entry point isn't created by poetry.

---

## Dependency Security Scanning: Primary vs Fallback Path

**Primary path (pip-audit):** `dev/deps_check.py` runs pip-audit against the full venv, catching both direct and transitive dependencies. This is the normal case.

**Fallback path (OSV API):** If pip-audit fails, the script falls back to scanning only direct dependencies from pyproject.toml and will miss transitive vulnerabilities.

**Diagnostic:** The "Packages scanned" count in the report reflects direct deps only regardless of which path ran. If it seems low, run `poetry run python -m pip_audit --progress-spinner off` to verify pip-audit is working.

---

## CSP Blocks Inline Event Handlers

**Wrong:** Adding `onclick="doSomething()"` or `onclick="window.location='...'"` to HTML elements
**Right:** Use `<a href="...">` for navigation, or attach event listeners from `<script nonce="{{ csp_nonce }}">` blocks

This project uses CSP with nonces. Only script blocks with the correct nonce execute. Inline event handlers (`onclick`, `onsubmit`, `onchange`, etc.) are silently blocked and fail without error messages.

**Symptoms:** Buttons don't work, modals don't open, clickable rows don't navigate, but no console errors appear.

**Audit command:** `grep -r "onclick=\|onsubmit=\|onchange=" app/templates/`

---

## Section Pages Need Redirect Routes

**Wrong:** Adding a section page to `pages.py` without a corresponding route
**Right:** Add both the page definition AND a redirect route (e.g., `/admin/audit/` redirects to `/admin/audit/events`)

Section pages (containers for sub-pages) don't have their own content. They need redirect routes that call `get_first_accessible_child()` to navigate to their first accessible child page.

---

## DAG vs Tree Model Confusion

**Wrong:** Assuming that groups sharing a common ancestor cannot become parent-child (tree model thinking)
**Right:** In a DAG, only true cycles are prevented (A cannot be both ancestor AND descendant of B)

A DAG allows multiple paths to the same node. If groups A and B are both children of C, A can still become a child of B. The only constraint is that no group can be both above and below another in the hierarchy.

**Cycle detection query:** `SELECT 1 FROM group_lineage WHERE ancestor_id = :child_id AND descendant_id = :parent_id`

---

## Closure Table Maintenance Must Be Transactional

**Wrong:** Updating `group_relationships` and `group_lineage` in separate database calls
**Right:** Always update both tables within a single transaction using `session()` context manager

The closure table (`group_lineage`) must stay in sync with direct relationships (`group_relationships`). If one update succeeds and the other fails, the data becomes inconsistent and cycle detection breaks.

```python
with session(tenant_id=tenant_id) as cur:
    cur.execute(...)  # Update relationships
    cur.execute(...)  # Update lineage
    # Both commit together or both roll back
```

---

## Closure Table Self-References

**Wrong:** Forgetting to insert self-referential rows when creating new nodes
**Right:** Every group must have a `(group_id, group_id, 0)` row in the lineage table

The closure table pattern requires self-references for transitive path calculations to work. When adding a relationship `parent → child`, the SQL joins on these self-references to build all transitive paths.

---

## Compound Strings in UUID Columns Fail Silently

**Wrong:** `artifact_id=f"{group_id}:{user_id}"` in `log_event()` calls
**Right:** `artifact_id=group_id` with the second ID in `metadata`

The `event_logs.artifact_id` column is `UUID NOT NULL`. A colon-separated compound string fails Postgres UUID validation, so the INSERT is silently rejected and the audit event is never recorded. No error is raised because `log_event()` swallows exceptions to avoid disrupting the main operation.

When logging events for operations involving two entities (membership, relationships), use one UUID as `artifact_id` and put the other in `metadata`. The existing `bulk_add_members()` function shows the correct pattern.

---

## Database Name Confusion

**Wrong:** Assuming the database is named `weftid` or `weft_id`
**Right:** The database name is `appdb`

This catches agents that guess the DB name from the project name. Always use `appdb`.

---

## The `appowner` Role Cannot Log In

**Wrong:** Connecting to Postgres as `appowner` to run migrations or queries
**Right:** Connect as `postgres` superuser. Migrations use `SET LOCAL ROLE appowner` internally for DDL ownership.

The `appowner` role exists for object ownership but has `NOLOGIN`. Direct connections as `appowner` will fail with an authentication error.

---

## Running Database Migrations Without Full Reset

**Wrong:** `make db-reset` (destroys all data), or manually running SQL files with `psql`
**Right:** `make migrate` (applies any pending migrations from `db-init/migrations/`)

The migration runner (`db-init/migrate.py`) handles transaction management, error logging, and idempotent reruns. In dev, migrations also run automatically on `make up`.

---

## Importing from Private Modules

**Wrong:** `from database._core import UNSCOPED, fetchall` (importing from an underscore-prefixed private module)
**Right:** `from database import UNSCOPED, fetchall` (importing from the public package)

Do not import from private (`_`-prefixed) modules. Instead, import from the parent package that re-exports those symbols. For example, `database.__init__` re-exports `UNSCOPED`, `fetchall`, `fetchone`, `execute`, and `session` from `database._core`.

**Exception:** Modules *inside* the `database/` package itself must import from `_core` directly (e.g., `from ._core import ...` or `from database._core import ...`) because the package `__init__` has not finished loading when submodules are first imported.

---

## Tailwind CSS: New Classes Don't Appear Without Rebuild

**Wrong:** Adding a new Tailwind utility class to a template and expecting it to work immediately.
**Right:** Run `make build-css` after adding any Tailwind class that wasn't already in the codebase.

Tailwind generates CSS only for classes it finds during a build scan. If you add `text-rose-600` to a template but it wasn't previously used anywhere, the class won't exist in `static/css/output.css` until you rebuild. The browser renders nothing with no error.

**Use `make watch-css`** during active template development to auto-rebuild on every save.

---

## Cytoscape Graph: Must Initialize on a Visible Container

**Wrong:** Calling `cytoscape({container: el, ...})` when `el` is inside a hidden tab or has `display: none`.
**Right:** Defer initialization until the container is visible. Use `requestAnimationFrame` or listen for the tab activation event.

Cytoscape measures the container dimensions at init time. A hidden container reports 0×0, which produces a broken (zero-size) layout. The established pattern in this codebase is to defer graph init to `rAF` when rendering tabs.

---

## Check WeftUtils Before Writing Inline JavaScript

The project has a shared utility object at `static/js/utils.js` (`WeftUtils`). Before writing custom JavaScript for common UI patterns, check if it's already there:

- `WeftUtils.confirm(msg, callback)` - confirmation modal
- `WeftUtils.showModal(id)` / `WeftUtils.hideModal(id)` - modal open/close
- `WeftUtils.copyToClipboard(text, el)` - clipboard copy with feedback
- `WeftUtils.stickyActionBar(id)` - bulk action bar that sticks to bottom when scrolled out of view
- `WeftUtils.detectTimezone()` / `WeftUtils.detectLocale()` - locale detection
- `WeftUtils.listManager(config)` - list view manager for localStorage persistence, collapsible filter panel, page size selector, and multiselect with sticky action bar. Use this any time a list view needs any combination of these features. See `.claude/references/list-view-patterns.md` for the full config and examples.

Duplicating these inline is also risky because inline event handlers are blocked by CSP.

**Write new JS in ES2020**: use `const`/`let` (no `var`), arrow functions, template literals.
See `.claude/references/js-patterns.md` for the full standard.

**Extract server data from script bodies**: all Jinja2 `{{ }}` expressions must go in a
`<script type="application/json" id="page-data">` block. Inline scripts read from it via
`JSON.parse(document.getElementById('page-data').textContent)`. Never put `{{ var }}` directly
inside a `<script nonce="...">` body.

---

## Cross-Tenant Queries: Use UNSCOPED, Not Raw Pool

**Wrong:** `get_pool()` then `pool.connection()` to bypass RLS for background worker queries
**Right:** `fetchall(UNSCOPED, query)` or `execute(UNSCOPED, query, params)`

The `UNSCOPED` sentinel skips the `SET LOCAL app.tenant_id` call, giving the query cross-tenant visibility. This is cleaner and uses the standard database helpers instead of duplicating connection management. Use it for background worker queries that need to scan across all tenants.

---

## Never Paste Inline SVG Icons

**Wrong:** Copy-pasting `<svg>...<path d="..."/></svg>` directly into a template
**Right:** `{{ icon("chevron-down", class="w-4 h-4") }}`

All icons live as valid SVG files in `app/templates/icons/`. The `icon()` Jinja2 global (from `app/utils/templates.py`) reads the SVG and injects HTML attributes. No import needed. Check the icons directory for available names before creating a new one.

---

## Database Changes Go in Migrations Only

**Wrong:** Adding a new column to `db-init/schema.sql` (the baseline schema)
**Right:** Create a new migration file in `db-init/migrations/` (e.g., `0008_description.sql`)

The `schema.sql` file represents the initial database state before any migrations. It is only applied on a fresh database. All schema changes must go exclusively in migration files. Never modify `schema.sql` for new changes.

---

## Email HTML Must Use Inline Styles

**Wrong:** Using `<style>` blocks with CSS classes in email HTML (e.g., `.button { color: white; }`)
**Right:** All styling via inline `style` attributes on every element

Gmail, Outlook, and other major email clients strip `<style>` blocks entirely. Any styling defined via CSS classes silently disappears. This causes elements like CTA buttons to lose their `color: white`, rendering dark link text on a blue background (illegible).

The shared layout in `app/utils/email.py` uses style constants (`_S_BUTTON`, `_S_INFO_BOX`, etc.) to keep inline styles DRY. New emails must follow this pattern.

---

## Set-Password Links Must Include the Nonce

**Wrong:** Constructing `/set-password?email_id={id}` (no nonce)
**Right:** `/set-password?email_id={id}&nonce={set_password_nonce}`

The `set_password_nonce` column on `user_emails` makes set-password links one-time use,
the same way `verify_nonce` makes email verification links one-time use. Any code that
builds a set-password URL must fetch and include the current `set_password_nonce` value.
On successful password set, call `emails_service.increment_set_password_nonce()` to
invalidate the link.

The "Resend Invitation" flow (future backlog item) must also increment the nonce *before*
building the new link, so old copies of the invitation email become invalid.

---

## Nginx 502 After Docker Container Rebuild

**Wrong:** Assuming `make up` leaves nginx working after rebuilding the app container
**Right:** Restart the reverse proxy after a rebuild: `docker compose restart reverse-proxy`

When `make up` recreates the app container, nginx may lose its upstream connection and return 502 for all requests. The app container itself is healthy (responds to `curl` internally), but nginx's cached DNS/connection to the old container is stale. A quick `docker compose restart reverse-proxy` fixes it. This is a dev-only issue (production uses a separate deploy flow).

---

## Background Jobs Must Use `system_context()` for `log_event()`

**Wrong:** Calling `log_event()` directly in a job handler
**Right:** Wrap the code that calls `log_event()` in `with system_context():`

`log_event()` requires HTTP request metadata (IP, user agent, session hash) from middleware. Background jobs have no HTTP request, so `log_event()` raises `RuntimeError: log_event called without request context`. The `system_context()` context manager signals that this is intentional (automated/background action) and bypasses the requirement.

```python
from utils.request_context import system_context

@register_handler("my_job")
def handle_my_job(task: dict) -> dict:
    with system_context():
        # ... do work ...
        log_event(...)  # Now works without request context
```

---

## Jinja2 Autoescape Mangles JSON in Script Blocks

**Wrong:** Passing `json.dumps(data)` via template context and using `{{ json_string }}` in a `<script type="application/json">` block
**Right:** Pass the dict directly and use `{{ data | tojson }}` in the template

Jinja2 autoescape is enabled globally (`autoescape=True`). Raw strings passed through `{{ }}` get HTML-encoded (`"` becomes `&#34;`), producing invalid JSON that breaks `JSON.parse()`. The `tojson` filter serializes to JSON AND marks the output as Markup-safe, bypassing autoescape.

**Symptoms:** `SyntaxError` on `JSON.parse(document.getElementById('page-data').textContent)` with no visible cause. Inspect the rendered HTML to see `&#34;` in the JSON.

---

## Form() Parameters Need max_length Like Pydantic Fields

**Wrong:** `password: Annotated[str, Form()]` in a route handler
**Right:** `password: Annotated[str, Form(max_length=255)]`

The project rule "all str fields must have max_length" applies to **Form() parameters in route handlers**, not just Pydantic schema fields. Web form endpoints bypass Pydantic validation entirely, so they accept unbounded strings by default. Password fields are especially dangerous: an attacker can submit a multi-megabyte string that gets passed to Argon2, causing CPU exhaustion on a pre-auth endpoint.

Standard limits: passwords 255, emails 320, UUIDs/IDs 50, codes 100, timezone 50, locale 10, names 255, descriptions 2000, URLs 2048, enum-like 50.

The compliance check `form-input-length` catches these automatically.

---

## innerHTML Requires escapeHtml for Dynamic Data

**Wrong:** `` previewEl.innerHTML = `<p>${data.name}</p>` ``
**Right:** `` previewEl.innerHTML = `<p>${escapeHtml(data.name)}</p>` ``

When inserting API response data or any non-literal value into the DOM via `innerHTML`, every interpolated expression must be wrapped in `escapeHtml()`. CSP nonces block inline `<script>` execution but do not prevent HTML injection (phishing overlays, CSS exfiltration, image-tag exfiltration).

The codebase has a correct reference implementation in `users_bulk_primary_emails.html` (lines 108-110). Use that `escapeHtml()` function or add it to `WeftUtils`. For content that is purely hardcoded HTML or server-generated SVG (mandalas), innerHTML without escaping is acceptable.

The compliance check `template-xss` catches these automatically.

---

## Security Tokens Must Be Cryptographically Random

**Wrong:** Sequential integer nonces (`DEFAULT 1`, then increment on use)
**Right:** Random hex tokens via `gen_random_bytes(24)` (DB) or `secrets.token_hex(24)` (Python)

Sequential nonces are trivially guessable if the attacker can observe or predict the sequence. This applies to email verification tokens, password reset nonces, set-password links, and any other one-time-use value. Always use `secrets.token_hex()` or `secrets.token_urlsafe()` in Python, or `encode(gen_random_bytes(24), 'hex')` in PostgreSQL.

---

## Authorization Must Be Enforced in the Service Layer

**Wrong:** Checking a tenant policy (like `allow_users_edit_profile`) only in the router
**Right:** Check in the **service function** so all entry points (web UI, API, future CLI) are covered

If a policy check exists only in the router, the API route to the same service function bypasses it. The service layer is the single enforcement point for authorization. Routers handle HTTP concerns (session, templates, redirects); services enforce business rules.

---

## Redirect Targets From User Input Must Be Validated

**Wrong:** `return RedirectResponse(url=request.query_params.get("next", "/dashboard"))`
**Right:** Validate the target is a safe relative path before redirecting

User-controlled redirect targets (RelayState, `next` params, return URLs) can be crafted to redirect users to external phishing sites. At minimum, validate that the value starts with `/`, does not start with `//`, and does not contain `://`. See `_safe_relay_state()` in `app/routers/saml/authentication.py` for the reference pattern.

---

## Numeric Inputs to Security Logic Need Explicit Bounds

**Wrong:** `grace_period_days: int = Query(default=7)` on a certificate rotation endpoint
**Right:** `grace_period_days: int = Query(default=7, ge=0, le=90)`

Numeric parameters that feed into security calculations (certificate lifetimes, rate limit windows, retry counts, session timeouts) must have explicit `ge`/`le` bounds. Without bounds, an attacker can pass 999999 to extend a certificate's grace period to centuries. Apply bounds at both the API parameter level and in service-layer validation (defense-in-depth).

---

## psycopg Named Params Conflict with PostgreSQL Cast Syntax

**Wrong:** `split_part(:email::text, '@', 2)` in a SQL query with named parameters
**Right:** Extract the value in Python and pass as a separate parameter

psycopg interprets `::text` as a named parameter `:text`, not a PostgreSQL type cast. This causes `ProgrammingError: query parameter missing: text`. Instead, compute the value in Python before passing it to the query:

```python
# Wrong:
fetchone(tenant_id, "INSERT ... split_part(:email::text, '@', 2)", {"email": email})

# Right:
fetchone(tenant_id, "INSERT ... :domain", {"email": email, "domain": email.split("@")[1]})
```
