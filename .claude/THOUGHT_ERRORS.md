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

## Running Linting

**Wrong:** `ruff check` or assuming pyright is available
**Right:** `poetry run ruff check`

Linting must be run via poetry.

## Test Environment

The test environment sets `IS_DEV=true` in `tests/conftest.py`. This is required because production validation would otherwise fail with default secret values.

---

## Type Checking

**Wrong:** `poetry run pyright` or `poetry run mypy` (neither is installed)
**Right:** `poetry run ruff check app/`

This project uses ruff for linting and type-related checks. Neither mypy nor pyright is available in the virtualenv.

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

## Dependency Security Scanning Limitations

**Issue:** `scripts/deps_check.py` may miss vulnerabilities that `pip-audit` catches directly.

**Why:** The script only scans direct dependencies from pyproject.toml, not transitive dependencies. Vulnerabilities in transitive deps (like ecdsa via sendgrid) are missed.

**Workaround:** Run `poetry run python -m pip_audit --progress-spinner off` directly to catch all vulnerabilities including transitive dependencies.

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

## Running Database Migrations Without Full Reset

**Wrong:** `make db-reset` (destroys all data)
**Right:** Run migration as postgres superuser: `docker compose exec -T db psql -U postgres -d appdb -f /docker-entrypoint-initdb.d/00027_groups.sql`

Migrations use `SET ROLE appowner` which requires superuser privileges. The `appuser` role cannot execute this. When you need to apply a new migration without losing data, run it as the `postgres` user instead of `appuser`.
