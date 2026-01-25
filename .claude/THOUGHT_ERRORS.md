# Thought Errors

This file documents common mistakes Claude makes in this project. Review this before starting work to avoid repeating them.

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

**Wrong:** `poetry run pyright`
**Right:** `poetry run mypy`

This project uses mypy, not pyright. Check before assuming.

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

## Adding New Thought Errors

When you make a mistake that causes wasted effort or confusion, add it here:

1. Describe what you did wrong
2. Describe what you should have done
3. Add any relevant context

This helps prevent the same mistakes in future sessions.
