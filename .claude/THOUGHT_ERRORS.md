# Thought Errors

This file documents common mistakes Claude makes in this project. Review this before starting work to avoid repeating them.

## Running Tests

**Wrong:** `python -m pytest` or `docker compose exec web pytest`
**Right:** `poetry run pytest`

Tests must be run via poetry to use the correct virtual environment.

## Running Linting

**Wrong:** `ruff check` or assuming pyright is available
**Right:** `poetry run ruff check`

Linting must be run via poetry.

## Test Environment

The test environment sets `IS_DEV=true` in `tests/conftest.py`. This is required because production validation would otherwise fail with default secret values.

---

## Adding New Thought Errors

When you make a mistake that causes wasted effort or confusion, add it here:

1. Describe what you did wrong
2. Describe what you should have done
3. Add any relevant context

This helps prevent the same mistakes in future sessions.
