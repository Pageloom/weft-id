# Project Instructions

## Git commits
- Keep them short and to the point
- The summary should be short
- The description should include a short definition of what problem
  was addressed
- The description should thenafter explain, tersely, how it was done
- Do NOT include claude attributions in commit messages

## Architecture Overview

This project follows a layered architecture:

```
Request → Router → Service → Database → PostgreSQL
```

- **Routers** (`app/routers/`): HTTP/template layer only. Never import database modules directly.
- **Services** (`app/services/`): Business logic and authorization. Receives `RequestingUser`, returns Pydantic schemas, raises `ServiceError` subclasses.
- **Database** (`app/database/`): SQL execution with tenant scoping. Returns dicts.

## Development Commands

### Python Development Tasks (Use Poetry)

**Run tests:**
```bash
poetry run pytest                                    # Run all tests
poetry run pytest --cov=app --cov-report=term-missing  # With coverage
poetry run pytest -n auto                             # Parallel execution
```

**Linting:**
```bash
poetry run ruff check app/ tests/           # Check for issues
poetry run ruff check --fix app/ tests/     # Auto-fix issues
```

**Formatting:**
```bash
poetry run black app/ tests/                # Format code
poetry run ruff check --fix app/ tests/     # Fix style issues
```

**Type checking:**
```bash
poetry run mypy app/                        # Check types
```

**Dependency security scanning:**
```bash
python scripts/deps_check.py                # Scan dependencies
python scripts/deps_check.py --include-dev  # Include dev deps
```

**Architectural compliance:**
```bash
python scripts/compliance_check.py          # Check all principles
python scripts/compliance_check.py --check activity  # Specific check
```

### Docker Infrastructure (Use Make)

**Service management:**
```bash
make up          # Build and start all services
make down        # Stop and remove containers
make status      # Show service status
make db-reset    # Wipe DB volume
make restart-app # Restart specific service
```

**Logs and debugging:**
```bash
make logs        # Tail all logs
make logs-app    # Tail specific service logs
make sh-app      # Open shell in service container
```

**Quick reference:**
```bash
make help        # Show all available targets
```

### Development Workflow

Before committing code:
1. Run formatting: `poetry run black app/ tests/`
2. Run linting: `poetry run ruff check --fix app/ tests/`
3. Run type checking: `poetry run mypy app/`
4. Run tests: `poetry run pytest`

All four must pass before committing.

## Best Practices

1. **All writes go through the service layer** - routers never call database modules directly
2. **Every service write must emit an event log** - "if there is a write, there is a log"
3. **Read service functions must track activity** - call `track_activity(tenant_id, user_id)` at the start of read-only service functions
4. **Authorization via `app/pages.py`** - single source of truth for page access and navigation
5. **New pages must be registered in `app/pages.py`** - each route checks access via this file
6. **Migrations** go in `db-init/` with sequential numbering (next: `00020_*.sql`)
7. **Run formatting, linting, and typechecking** before committing code
8. **API-first methodology** - any functionality available in the web client must also be exposed via API endpoints under `/api/v1/`
9. **Backlog management** - after completing a BACKLOG.md item, move it to BACKLOG_ARCHIVE.md with status marked as Complete

## Testing Requirements

- **New code must have comprehensive test coverage** - aim for ~100% on new code
- **Test both layers**: unit tests for service functions, integration tests for routes/API endpoints
- **Cover happy paths and key edge cases** - don't just test the golden path
- **All existing tests must pass** - never break existing functionality
- Tests live in `tests/` mirroring the app structure

## Service Function Pattern

```python
def do_something(
    requesting_user: RequestingUser,
    data: SomeSchema,
) -> ResultSchema:
    """Authorization: Requires admin role."""
    _require_admin(requesting_user)
    # ... business logic ...
    # ... database calls ...
    # ... event log ...
    return ResultSchema(...)
```

## Development Workflow

- Use `/pm` to add items to the product backlog
- Use `/dev` to implement items from the backlog
- Use `/test` to review quality and push coverage intelligently
- Use `/compliance` to verify architectural principles are followed
- Use `/security` to scan for OWASP Top 10 and other security vulnerabilities
- Use `/deps` to audit third-party dependencies for known CVEs and vulnerabilities

## Issue Tracking

- Quality issues found by `/test` are logged in `ISSUES.md`
- Architectural violations found by `/compliance` are logged in `ISSUES.md`
- Security vulnerabilities found by `/security` are logged in `ISSUES.md`
- Dependency vulnerabilities found by `/deps` are logged in `ISSUES.md`
- Goal: keep `ISSUES.md` empty
