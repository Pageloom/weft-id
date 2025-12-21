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

## Best Practices

1. **All writes go through the service layer** - routers never call database modules directly
2. **Every service write must emit an event log** - "if there is a write, there is a log"
3. **Authorization via `app/pages.py`** - single source of truth for page access and navigation
4. **New pages must be registered in `app/pages.py`** - each route checks access via this file
5. **Migrations** go in `db-init/` with sequential numbering (next: `00010_*.sql`)
6. **Run formatting, linting, and typechecking** before committing code

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

## Issue Tracking

- Quality issues found by `/test` are logged in `ISSUES.md`
- Goal: keep `ISSUES.md` empty
