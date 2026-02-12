# Project Instructions

## What This Project Is

Weft-ID is a multi-tenant identity federation platform that acts as middleware between applications and identity providers (Okta, Entra ID, Google Workspace, SAML/OIDC). Core capabilities:

- SAML 2.0 and OAuth2 identity provider integration
- SAML 2.0 Identity Provider for downstream service providers (SSO assertions, per-SP signing certificates)
- Multi-factor authentication (TOTP-based with backup codes)
- User lifecycle management with inactivation/reactivation workflows
- Comprehensive audit logging and activity tracking
- Tenant-isolated data with Row-Level Security (RLS)

## Before Starting Work

**Read `.claude/THOUGHT_ERRORS.md`** for common mistakes to avoid. Key gotchas:

- **Tests**: Use `poetry run python -m pytest` or `./test` (not `pytest` directly)
- **Linting**: Use `ruff check` (not `mypy` or `pyright`)
- **UUIDs**: Convert to string when comparing across boundaries
- **Background jobs**: Restart worker container, not app container
- **Mocking sessions**: Patch `starlette.requests.Request.session`, not client cookies

## Git Commits

- Keep them short and to the point
- The summary should be short (80 chars or less)
- The description should include a short definition of what problem was addressed
- The description should then explain, tersely, how it was done
- Do NOT include Claude attributions in commit messages

## Architecture Overview

This project follows a layered architecture:

```
Request → Router → Service → Database → PostgreSQL
```

- **Routers** (`app/routers/`): HTTP/template layer only. Never import database modules directly.
- **Services** (`app/services/`): Business logic and authorization. Receives `RequestingUser`, returns Pydantic schemas, raises `ServiceError` subclasses.
- **Database** (`app/database/`): SQL execution with tenant scoping. Returns dicts.

### Authentication vs Authorization

- **Authentication** (router layer): FastAPI dependencies in `app/dependencies.py` and `app/api_dependencies.py` identify the caller and return a user dict. They redirect unauthenticated users.
- **Authorization** (service layer): Functions in `app/services/auth.py` check role-based access. They receive a `RequestingUser` and raise `ForbiddenError` if the role is insufficient.

## Key Files

| File | Purpose |
|------|---------|
| `app/pages.py` | Authorization registry. All routes must be registered here |
| `app/constants/event_types.py` | Event type registry for audit logging |
| `app/schemas/common.py` | `RequestingUser` TypedDict and common schemas |
| `app/services/exceptions.py` | ServiceError subclasses (ForbiddenError, NotFoundError, ValidationError) |
| `app/services/event_log.py` | `log_event()` function for audit logging |
| `app/services/activity.py` | `track_activity()` for read operation tracking |
| `BACKLOG.md` | Product backlog (pending items) |
| `BACKLOG_ARCHIVE.md` | Completed backlog items with acceptance criteria |
| `ISSUES.md` | Active quality/security issues (goal: keep empty) |
| `ISSUES_ARCHIVE.md` | Resolved issues with fix details |
| `app/services/service_providers.py` | SP registration, SSO response building |
| `app/routers/saml_idp/` | SAML IdP admin, SSO, metadata (package) |
| `app/database/service_providers.py` | SP database queries |
| `app/database/sp_signing_certificates.py` | Per-SP signing certificate queries |
| `.claude/THOUGHT_ERRORS.md` | Common mistakes to avoid |

## Directory Structure

```
app/
├── routers/          # HTTP layer (imports services only)
│   ├── api/v1/       # RESTful API endpoints
│   ├── auth/         # Login, logout, onboarding (package)
│   ├── saml/         # SAML SP authentication (package)
│   ├── saml_idp/     # SAML IdP admin, SSO, metadata (package)
│   └── users/        # User management (package)
├── services/         # Business logic (imports database)
│   ├── users/        # User CRUD, profile, lifecycle (package)
│   ├── groups/       # Group CRUD, hierarchy, membership (package)
│   └── saml/         # SAML providers, certificates (package)
├── database/         # SQL execution (returns dicts)
│   ├── groups/       # Group queries (package)
│   ├── oauth2/       # OAuth2 queries (package)
│   ├── saml/         # SAML queries (package)
│   └── users/        # User queries (package)
├── schemas/          # Pydantic models
├── templates/        # Jinja2 templates
├── middleware/       # Request processing
├── jobs/             # Background task handlers
└── constants/        # Enums and constants
tests/                # Mirrors app/ structure
db-init/              # SQL migrations (sequential numbering)
scripts/              # Compliance and dependency checks
.claude/skills/       # Skill definitions (/pm, /dev, /test, etc.)
.claude/references/   # Detailed patterns and checklists for agents
```

### Package-Split Pattern

When a module grows large, it is split into a package directory with focused submodules:

- Public submodules are named by concern (e.g., `crud.py`, `hierarchy.py`, `membership.py`)
- Private helpers use an underscore prefix (e.g., `_converters.py`, `_validation.py`)
- `__init__.py` re-exports public functions for backwards compatibility
- When splitting a module into a package, mock targets in tests must be updated to reference the submodule (e.g., `routers.users.crud.some_func` instead of `routers.users.some_func`)

## Core Types

**RequestingUser** (TypedDict in `app/schemas/common.py`):
```python
{
    "id": str,           # User ID
    "tenant_id": str,    # Tenant ID for scoping
    "role": str,         # "super_admin" | "admin" | "user"
    "email": str,
    # ... additional fields
}
```

**ServiceError Subclasses** (in `app/services/exceptions.py`):
- `ForbiddenError` - Authorization failures (403)
- `NotFoundError` - Resource not found (404)
- `ValidationError` - Input validation failures (400)

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

## Event Logging Pattern

**Writes must log events** (after successful mutation):
```python
from app.services.event_log import log_event

log_event(
    tenant_id=requesting_user["tenant_id"],
    actor_user_id=requesting_user["id"],
    event_type="user_created",  # Past tense, from event_types.py
    artifact_type="user",
    artifact_id=user_id,
    metadata={"role": user_data.role}  # Context for audit trail
)
```

**Reads must track activity** (at function start):
```python
from app.services.activity import track_activity

def get_users(requesting_user: RequestingUser) -> list[UserResponse]:
    track_activity(requesting_user["tenant_id"], requesting_user["id"])
    # ... rest of function
```

## Tenant Isolation

Database functions use Row-Level Security (RLS):
- All queries are scoped via `tenant_id` parameter
- Use `UNSCOPED` constant for intentional cross-tenant operations (system tasks only)
- Database layer functions: `fetchall(tenant_id, ...)`, `fetchone(tenant_id, ...)`, `execute(tenant_id, ...)`

## Group System Architecture

Groups organize users and support hierarchical relationships via a DAG (Directed Acyclic Graph) model.

### Data Model

| Table | Purpose |
|-------|---------|
| `groups` | Group definitions (name, description, type) |
| `group_memberships` | User-to-group membership |
| `group_relationships` | Direct parent-child edges |
| `group_lineage` | Closure table for all ancestor-descendant pairs |

### DAG Model

- Groups can have **multiple parents** (unlike a tree)
- Only true cycles are prevented (A cannot be both ancestor AND descendant of B)
- Example: Groups A and B can both be children of C, and A can become a child of B

### Closure Table Pattern

The `group_lineage` table pre-computes all ancestor-descendant relationships:

```
ancestor_id | descendant_id | depth
------------+---------------+------
group_a     | group_a       | 0      -- self-reference (every group has this)
group_a     | group_b       | 1      -- direct child
group_a     | group_c       | 2      -- grandchild (transitive)
```

**Benefits:**
- O(1) cycle detection: `SELECT 1 FROM group_lineage WHERE ancestor_id = child AND descendant_id = parent`
- O(1) ancestry queries: find all ancestors or descendants with a single query
- Depth tracking enables hierarchy visualization

**Maintenance:**
- On group creation: insert self-reference row `(group_id, group_id, 0)`
- On relationship creation: insert transitive paths atomically (all ancestors of parent become ancestors of all descendants of child)
- On relationship deletion: rebuild lineage for affected subtree

### Transactional Consistency

Relationship changes must update both `group_relationships` AND `group_lineage` atomically. Use the database `session()` context manager for transactions:

```python
with session(tenant_id=tenant_id) as cur:
    # 1. Insert/delete the direct relationship
    cur.execute(...)
    # 2. Update the lineage table
    cur.execute(...)
    # Transaction commits when context exits
```

### Group Types

- `weftid`: Manually managed groups (admin can add/remove members)
- `idp`: Identity Provider groups (synced from external IdP, read-only in WeftId)

## Background Jobs

Background jobs run in a separate worker container.
- Code location: `app/jobs/`
- Job registry: `app/jobs/registry.py`
- **Changes require worker restart**: `docker compose restart worker`

## Development Commands

### Python Development Tasks (Use Poetry)

**Run tests:**
```bash
./test                                                         # Run all tests (parallelized by default)
poetry run python -m pytest                                    # Full command
poetry run python -m pytest --cov=app --cov-report=term-missing  # With coverage report
```

Note: Tests run in parallel by default (`-n auto` configured in `pytest.ini`).

**Linting:**
```bash
poetry run ruff check app/ tests/           # Check for issues
poetry run ruff check --fix app/ tests/     # Auto-fix issues
```

**Formatting:**
```bash
poetry run ruff format app/ tests/          # Format code
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

**Frontend/CSS build:**
```bash
make build-css   # Build Tailwind CSS (run after modifying templates)
make watch-css   # Watch templates and auto-rebuild CSS (recommended for active development)
```

**Quick reference:**
```bash
make help        # Show all available targets
```

**Running a migration on demand:**

Migrations in `db-init/` run automatically on first DB init. To run a new migration against a running dev database:
```bash
docker compose exec -T db psql -U postgres -d appdb < db-init/00031_example.sql
```
Replace the filename with the migration to run. The `-T` flag disables TTY allocation so the file pipes correctly.

### Frontend Development Workflow

**Tailwind CSS is built locally** from `static/css/input.css` → `static/css/output.css`

The build process scans all templates (`app/templates/**/*.html`) and generates CSS containing only the Tailwind utility classes actually used in your templates.

**When adding new Tailwind classes to templates:**

**Option 1: Manual rebuild** (when needed)
```bash
make build-css
```
Run this after you've added new Tailwind classes to any template file. The generated CSS will be updated with the new classes.

**Option 2: Watch mode** (recommended for active development)
```bash
make watch-css
```
Leave this running in a separate terminal while working on templates. It automatically detects changes to HTML files and rebuilds the CSS. Press Ctrl+C to stop watching.

**In Docker:**
The CSS is built during the Docker image build process, so running `make up` will always rebuild the CSS from scratch.

### Development Workflow

**Starting a development session:**
1. Start Docker services: `make up`
2. (Optional) Start CSS watch mode: `make watch-css` (in separate terminal)
3. Work on code/templates normally
4. CSS rebuilds automatically if watch mode is running

**Before committing code:**
1. Run formatting: `poetry run ruff format app/ tests/`
2. Run linting: `poetry run ruff check --fix app/ tests/`
3. Run tests: `./test` (or `poetry run python -m pytest`)
4. If you modified templates and didn't use watch mode: `make build-css`

All checks must pass before committing.

## Best Practices

1. **All writes go through the service layer** - routers never call database modules directly
2. **Every service write must emit an event log** - "if there is a write, there is a log"
3. **Read service functions must track activity** - call `track_activity(tenant_id, user_id)` at the start of read-only service functions
4. **Authorization via `app/pages.py`** - single source of truth for page access and navigation
5. **New pages must be registered in `app/pages.py`** - each route checks access via this file
6. **Migrations** go in `db-init/` with sequential numbering (check existing files for next number)
7. **Run formatting and linting** before committing code
8. **API-first methodology** - any functionality available in the web client must also be exposed via API endpoints under `/api/v1/`
9. **Backlog management** - after completing a BACKLOG.md item, move it to BACKLOG_ARCHIVE.md with status marked as Complete

## Testing Requirements

- **New code must have comprehensive test coverage** - aim for ~100% on new code
- **Test both layers**: unit tests for service functions, integration tests for routes/API endpoints
- **Cover happy paths and key edge cases** - don't just test the golden path
- **All existing tests must pass** - never break existing functionality
- Tests live in `tests/` mirroring the app structure
- **Test environment**: Tests set `IS_DEV=true` (in `tests/conftest.py`) to bypass production validation

## Agent Workflow

- Use `/pm` to add items to the product backlog
- Use `/dev` to implement items from the backlog (checks ISSUES.md first)
- Use `/test` to review quality and push coverage intelligently
- Use `/compliance` to verify architectural principles are followed
- Use `/security` to scan for OWASP Top 10 and other security vulnerabilities
- Use `/deps` to audit third-party dependencies for known CVEs and vulnerabilities
- Use `/refactor` to analyze codebase for refactoring opportunities and technical debt

## Issue Tracking

- Quality issues found by `/test` are logged in `ISSUES.md`
- Architectural violations found by `/compliance` are logged in `ISSUES.md`
- Security vulnerabilities found by `/security` are logged in `ISSUES.md`
- Dependency vulnerabilities found by `/deps` are logged in `ISSUES.md`
- Refactoring opportunities found by `/refactor` are logged in `ISSUES.md`
- `/dev` checks ISSUES.md first before BACKLOG.md (bugs before features)
- **When resolved:** Move issues from `ISSUES.md` to `ISSUES_ARCHIVE.md` (don't keep resolved items in ISSUES.md)
- Goal: keep `ISSUES.md` empty
